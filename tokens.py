"""Instagram User Access Token: конверт, первичная загрузка из окружения, продление.

Токен живёт 60 суток и, если его не продлить, умирает НАВСЕГДА — восстанавливается только
ручным re-auth владельца. Поэтому продление идёт заранее, за REFRESH_BEFORE_DAYS до конца,
а не в день X, и провал продления — это алерт, а не строка в логе.

ИСТОЧНИК ПРАВДЫ — ТАБЛИЦА, а не окружение. Переменная засевает токен ровно один раз, когда
строки ещё нет, и больше не участвует ни в чём: сервис ротирует токен сам, значение в окружении
с первого дня остаётся старым, и рутинный рестарт (деплой, OOM, перезагрузка хоста) затирал бы
свежий токен мёртвым. Автопродление, отменяющее себя на деплое, хуже отсутствия автопродления.

Восстановление после протухания (владелец установки прошёл Instagram Business Login
заново) идёт через панель, функция store() ниже: запись снимает invalid_at, и диспетчер
сам разбирает накопившуюся очередь. Ни правки файлов, ни рестарта контейнера — то есть
авария не стоит приёма вебхуков.
Запасной путь, если панель недоступна или сменился IG_TOKEN_KEY (тогда строка перестаёт
расшифровываться): в базе установки `delete from instagram.ig_token`, свежий токен в
переменную IG_ACCESS_TOKEN, затем поднять сервис заново. Порядок именно такой: пока
строка в таблице цела, окружение её не перезаписывает.

Хранится зашифрованным: enc:<iv_b64>:<tag_b64>:<ct_b64>, AES-256-GCM, ключ —
sha256(IG_TOKEN_KEY). Ключ отдельный от всех прочих секретов установки намеренно: этот
контейнер единственный, до которого достаёт интернет, и общий ключ здесь означал бы, что
утечка отсюда стоит дороже, чем стоит сама утечка отсюда.
"""

import base64
import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import db
import meta
from config import IG_ACCESS_TOKEN, IG_TOKEN_KEY, IG_USER_ID, PANEL_URL

log = logging.getLogger("tokens")

PREFIX = "enc:"
TAG_LEN = 16
# Продлевать заранее: платформа не даёт продлить токен моложе суток и не воскрешает мёртвый.
REFRESH_BEFORE_DAYS = 10
# Горизонт для токена с НЕИЗВЕСТНЫМ сроком жизни: ровно порог продления, чтобы ближайший
# круг честно спросил Meta, а не отсекал сам себя выдуманными шестьюдесятью сутками.
# Ни одно число про срок жизни токена в коде не выдумывается — только expires_in из ответа.
PROBE_HORIZON = timedelta(days=REFRESH_BEFORE_DAYS)
CACHE_TTL_SEC = 30
# Сколько Meta может молчать о сроке, прежде чем это станет сигналом. Считаем по СОСТОЯНИЮ
# (refreshed_at в таблице), а не по кругам подряд в памяти: счётчик в памяти обнуляется
# рестартом, и при регулярных деплоях алерт не пришёл бы ни разу. Круг идёт раз в 6 часов,
# так что сигнал повторяется, пока состояние держится, — одноразовый алерт теряется, если
# именно он не доставился.
REFRESH_SILENCE_LIMIT = timedelta(hours=24)
# Платформа не продлевает токен моложе суток — отказ в этом окне штатный, не авария.
TOKEN_MIN_AGE = timedelta(hours=26)


@dataclass(frozen=True)
class TokenState:
    value: str | None
    expires_at: datetime | None
    invalid_at: datetime | None
    # Когда Meta в последний раз ПОДТВЕРДИЛА срок жизни продлением. None означает, что
    # в expires_at стоит горизонт зонда (PROBE_HORIZON), а не настоящий срок: обратный
    # отсчёт «истекает через N суток» по такому значению — враньё человеку, поэтому
    # панель показывает его только при непустом refreshed_at.
    refreshed_at: datetime | None = None

    @property
    def usable(self) -> bool:
        return bool(self.value) and self.invalid_at is None


_cache: tuple[float, TokenState] | None = None


def _key() -> bytes:
    # Без фолбэка: пустой ключ шифровал бы токен публично известным нулём.
    if not IG_TOKEN_KEY:
        raise RuntimeError("IG_TOKEN_KEY не задан — токен нельзя ни зашифровать, ни прочитать")
    return hashlib.sha256(IG_TOKEN_KEY.encode()).digest()


def encrypt(plain: str) -> str:
    iv = os.urandom(12)
    sealed = AESGCM(_key()).encrypt(iv, plain.encode(), None)
    # cryptography клеит тег в хвост шифротекста, node отдаёт его отдельным полем —
    # режем, чтобы строка читалась тем же разбором, что в settings.ts.
    ct, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    return PREFIX + ":".join(base64.b64encode(part).decode() for part in (iv, tag, ct))


def decrypt(stored: str) -> str:
    """Открытый текст в колонке token_enc — это дефект, а не совместимость: падаем."""
    if not stored.startswith(PREFIX):
        raise ValueError("token_enc не в формате конверта")
    parts = stored.split(":")
    if len(parts) != 4:
        raise ValueError("token_enc повреждён")
    iv, tag, ct = (base64.b64decode(p) for p in parts[1:])
    return AESGCM(_key()).decrypt(iv, ct + tag, None).decode()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def state(force: bool = False) -> TokenState:
    """Текущий токен. Кэш на CACHE_TTL_SEC — диспетчер спрашивает на каждом круге."""
    global _cache
    if not force and _cache and (_now().timestamp() - _cache[0]) < CACHE_TTL_SEC:
        return _cache[1]
    row = await db.load_token()
    if row is None:
        current = TokenState(None, None, None)
    else:
        try:
            value = decrypt(row["token_enc"])
        except Exception:
            # Ключ сменили или строка побита — вести себя как «токена нет» честнее,
            # чем сыпать исключением на каждой отправке.
            log.exception("токен не расшифровывается")
            value = None
        current = TokenState(value, row["expires_at"], row["invalid_at"], row["refreshed_at"])
    _cache = (_now().timestamp(), current)
    return current


def forget() -> None:
    global _cache
    _cache = None


async def ensure_from_env() -> None:
    """Засеивает токен из окружения, ТОЛЬКО когда своего в таблице нет.

    Живой токен не переписывается никогда — почему именно так, см. шапку модуля.
    """
    row = await db.load_token()
    if row is not None:
        if row["invalid_at"] is not None:
            # Момент, когда владелец УВЕРЕН, что уже починил: положил новый токен и
            # перезапустил. Единственный признак обратного — строка в docker logs, а туда
            # он не смотрит. Поэтому здесь алерт, а не только лог.
            log.error("токен в БД помечен мёртвым, засев из окружения запрещён")
            await meta.alert_owner(
                "Instagram: автоответы по-прежнему стоят — перезапуск токен не починил.\n"
                "Сохранённый токен помечен мёртвым, и переменной окружения он НЕ "
                "перезаписывается: иначе каждый рестарт затирал бы свежий токен старым.\n"
                f"Вставьте новый токен здесь: {PANEL_URL}, раздел «Токен» — поверх мёртвого "
                "значения запись разрешена, рестарт после неё не нужен."
            )
        return
    if not IG_ACCESS_TOKEN:
        log.warning("токена нет ни в БД, ни в окружении — отправлять нечем, диспетчер на паузе")
        return
    await db.save_token(
        ig_user_id=IG_USER_ID,
        token_enc=encrypt(IG_ACCESS_TOKEN),
        expires_at=_now() + PROBE_HORIZON,
        refreshed_at=None,
    )
    forget()
    log.info("токен засеян из окружения; настоящий срок жизни узнаем первым продлением")


async def store(value: str) -> datetime:
    """Кладёт токен, принесённый владельцем из Instagram Business Login. Возвращает срок.

    Перезаписывает и живой токен, и помеченный мёртвым: в отличие от ensure_from_env,
    здесь не рутинный рестарт, а осознанное действие человека — ровно тот случай, ради
    которого запрет на затирание и делался с оговоркой. save_token снимает invalid_at,
    поэтому диспетчер снимается с паузы сам, без рестарта контейнера.

    Срок жизни НЕ выдумываем: Meta называет его только в ответе на продление, а продлить
    токен моложе суток платформа не даёт. Ставим горизонт зонда — ближайший круг
    token_loop честно сходит в Meta и запишет настоящий expires_at.
    """
    expires_at = _now() + PROBE_HORIZON
    await db.save_token(
        ig_user_id=IG_USER_ID,
        token_enc=encrypt(value),
        expires_at=expires_at,
        refreshed_at=None,
    )
    forget()
    # Ни самого токена, ни его длины: длина — это подсказка тому, кто читает логи.
    log.info("токен заменён через админку; настоящий срок жизни узнаем первым продлением")
    return expires_at


async def probe(value: str) -> None:
    """Фоновая проверка только что сохранённого токена. Ответ владельцу её НЕ ждёт.

    Синхронно в Meta не ходим намеренно: починка аварии не должна зависеть от доступности
    той самой платформы, ради обхода которой админка и делалась. Но и молча принять
    мёртвый токен нельзя — строка в ig_token одна (CHECK id = 1), истории нет, и неверная
    вставка мгновенно становится рабочим состоянием.

    Разбор исхода:
      code=190          — токен не принят: пауза диспетчера и алерт владельцу;
      сеть / 5xx / таймаут — молчим, это и есть «Meta лежит», ради чего всё затевалось;
      прочий 4xx        — наша ошибка запроса, а не токена: только строка в лог;
      чужой аккаунт     — алерт, но НЕ пауза: токен рабочий, просто не от того аккаунта.
    """
    try:
        me = await meta.fetch_me(value)
    except Exception as exc:
        verdict = meta.classify(exc)
        if verdict == meta.TOKEN_INVALID:
            await mark_invalid(f"новый токен не принят Meta: {exc}")
            return
        if verdict == meta.RETRY:
            log.info("зонд нового токена не состоялся (Meta недоступна), это не отказ: %s", exc)
            return
        log.warning("зонд нового токена вернул неожиданный отказ, токен не трогаю: %s", exc)
        return
    if not IG_USER_ID:
        return
    # Совпадение по ЛЮБОМУ из полей: см. meta.fetch_me — какое из них отдаст Graph,
    # источником с датой не подтверждено, а ложный алерт хуже отсутствующего.
    ids = {str(me.get(field)) for field in ("id", "user_id") if me.get(field)}
    if ids and IG_USER_ID not in ids:
        await meta.alert_owner(
            "Instagram: сохранённый токен принадлежит ДРУГОМУ аккаунту — ответы уйдут "
            "не от того имени, под которым люди оставляли комментарии.\n"
            f"Пройдите Instagram Business Login под нужным аккаунтом и вставьте токен "
            f"заново: {PANEL_URL}, раздел «Токен».\n"
            f"Технические подробности: ожидали {IG_USER_ID}, у токена "
            f"{', '.join(sorted(ids))}."
        )
        return
    log.info("зонд нового токена: Meta приняла его, аккаунт тот же")


async def refresh_if_needed() -> bool:
    """Продление за REFRESH_BEFORE_DAYS до истечения. Зовётся раз в шесть часов из main."""
    current = await state(force=True)
    if not current.usable:
        return False
    row = await db.load_token()
    if row is None:
        return False
    if current.expires_at is not None:
        if current.expires_at - _now() > timedelta(days=REFRESH_BEFORE_DAYS):
            return False
    try:
        value, expires_in = await meta.refresh_token(current.value)
    except Exception as exc:
        if meta.classify(exc) == meta.TOKEN_INVALID:
            await mark_invalid(f"продление отклонено: {exc}")
            return False
        await note_refresh_failure(row, exc)
        return False
    if not value:
        log.warning("продление вернуло пустой токен — оставляю прежний")
        return False
    # Срок берём из ответа Meta. Не назвала — оставляем горизонт проверки, следующий круг
    # спросит снова; выдуманные 60 суток отсекли бы продление на всю их длину.
    lifetime = timedelta(seconds=expires_in) if expires_in else PROBE_HORIZON
    await db.save_token(
        ig_user_id=IG_USER_ID,
        token_enc=encrypt(value),
        expires_at=_now() + lifetime,
        refreshed_at=_now(),
    )
    forget()
    log.info(
        "токен продлён, срок от Meta: %s",
        f"{lifetime.days} суток" if expires_in else "не назван, спрошу снова",
    )
    return True


async def note_refresh_failure(row: dict, exc: Exception) -> None:
    """Продление не удалось по причине, не связанной с мёртвым токеном.

    Молчать до самой смерти токена нельзя: запас в 10 суток существует ровно ради этого
    окна. Но и кричать «нужен ручной re-auth» на исправном токене первых суток нельзя —
    это тот самый алерт, который приучает себя не читать, а следующий будет настоящим.
    """
    seeded_at = row["updated_at"]
    confirmed_at = row["refreshed_at"] or seeded_at
    if row["refreshed_at"] is None and _now() - seeded_at < TOKEN_MIN_AGE:
        log.info("срок токена ещё не подтверждён Meta: платформа не продлевает токен моложе суток")
        return
    silence = _now() - confirmed_at
    if silence < REFRESH_SILENCE_LIMIT:
        log.warning("продление не удалось, повторю через шесть часов: %s", exc)
        return
    log.error("Meta не подтверждает срок токена %s ч", int(silence.total_seconds() // 3600))
    await meta.alert_owner(
        "Instagram: автоответы пока работают, но доступ к аккаунту скоро кончится — "
        f"продлить его не удаётся уже {int(silence.total_seconds() // 3600)} ч.\n"
        "Доступ живёт 60 суток и после смерти НЕ восстанавливается: если продление так и "
        "не пройдёт, вернуть автоответы можно будет только новым входом вручную.\n"
        f"Не дожидаясь: пройдите Instagram Business Login и вставьте свежий токен — "
        f"{PANEL_URL}, раздел «Токен».\n"
        f"Технические подробности: {str(exc)[:300]}"
    )


async def mark_invalid(reason: str) -> None:
    """Токен мёртв: диспетчер на паузу, владельцу — алерт.

    Пауза, а не отказ доставок: строки ig_delivery переживут её и уйдут, когда владелец
    подставит новый токен, — если, конечно, к тому моменту не закроется окно платформы.
    """
    already = (await state()).invalid_at is not None
    await db.mark_token_invalid(reason[:500])
    forget()
    if already:
        return  # алерт на каждый круг — это шум, а не сигнал
    await meta.alert_owner(
        "Instagram отключил доступ: автоответы стоят и будут копиться, пока доступ не "
        "вернут.\n"
        f"Пройдите Instagram Business Login и вставьте свежий токен: {PANEL_URL}, раздел "
        "«Токен». Рестарт не нужен — очередь разберётся сама.\n"
        f"Технические подробности: {reason[:300]}"
    )
