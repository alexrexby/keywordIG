"""Instagram User Access Token: конверт, первичная загрузка из окружения, продление.

Токен живёт 60 суток и, если его не продлить, умирает НАВСЕГДА — восстанавливается только
ручным re-auth владельца. Поэтому продление идёт заранее, за REFRESH_BEFORE_DAYS до конца,
а не в день X, и провал продления — это алерт, а не строка в логе.

ИСТОЧНИК ПРАВДЫ — ТАБЛИЦА, а не окружение. Переменная засевает токен ровно один раз, когда
строки ещё нет, и больше не участвует ни в чём: сервис ротирует токен сам, значение в окружении
с первого дня остаётся старым, и рутинный рестарт (деплой, OOM, перезагрузка хоста) затирал бы
свежий токен мёртвым. Автопродление, отменяющее себя на деплое, хуже отсутствия автопродления.

Восстановление после протухания (владелец прошёл Instagram Business Login заново):
    docker compose -f docker-compose.prod.yml exec -T postgres \
      psql -U ig -d ig -c "delete from instagram.ig_token"
затем положить новый токен в переменную IG_ACCESS_TOKEN и перезапустить instagram-service.

Хранится зашифрованным: формат строки тот же, что у секретов настроек в
CRM — enc:<iv_b64>:<tag_b64>:<ct_b64>, AES-256-GCM, ключ sha256(...).
Второго формата секретов в проекте не заводим.

РАСХОЖДЕНИЕ С ПЛАНОМ, осознанное: ключ конверта — sha256(IG_TOKEN_KEY), а не sha256(AUTH_SECRET),
как написано в разделе «Безопасность». Причина: AUTH_SECRET подписывает сессии Auth.js всей
платформы, а этот контейнер — единственный, до которого достаёт интернет; ревью этапа 1 убрало
отсюда общий набор секретов ровно поэтому, и вернуть сюда AUTH_SECRET значит отменить тот фикс.
Общий ключ ничего не даёт: CRM схему instagram не читает и расшифровывать этот токен
некому. Совместимость ФОРМАТА, ради которой план и просил тот же конверт, сохранена.
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
from config import IG_ACCESS_TOKEN, IG_TOKEN_KEY, IG_USER_ID

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
        current = TokenState(value, row["expires_at"], row["invalid_at"])
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
                "Instagram: перезапуск не починил токен — в таблице по-прежнему мёртвое "
                "значение, и оно НЕ перезаписывается из окружения (иначе рестарт затирал бы "
                "продлённый токен).\nСнимите строку и поднимите сервис заново:\n"
                "docker compose -f docker-compose.prod.yml exec -T postgres "
                'psql -U ig -d ig -c "delete from instagram.ig_token"'
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
        f"Instagram: продлить токен не удаётся уже {int(silence.total_seconds() // 3600)} ч.\n"
        f"Причина: {str(exc)[:300]}\n"
        "Токен живёт 60 суток и после смерти не восстанавливается — нужен ручной re-auth "
        "до истечения срока. Сообщение повторится на следующем круге, пока не продлится."
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
        "Instagram: токен доступа не принят Meta, автоответы на паузе.\n"
        f"Причина: {reason[:300]}\n"
        "Нужен ручной re-auth: пройти Instagram Business Login, снять строку "
        "instagram.ig_token, положить новый токен в переменную IG_ACCESS_TOKEN "
        "и перезапустить instagram-service."
    )
