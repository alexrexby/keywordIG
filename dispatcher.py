"""Диспетчер: событие → правило → публичный ответ → материал в директ.

Очередь своя и живёт в Postgres: claim через UPDATE ... FOR UPDATE SKIP LOCKED,
задержка ретрая 2**attempts * 60 c с потолком в час. Брокера сюда не заводим —
у установки и так есть база, а вторая инфраструктура ломается отдельно от первой.

Два решения разведены намеренно и не склеиваются обратно:
  «отвечать ли публично» — да всегда, когда есть чем и есть под чем (комментарий);
  «выдавать ли материал» — ровно один раз на пару (правило, человек).
Повторное обращение получает публичный ответ и НЕ получает второго директа: молчание
под постом видят посторонние, а второй private reply запрещён платформой.
"""

import asyncio
import contextlib
import logging
import random
import time
from datetime import datetime, timezone

import db
import meta
import rules
import tokens
from config import IG_DAILY_DM_LIMIT, IG_DISPATCH_RATE, IG_USER_ID, PANEL_URL

log = logging.getLogger("dispatcher")

# Попытка засчитывается при claim'е, поэтому сравнение идёт с уже увеличенным значением,
# а задержка растёт как 2**attempts минут — но с потолком в час.
# Шесть попыток, а не три: на том конце внешняя платформа с инцидентами в десятки минут,
# при окне доставки 7 суток. Бюджет в шесть минут делал ложный FAILED (а с ним и
# запертого от материала человека) обычным делом.
MAX_ATTEMPTS = 6
RETRY_BASE_SEC = 60
RETRY_MAX_SEC = 60 * 60
# Лимит темпа Meta — не вина доставки: ждём дольше и попытку не жжём.
RATE_LIMIT_DELAY_SEC = 15 * 60
TOKEN_PAUSE_DELAY_SEC = 15 * 60
IDLE_SLEEP_SEC = 5
STUCK_SWEEP_SEC = 5 * 60
# Алерт по накоплению отказов: одна неудача — это жизнь, пять за час — сломанная механика.
FAILURE_WINDOW_MIN = 60
FAILURE_ALERT_THRESHOLD = 5
FAILURE_ALERT_COOLDOWN_SEC = 60 * 60
# Пауза (нет токена, упёрлись в суточный бюджет) — это тоже отказ, просто бесшумный:
# health зелёный, ошибок ноль, доставки копятся. Сигналим, пока очередь непуста.
PAUSE_ALERT_COOLDOWN_SEC = 6 * 60 * 60
BUDGET_RECHECK_SEC = 60

# Комментарий от самого аккаунта: без этой проверки сервис отвечает на собственный
# публичный ответ и уходит в петлю — главный самострел такой механики.
SELF_IDS = {IG_USER_ID} if IG_USER_ID else set()

_last_send_at = 0.0
# Кулдаун по КЛЮЧУ причины: срочный алерт «правило не настроено» не должен на час
# затыкать сигнал о накоплении отказов или о простое очереди — это разные события.
# Значений 0.0 здесь нет намеренно: time.monotonic() в linux-контейнере считается от
# загрузки ХОСТА, и «0 + кулдаун» на свежем хосте ещё не наступил — первый же алерт
# был бы съеден молча. Отсутствие ключа = ещё не сигналили.
_alert_at: dict[str, float] = {}
# То же самое и здесь: 0.0 означало бы «свип только что был» и «бюджет только что считали»
# на хосте, который загрузился меньше кулдауна назад. Для свипа это худший момент из всех —
# перезагрузка хоста и есть та смерть процесса, после которой доставки застревают.
_last_sweep_at: float | None = None
_budget_at: float | None = None
_budget_used = 0

# Остановка сервиса. Взводится в lifespan ДО отмены задач: у публичного ответа
# идемпотентности на стороне Meta нет, и отмена посреди POST /{comment_id}/replies даёт
# вторую реплику под тем же комментарием, когда свипер поднимет строку. Тихая потеря была
# дешевле, чем две одинаковые реплики в ленте на глазах у аудитории.
stopping = asyncio.Event()
# Отметка живости цикла: смерть таска иначе не видна снаружи вообще — health отвечает 200,
# а алерты о простое живут ВНУТРИ этого же цикла.
last_tick_at: datetime | None = None


async def run() -> None:
    """Единственный цикл сервиса, отвечающий человеку."""
    global last_tick_at
    log.info("диспетчер запущен: не больше %s отправок в минуту", IG_DISPATCH_RATE)
    last_tick_at = _now()
    while not stopping.is_set():
        busy = False
        try:
            busy = await tick()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("dispatcher")
        last_tick_at = _now()
        if busy:
            continue
        # Ожидание, прерываемое остановкой: простаивающий сервис не должен задерживать
        # деплой на IDLE_SLEEP_SEC, а занятый — обязан дожать текущую доставку.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stopping.wait(), IDLE_SLEEP_SEC)
    log.info("диспетчер остановлен штатно")


async def tick() -> bool:
    await sweep_stuck()
    busy = await intake_once()
    token = await tokens.state()
    if not token.usable:
        # Пауза, а не отказ: доставки копятся и уйдут, когда владелец подставит токен.
        # Жечь их попытки, пока отправлять нечем, — потерять их к моменту починки.
        await note_paused(
            "токен",
            "доступ к Instagram не работает: токена нет или Meta его не принимает",
            f"Вставьте свежий токен: {PANEL_URL}, раздел «Токен». Очередь уйдёт сама.",
        )
        return busy
    if await over_daily_budget():
        # Темп ограничивает скорость, бюджет — объём. Рискует этим аккаунт владельца
        # установки, а не сервер: сотня автоматических сообщений незнакомым людям за
        # час — ровно тот профиль, который платформа ловит как спам.
        await note_paused(
            "бюджет",
            f"сработал суточный потолок в {IG_DAILY_DM_LIMIT} сообщений",
            "Чинить нечего: отправка продолжится сама. Потолок поднимается переменной "
            "IG_DAILY_DM_LIMIT — но сначала посмотрите, кому и что уже ушло.",
        )
        return busy
    if stopping.is_set():
        # Новую доставку на остановке не начинаем: окно дожатия обслуживает ту, что уже
        # в полёте. Иначе POST, стартовавший внутри окна, попадёт под отмену — и вернётся
        # ровно двоение публичной реплики, ради которого окно и заводилось.
        return busy
    return await dispatch_once(token.value) or busy


async def over_daily_budget() -> bool:
    """Потолок отправок за сутки. Считается по факту ухода сообщения, а не по попыткам."""
    global _budget_at, _budget_used
    if IG_DAILY_DM_LIMIT <= 0:
        return False
    if _budget_at is None or time.monotonic() - _budget_at >= BUDGET_RECHECK_SEC:
        _budget_used = await db.count_dm_sent_since(24)
        _budget_at = time.monotonic()
    return _budget_used >= IG_DAILY_DM_LIMIT


# ---------- Событие → доставка ----------


async def intake_once() -> bool:
    """Одно событие журнала: разобрать, подобрать правило, завести доставку.

    Отметка processed_at и вставка доставки — в одной транзакции: иначе падение между
    ними теряет комментарий молча, а ig_event объявлен единственным источником правды.
    Наружу не бросает НИКОГДА: исключение здесь означало бы, что одно ядовитое событие
    вечно занимает голову очереди и вместе с собой останавливает доставку всем остальным.
    """
    claimed: list[int] = []
    try:
        async with db.pool_ref().connection() as conn:
            async with conn.transaction():
                event = await db.claim_event(conn)
                if event is None:
                    return False
                claimed.append(event["id"])
                cand = rules.parse_event(
                    event["field"], event["event_key"], event["payload"],
                    SELF_IDS, event["received_at"],
                )
                if cand is None:
                    log.info("событие %s (%s): отвечать не на что", event["id"], event["field"])
                    return True
                if foreign_account(event["payload"]):
                    # Установка обслуживает ОДИН аккаунт — свой. Событие чужого аккаунта
                    # (одно приложение Meta подписали на два) иначе было бы обслужено
                    # нашим токеном: ответ ушёл бы от чужого имени, а счётчик лимитов
                    # съел бы владелец установки. К Meta при этом не идём вовсе.
                    log.warning(
                        "событие %s: аккаунт-получатель не наш (entry_id %s) — пропускаю",
                        event["id"],
                        event["payload"].get("entry_id"),
                    )
                    await db.insert_delivery(conn, cand, None, "SKIPPED_FOREIGN_ACCOUNT")
                    return True
                if cand.self_authored:
                    await db.insert_delivery(conn, cand, None, "SKIPPED_SELF")
                    return True
                rule = rules.match_rule([to_rule(r) for r in await db.load_rules(conn)], cand)
                state = "PENDING" if rule else "SKIPPED_NO_RULE"
                created = await db.insert_delivery(conn, cand, rule.id if rule else None, state)
                if created is None:
                    log.info("повтор: доставка по %s %s уже заведена", cand.source, cand.source_id)
                elif rule:
                    log.info("доставка %s: правило «%s»", created, rule.name)
                return True
    except Exception:
        # Транзакция откатилась вместе с processed_at — помечаем событие отдельно,
        # иначе следующий круг возьмёт его же и очередь встанет навсегда.
        event_id = claimed[0] if claimed else None
        log.exception("intake: событие %s не разобралось", event_id)
        if event_id is not None:
            await db.mark_event_processed(event_id)
        return True


def foreign_account(payload: dict) -> bool:
    """Событие адресовано НЕ нашему аккаунту: entry.id вебхука — это получатель.

    Установка обслуживает один аккаунт, и это выражено схемой (CHECK id = 1 в ig_token).
    Здесь то же самое выражено на входе: одно приложение Meta можно подписать на два
    аккаунта, и тогда чужие комментарии обслуживались бы нашим токеном.

    Обе неизвестности трактуются в пользу работы, а не тишины: пустой IG_USER_ID (аккаунт
    ещё не назван) и событие без entry.id сравнивать не с чем, и глушить их значит
    остановить механику молча — ровно тот отказ, который эта установка не умеет заметить.
    """
    if not IG_USER_ID:
        return False
    entry_id = str(payload.get("entry_id") or "")
    return bool(entry_id) and entry_id != IG_USER_ID


def to_rule(row: dict) -> rules.Rule:
    return rules.Rule(
        id=row["id"],
        name=row["name"],
        trigger=row["trigger"],
        media_id=row["media_id"],
        keywords=list(row["keywords"] or []),
        match_mode=row["match_mode"],
        priority=row["priority"],
        public_replies=list(row["public_replies"] or []),
        duplicate_replies=list(row["duplicate_replies"] or []),
        dm_text=row["dm_text"],
        dm_buttons=list(row["dm_buttons"] or []),
    )


# ---------- Доставка → Meta ----------


async def dispatch_once(token: str) -> bool:
    delivery = await db.claim_delivery()
    if delivery is None:
        return False
    try:
        await deliver(delivery, token)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        await handle_failure(delivery, exc)
    return True


async def deliver(d: dict, token: str) -> None:
    if d["expires_at"] <= _now():
        # Окно платформы закрылось, пока доставка ждала ретраев: к Meta не идём вовсе.
        # Бронь снимаем и здесь: материал не уходил, запирать человека не за что, а путь
        # сюда обычный — пауза по мёртвому токену дольше суток закрывает окно канала DM.
        await release(d)
        await db.finish_delivery(d["id"], "EXPIRED", "окно платформы закрылось")
        return

    row = await db.load_rule(d["rule_id"]) if d["rule_id"] else None
    if row is None:
        await release(d)  # правило выключили между попытками — бронь переживает выключение
        await db.finish_delivery(d["id"], "SKIPPED_NO_RULE", "правило выключено или удалено")
        return
    rule = to_rule(row)

    reason = rules.unconfigured(rule)
    if reason:
        # Ни одного обращения к Meta: публичное «отправила в директ» при пустом директе —
        # худший исход, он выглядит как обман, а не как поломка.
        await release(d)
        await db.finish_delivery(d["id"], "FAILED", reason)
        # Свой ключ кулдауна на каждое правило: два недописанных правила не должны
        # затыкать друг друга, как не затыкают друг друга разные причины отказа.
        await alert(
            f"правило:{rule.id}",
            f"Instagram: правило «{rule.name}» никому не отвечает — оно ещё не дописано.\n"
            "Сервис намеренно не пошёл в Instagram: публичное «отправили в директ» при "
            "пустом директе выглядит как обман, а не как поломка.\n"
            f"Допишите правило: {PANEL_URL}, раздел «Правила».\n"
            f"Что именно мешает: {reason}",
            FAILURE_ALERT_COOLDOWN_SEC,
        )
        return

    owner = await db.reserve_contact_rule(rule.id, d["igsid"], d["id"])
    if owner == d["id"]:
        await reply_public(d, rule.public_replies, token)
        await send_material(d, rule, token)
        await db.finish_delivery(d["id"], "DONE")
        return

    replied = await reply_public(d, rule.duplicate_replies, token)
    # Разные состояния, потому что это разные события для статистики: материал выдан
    # один раз, а ответов на повтор может быть сколько угодно.
    await db.finish_delivery(d["id"], "REPLIED_DUPLICATE" if replied else "SKIPPED_DUPLICATE")


async def reply_public(d: dict, variants: list[str], token: str) -> bool:
    """Публичный ответ под комментарием. False — отвечать было нечем или это не комментарий."""
    if d["source"] != rules.COMMENT or not variants:
        return False
    if d["public_reply_id"]:
        return True  # ответили на прошлой попытке; вторая реплика в ветке не нужна
    await throttle()
    # Вариант выбирается из массива, а внутри строки раскрывается {а|б} — в момент
    # отправки, а не при сохранении: в базе лежит шаблон, в ленте — разные реплики.
    text = rules.expand(random.choice(variants))
    reply_id = await meta.reply_to_comment(d["source_id"], text, token)
    # Пустой id от Meta — всё равно факт ответа: помечаем, иначе ретрай ответит второй раз.
    await db.mark_public_reply(d["id"], reply_id or "sent")
    return True


async def send_material(d: dict, rule: rules.Rule, token: str) -> None:
    """Материал в директ: private reply на комментарий или ответ в открытом диалоге."""
    if d["dm_message_id"]:
        return  # уже ушло на прошлой попытке — второго private reply платформа не даст
    await throttle()
    # Отметка ПОПЫТКИ до запроса: после неё «ответа не видели» уже не читается как
    # «не отправляли», и решение о брони не зависит от знания кодов ошибок Meta.
    await db.note_dm_attempt(d["id"])
    d["dm_attempts"] = (d["dm_attempts"] or 0) + 1
    text = rules.expand(rule.dm_text)
    buttons = render_buttons(rule.dm_buttons)
    try:
        if d["source"] == rules.COMMENT:
            message_id = await meta.send_private_reply(d["source_id"], text, buttons, token)
        else:
            message_id = await meta.send_direct_message(d["igsid"], text, buttons, token)
    except meta.MetaError as exc:
        # Meta ОТВЕТИЛА внятным отказом — исход известен, сообщение не ушло: метку
        # неизвестности снимаем, иначе бронь на человека становится вечной при мёртвом
        # токене, закрытом окне и любом другом объяснимом отказе. Незнакомый код и
        # «уже отвечали» исключены намеренно: там исход как раз неизвестен или обратный.
        verdict = meta.classify(exc)
        if 400 <= (exc.status or 0) < 500 and verdict not in (
            meta.TERMINAL_UNKNOWN,
            meta.ALREADY_DONE,
        ):
            await db.clear_dm_attempt(d["id"])
            d["dm_attempts"] = 0
        raise
    await db.mark_dm_sent(d["id"], message_id or "sent")
    global _budget_used
    _budget_used += 1


def render_buttons(buttons: list) -> list[dict]:
    """Заголовки кнопок раскрываются тем же движком, что и тексты."""
    out = []
    for button in buttons:
        if not isinstance(button, dict):
            continue
        out.append({**button, "title": rules.expand(str(button.get("title") or ""))})
    return out


async def handle_failure(d: dict, exc: Exception) -> None:
    """Классификация отказа Meta. Слепого ретрая нет ни в одной ветке."""
    verdict = meta.classify(exc)
    message = str(exc)[:500]
    if verdict == meta.TOKEN_INVALID:
        await tokens.mark_invalid(message)  # пауза диспетчера + алерт владельцу
        await db.reschedule_delivery(d["id"], TOKEN_PAUSE_DELAY_SEC, message, count_attempt=False)
        return
    if verdict == meta.RATE_LIMIT:
        await db.reschedule_delivery(d["id"], RATE_LIMIT_DELAY_SEC, message, count_attempt=False)
        return
    if verdict == meta.EXPIRED:
        await release(d)
        await db.finish_delivery(d["id"], "EXPIRED", message)
        return
    if verdict == meta.ALREADY_DONE:
        # Meta считает, что private reply на этот комментарий уже был. Значит доставлено.
        await db.finish_delivery(d["id"], "DONE", message)
        return
    if verdict == meta.RETRY and d["attempts"] < MAX_ATTEMPTS:
        delay = min(2 ** d["attempts"] * RETRY_BASE_SEC, RETRY_MAX_SEC)
        await db.reschedule_delivery(d["id"], delay, message, count_attempt=True)
        return
    log.warning("доставка %s окончательно не удалась: %s", d["id"], message)
    if verdict == meta.TERMINAL_UNKNOWN:
        # Кода не знаем — значит не знаем и того, дошло ли сообщение. Бронь не снимаем:
        # запертый человек виден в системе и поправим, вторая копия материала необратима.
        # Ключ кулдауна — сам код: иначе «правило не настроено» съедает единственную пробу,
        # которой и добываются пары для WINDOW_CODES/DUPLICATE_CODES.
        await db.finish_delivery(d["id"], "FAILED", message)
        await alert(
            f"неизвестный код:{getattr(exc, 'code', None)}/{getattr(exc, 'subcode', None)}",
            "Instagram отказал по причине, которой сервис не знает: один человек не получил "
            f"материал (доставка {d['id']}).\n"
            f"Остальные ответы идут. Если сообщение повторяется — откройте {PANEL_URL}, "
            "раздел «Очередь», и передайте код из последней строки разработчику пакета: "
            "по нему этот отказ станет распознаваемым.\n"
            f"Технические подробности: {message[:300]}",
            FAILURE_ALERT_COOLDOWN_SEC,
        )
        return
    await release(d)
    await db.finish_delivery(d["id"], "FAILED", message)
    await note_failure(message)


async def release(d: dict) -> None:
    """Терминальный отказ снимает СВОЮ резервацию, если материал доказанно не уходил.

    Иначе один десятиминутный сбой Meta запирает человека от материала навсегда, а его
    следующий комментарий получает публичное «уже отправила» — утверждение, которого
    не было. Отправленное при этом не разблокируется: условие смотрит на dm_message_id.
    """
    if not d["rule_id"]:
        return
    if await db.release_contact_rule(d["rule_id"], d["igsid"], d["id"]):
        log.info("доставка %s: резервация снята, материал не уходил", d["id"])
        return
    if d["dm_attempts"]:
        # Бронь осталась, потому что исход отправки так и не выяснился. Такой человек
        # заперт от материала, а на следующий комментарий получит публичное «уже
        # отправила» — молчать об этом нельзя: обычный note_failure ждёт пяти отказов.
        await alert(
            f"заперт:{d['id']}",
            "Instagram: один человек может остаться без материала — отправку начали, а "
            "подтверждения от платформы не получили.\n"
            "Пока бронь на нём висит, на повторный комментарий он получит публичное «уже "
            "отправили» — и это будет неправдой, если сообщение до него не дошло.\n"
            f"Загляните в свой директ. Не дошло — откройте {PANEL_URL}, раздел «Очередь», "
            f"и нажмите «снять бронь» у доставки {d['id']}: материал уйдёт заново.\n"
            f"Технические подробности: igsid {d['igsid']}, доставка {d['id']}.",
            FAILURE_ALERT_COOLDOWN_SEC,
        )


# ---------- Темп, зависшие, алерты ----------


async def throttle() -> None:
    """Лимит темпа отправки: виральный пост не должен упереть аккаунт в лимиты Meta за минуту."""
    global _last_send_at
    interval = 60.0 / max(IG_DISPATCH_RATE, 1)
    wait = _last_send_at + interval - time.monotonic()
    if wait > 0:
        await asyncio.sleep(wait)
    _last_send_at = time.monotonic()


async def sweep_stuck() -> None:
    global _last_sweep_at
    if _last_sweep_at is not None and time.monotonic() - _last_sweep_at < STUCK_SWEEP_SEC:
        return
    _last_sweep_at = time.monotonic()
    recovered = await db.recover_stuck_deliveries()
    if recovered:
        log.warning("вернул в очередь зависших доставок: %s", recovered)


async def note_failure(reason: str) -> None:
    """Алерт по накоплению отказов. Тихая деградация здесь неотличима от «всё работает».

    Порог здесь потому, что одна неудача — это жизнь, а пять за час — сломанная механика.
    Отказы со СВОЕЙ починкой (недописанное правило, запертый человек) порога не ждут:
    у них отдельные алерты со своими ключами кулдауна.
    """
    failed = await db.count_failed_since(FAILURE_WINDOW_MIN)
    if failed < FAILURE_ALERT_THRESHOLD:
        return
    await alert(
        "отказы",
        f"Instagram: за час не получили ответ {failed} чел. — они написали кодовое слово, "
        "а материал им не ушёл.\n"
        f"Откройте {PANEL_URL}, раздел «Очередь»: там видно, на чём именно спотыкается "
        "отправка.\n"
        f"Технические подробности: {reason[:300]}",
        FAILURE_ALERT_COOLDOWN_SEC,
    )


async def note_paused(key: str, reason: str, action: str) -> None:
    """Алерт о простое очереди. Пауза бесшумна по устройству: health зелёный, ошибок ноль,
    доставки просто копятся — узнать о ней иначе неоткуда."""
    pending = await db.count_pending()
    if not pending:
        return  # пауза с пустой очередью никому не мешает
    await alert(
        f"пауза:{key}",
        f"Instagram: автоответы стоят — {reason}.\nЖдут материала: {pending} чел.\n{action}",
        PAUSE_ALERT_COOLDOWN_SEC,
    )


async def alert(key: str, text: str, cooldown_sec: float) -> None:
    """Сигнал владельцу с кулдауном ПО ПРИЧИНЕ: разные поломки не затыкают друг друга."""
    last = _alert_at.get(key)
    if last is not None and time.monotonic() - last < cooldown_sec:
        return
    _alert_at[key] = time.monotonic()
    await meta.alert_owner(text)


def _now() -> datetime:
    return datetime.now(timezone.utc)
