"""Приёмник вебхуков Instagram: подпись → сырой журнал ig_event → 200.

Ответов человеку, правил и обращений в Meta здесь нет — это этап 2.
Задача приёмника ровно одна: превратить «доходят ли вебхуки» в строку в таблице.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.requests import ClientDisconnect

import db
from config import IG_APP_SECRET, IG_VERIFY_TOKEN
from signature import verify_signature, verify_token

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("main")

# Тело Meta — единицы килобайт. Тот же предел стоит рубежом раньше, в Caddy
# (request_body max_size 256KiB), и подпёрт mem_limit контейнера: роут публичный
# по устройству, а хост общий с соседним сервисом — OOM там роняет два продукта.
MAX_BODY_BYTES = 256 * 1024
# Потолок событий в одном теле: батч Meta — единицы штук, всё остальное подозрительно.
MAX_EVENTS_PER_REQUEST = 200
# event_key входит в btree-индекс (предел строки ~2704 байта) — длинный id заменяем хешем.
MAX_EVENT_KEY_LEN = 200
RETENTION_SWEEP_SEC = 6 * 60 * 60
# Тело в 256 КБ приходит за миллисекунды. Пятнадцати секунд хватает любому честному
# отправителю, а держать соединение открытым вечно ни uvicorn, ни Caddy не мешают.
BODY_READ_TIMEOUT_SEC = 15
# Строка в лог на каждый отказ подписи — это заливка логов с улицы (10 МБ × 3 на общем
# хосте), поэтому отказы считаем, а в лог кладём сводку не чаще раза в минуту.
REJECT_LOG_PERIOD_SEC = 60

rejected_total = 0
rejected_logged_at = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.pool = db.make_pool()
    await db.pool.open()
    applied = await db.migrate()
    log.info("миграции: %s", ", ".join(applied) if applied else "нечего применять")
    retention = asyncio.create_task(retention_loop())
    # Исключение таска нужно вычитать, иначе смерть цикла пройдёт молча.
    retention.add_done_callback(lambda t: t.cancelled() or t.exception())
    yield
    retention.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await retention  # дожидаемся, иначе pool.close() выдернет соединение из-под DELETE
    await db.pool.close()


app = FastAPI(lifespan=lifespan)


async def retention_loop():
    """Ретеншен: сырой журнал не растёт бесконечно."""
    while True:
        try:
            removed = await db.purge_old_events()
            if removed:
                log.info("ретеншен: удалено событий %s", removed)
        except Exception:
            log.exception("retention")
        await asyncio.sleep(RETENTION_SWEEP_SEC)


@app.get("/ig/health")
async def health():
    return {"ok": True}


@app.get("/ig/webhook")
async def webhook_verify(request: Request):
    """Handshake подписки Meta: сверить verify token и вернуть challenge как text/plain."""
    # Параметры приходят с ТОЧКАМИ в именах (hub.mode, hub.verify_token, hub.challenge) —
    # в аргументы функции они не разбираются, читаем query_params как есть.
    q = request.query_params
    if q.get("hub.mode") != "subscribe" or not verify_token(q.get("hub.verify_token"), IG_VERIFY_TOKEN):
        note_rejected("handshake")
        return PlainTextResponse("forbidden", status_code=403)
    return PlainTextResponse(q.get("hub.challenge", ""))


@app.post("/ig/webhook")
async def webhook_receive(request: Request):
    # Content-Length смотрим ДО чтения: буферизация чужого гигабайта и есть та работа,
    # которую нельзя делать на недоверенном вводе.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        note_rejected("тело больше лимита")
        return JSONResponse({"error": "too large"}, status_code=413)

    # Сырые байты ДО парсинга JSON: подпись считается по ним, пересериализация её ломает.
    try:
        raw = await asyncio.wait_for(read_body(request), BODY_READ_TIMEOUT_SEC)
    except ClientDisconnect:
        # Клиент оборвал тело. Ответ читать уже некому, важно другое: не сыпать ASGI-трейсом
        # (килобайты на запрос) — иначе ротация лога вымывается, а с ней и следы настоящих отказов.
        note_rejected("обрыв клиента")
        return JSONResponse({"error": "client disconnected"}, status_code=400)
    except asyncio.TimeoutError:
        note_rejected("таймаут тела")
        return JSONResponse({"error": "body read timeout"}, status_code=408)
    if raw is None:
        note_rejected("тело больше лимита")
        return JSONResponse({"error": "too large"}, status_code=413)

    # Подпись — ворота, а не колонка: не сошлась — 403 и выход, в БД не попадает ничего.
    # Иначе кто угодно с улицы занимает ключи дедупликации (и вытесняет настоящее событие
    # Meta через ON CONFLICT) и наполняет том, общий с CRM.
    if not verify_signature(raw, request.headers.get("X-Hub-Signature-256"), IG_APP_SECRET):
        note_rejected("подпись")
        return JSONResponse({"error": "bad signature"}, status_code=403)

    try:
        events = extract_events(raw)
    except Exception:
        # Незнакомая форма — не повод отдавать 500: на 5xx Meta ретраит вечно и в итоге
        # отключает подписку. Что не разобралось — то не разобралось, наружу 200.
        log.exception("extract_events")
        events = []
    if len(events) > MAX_EVENTS_PER_REQUEST:
        log.warning("событий в теле %s — беру первые %s", len(events), MAX_EVENTS_PER_REQUEST)
        events = events[:MAX_EVENTS_PER_REQUEST]
    if not events:
        # Подпись сошлась — значит это действительно Meta, а форма незнакомая:
        # такое сохраняем целиком, иначе факт доставки потеряется.
        events = [("unknown", body_key(raw), {"unrecognized": raw.decode("utf-8", "replace")})]

    # Postgres не примет в jsonb NUL и одинокий суррогат, а отказ вставки — это 503,
    # на который Meta ретраит ТО ЖЕ тело до отключения подписки. Чистим перед записью;
    # сырые байты, по которым уже сошлась подпись, при этом не трогаются.
    events = [(scrub(field), scrub(key), scrub(payload)) for field, key, payload in events]

    try:
        fresh = await db.insert_events(events)
    except Exception:
        # Записать не смогли — пусть Meta ретраит, иначе событие пропадёт молча.
        log.exception("ig_event insert")
        return JSONResponse({"error": "storage unavailable"}, status_code=503)

    log.info("событий %s, из них новых %s", len(events), fresh)
    # 200 отдаём и на повтор доставки, и когда записывать было нечего: любой не-2xx
    # Meta считает отказом и ретраит вплоть до отключения подписки.
    return {"ok": True}


async def read_body(request: Request) -> bytes | None:
    """Тело с обрывом на лимите. None — тело больше MAX_BODY_BYTES.

    Не request.body(): starlette склеивает весь поток в память до всякой проверки,
    а при Transfer-Encoding: chunked заголовка content-length нет и верить нечему.
    """
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def note_rejected(reason: str) -> None:
    """Счёт любых отказов приёмника. Ни тела, ни заголовков, ни секретов в лог не идёт.

    Строка на каждый отказ — это заливка логов с улицы: ротация 10 МБ × 3 вымывается
    парой минут работы одной консоли, и вместе с ней уходят следы настоящих отказов.
    """
    global rejected_total, rejected_logged_at
    rejected_total += 1
    now = time.monotonic()
    if now - rejected_logged_at >= REJECT_LOG_PERIOD_SEC:
        rejected_logged_at = now
        log.warning("отказ (%s); отказов с рестарта: %s", reason, rejected_total)


def extract_events(raw: bytes) -> list[tuple[str, str, dict]]:
    """Разбирает тело вебхука в строки журнала: (field, event_key, payload).

    Ключ идемпотентности — comment_id для комментариев и mid для сообщений.
    Форма Meta: entry[].changes[] для полей подписки и entry[].messaging[] для Direct.
    """
    try:
        body = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(body, dict):
        return []

    events: list[tuple[str, str, dict]] = []
    for entry in as_list(body.get("entry")):
        if not isinstance(entry, dict):
            continue
        origin = {"entry_id": entry.get("id"), "entry_time": entry.get("time")}
        for change in as_list(entry.get("changes")):
            if not isinstance(change, dict):
                continue
            field = str(change.get("field") or "unknown")[:64]
            value = change.get("value")
            value = value if isinstance(value, dict) else {"value": value}
            key = event_key(value.get("id"), change)
            events.append((field, key, {**origin, "field": field, "value": value}))
        for item in as_list(entry.get("messaging")):
            if not isinstance(item, dict):
                continue
            message = item.get("message")
            mid = message.get("mid") if isinstance(message, dict) else None
            key = event_key(mid, item)
            events.append(("messages", key, {**origin, "field": "messages", "value": item}))
    return events


def scrub(value):
    """Убирает из строк то, что Postgres не сможет записать в jsonb."""
    if isinstance(value, str):
        return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, dict):
        return {scrub(k): scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def as_list(value) -> list:
    """Meta присылает списки, но чужому телу верить нельзя: `for x in 5` — это TypeError."""
    return value if isinstance(value, list) else []


def event_key(raw_id, item: dict) -> str:
    """comment_id / mid, а если их нет или id неприлично длинный — детерминированный хеш."""
    if isinstance(raw_id, (str, int)) and not isinstance(raw_id, bool):
        key = str(raw_id)
        if 0 < len(key) <= MAX_EVENT_KEY_LEN:
            return key
    return item_key(item)


def item_key(item: dict) -> str:
    """Ключ для события без собственного id: хеш самого события.

    Повторная доставка того же тела даёт тот же ключ и упирается в ON CONFLICT.
    """
    return "sha256:" + hashlib.sha256(
        json.dumps(item, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def body_key(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
