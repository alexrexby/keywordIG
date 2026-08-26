"""Приёмник вебхуков Instagram и сборка процесса: подпись → сырой журнал ig_event → 200.

У приёмника задача ровно одна: превратить «доходят ли вебхуки» в строку в таблице.
Кто на них отвечает, решает диспетчер, и запускается он отсюда же — вместе с продлением
токена, ретеншеном и сторожком за самим диспетчером.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import signal
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.requests import ClientDisconnect

import admin
import db
import dispatcher
import legal
import logsafe
import meta
import panel
import tokens
from config import HEALTH_STALE_SEC, IG_APP_SECRET, IG_VERIFY_TOKEN
from signature import verify_signature, verify_token

logging.basicConfig(level=logging.INFO)
# После basicConfig: фильтр вешается на УЖЕ созданный обработчик. Затирает секреты у всех
# логгеров процесса, включая сторонние, — точечные уровни обойдёт первая же новая библиотека.
logsafe.install()
log = logging.getLogger("main")

# Тело Meta — единицы килобайт. Тот же предел стоит рубежом раньше, в Caddy
# (request_body max_size 256KiB), и подпёрт mem_limit контейнера: роут публичный
# по устройству, а OOM-killer выбирает жертву на ХОСТЕ — если рядом на сервере стоит
# что-то ещё, отказ обязан остаться внутри этого контейнера.
MAX_BODY_BYTES = 256 * 1024
# Потолок событий в одном теле: батч Meta — единицы штук, всё остальное подозрительно.
MAX_EVENTS_PER_REQUEST = 200
# event_key входит в btree-индекс (предел строки ~2704 байта) — длинный id заменяем хешем.
MAX_EVENT_KEY_LEN = 200
# Окно дожатия на остановке. Худший случай доставки больше окна (два throttle плюс два
# POST по 20 с = 46 с), и это осознанно: окно закрывает публичный ответ и начало директа,
# а срезка на самом директе безопасна — второй private reply на тот же комментарий
# запрещает уже платформа. Раздувать окно дороже: на всё время дожатия закрыт приём
# вебхуков. Новую доставку внутри окна диспетчер не начинает (dispatcher.tick).
# В compose под это стоит stop_grace_period: 30s — без него Docker убьёт контейнер
# через 10 с и окно останется только на бумаге.
SHUTDOWN_GRACE_SEC = 25
# Как часто сторожок смотрит, жив ли круг диспетчера.
WATCHDOG_SWEEP_SEC = 60
RETENTION_SWEEP_SEC = 6 * 60 * 60
# Продление токена: запас до истечения — 10 суток, поэтому раз в шесть часов с избытком.
TOKEN_SWEEP_SEC = 6 * 60 * 60
# Тело в 256 КБ приходит за миллисекунды. Пятнадцати секунд хватает любому честному
# отправителю, а держать соединение открытым вечно ни uvicorn, ни Caddy не мешают.
BODY_READ_TIMEOUT_SEC = 15
# Строка в лог на каждый отказ подписи — это заливка логов с улицы (10 МБ × 3 на общем
# хосте), поэтому отказы считаем, а в лог кладём сводку не чаще раза в минуту.
REJECT_LOG_PERIOD_SEC = 60

rejected_total = 0
# None, а не 0.0: monotonic считается от загрузки хоста, и на свежем хосте первая сводка
# об отказах не попала бы в лог вовсе. Тот же капкан, что чинили в диспетчере.
rejected_logged_at: float | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.pool = db.make_pool()
    await db.pool.open()
    applied = await db.migrate()
    log.info("миграции: %s", ", ".join(applied) if applied else "нечего применять")
    if not meta.channel_configured():
        # Громко, потому что тихо здесь стоит дороже всего: без канала алертов остальные
        # механизмы самодиагностики немы, и любая остановка автоответов выглядит как
        # «всё в порядке». Старт при этом не отменяем — приём вебхуков важнее сигнализации,
        # а настроить канал можно, не теряя ни одного события.
        log.error(
            "канал алертов не настроен (пусты IG_ALERT_BOT_TOKEN или IG_ALERT_CHAT_ID) — "
            "сказать об остановке автоответов будет некому и нечем"
        )
    try:
        await tokens.ensure_from_env()
    except Exception:
        # Приём вебхуков важнее отправки: без токена приёмник обязан работать дальше,
        # а диспетчер сам встанет на паузу и скажет об этом владельцу.
        log.exception("первичная загрузка токена")
    loops = [
        asyncio.create_task(retention_loop()),
        asyncio.create_task(token_loop()),
        asyncio.create_task(watchdog_loop()),
        asyncio.create_task(dispatcher.run()),
    ]
    retention, token, guard, dispatch = loops
    for name, task in (
        ("ретеншен", retention),
        ("токен", token),
        ("сторожок", guard),
        ("диспетчер", dispatch),
    ):
        task.add_done_callback(watch(name))
    yield
    # Сначала даём диспетчеру дожать текущую доставку: отмена посреди публичного ответа
    # оборачивается второй репликой под комментарием, когда свипер поднимет строку.
    dispatcher.stopping.set()
    retention.cancel()
    token.cancel()
    guard.cancel()
    done, pending = await asyncio.wait([dispatch], timeout=SHUTDOWN_GRACE_SEC)
    if pending:
        log.warning("диспетчер не успел за %s с — отменяю", SHUTDOWN_GRACE_SEC)
        dispatch.cancel()
    for task in loops:
        # Дожидаемся: иначе pool.close() выдернет соединение из-под работающего запроса.
        # suppress(BaseException), а не CancelledError: уже умерший таск иначе пере-бросит
        # своё исключение сюда, и ни meta.close(), ни pool.close() не выполнятся.
        with contextlib.suppress(BaseException):
            await task
    await meta.close()
    await db.pool.close()


def watch(name: str):
    """Смерть фонового цикла обязана быть видна снаружи.

    t.exception() без записи гасит и штатное предупреждение Python, и сам факт: контейнер
    остаётся живым, health отвечает 200, а работа не делается. Поэтому — строка в лог и
    SIGTERM себе: перезапуск делает restart: unless-stopped, а не наши руки.
    """

    def done(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        try:
            log.error("цикл %s умер: %r — прошу перезапуск контейнера", name, exc)
        finally:
            # Сигнал важнее записи: если логирование по любой причине бросит, перезапуск
            # всё равно обязан случиться, иначе контейнер останется живым и немым.
            os.kill(os.getpid(), signal.SIGTERM)

    return done


# Интерактивной схемы API нет: /docs и /openapi.json — это карта админ-роутов, отданная
# в интернет, а читателей у неё здесь нет. Выключено в приложении, а не на прокси: так
# оно остаётся выключенным и у того, кто поставит сервис за своим прокси.
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
# Машинный админ-API правил — отдельным модулем со своими воротами IG_ADMIN_TOKEN.
# Приёма вебхуков он не касается: убрать эту строку и admin.py достаточно, чтобы сервис
# вернулся к приёму вебхуков и доставке без всякого админ-API.
app.include_router(admin.router)
# Панель для человека: свои ворота (форма, пароль, подписанная cookie), свой префикс
# /panel/*. Два роутера, а не один: на втором висит проверка сессии, и вход в неё
# по устройству не попадает — путь-исключение внутри общей проверки однажды оказался бы
# лишним открытым адресом. Убрать обе строки, panel.py и templates/ — сервис продолжит
# принимать вебхуки и отвечать людям, просто настраивать его придётся через admin-API.
app.include_router(panel.login_router)
app.include_router(panel.router)
# Публичные страницы: политику конфиденциальности требует сама Meta при публикации
# приложения, а без публикации не приходят вебхуки. Отдаёт их сервис, чтобы адрес
# не зависел от чужого хостинга и не протухал отдельно от установки.
app.include_router(legal.router)
# Отказы панели — человеческой страницей, а не JSON'ом и не голым «Internal Server Error»:
# упавшая база — самый частый отказ установки, и панель существует ровно ради таких минут.
# Обработчики живут в panel.py и на путях вне /panel/* ведут себя как раньше; убрать их
# вместе с панелью — это те же две строки.
app.add_exception_handler(HTTPException, panel.on_http_error)
app.add_exception_handler(Exception, panel.on_error)


async def retention_loop():
    """Ретеншен: журнал уведомлений и карточки обращений не хранятся вечно.

    Второе — не гигиена диска, а исполнение обещания: срок из публичной политики
    конфиденциальности берётся из той же переменной, что и эта чистка
    (config.DELIVERY_RETENTION_DAYS). Документ, который сервис не соблюдает, хуже
    отсутствия документа.
    """
    while True:
        try:
            events = await db.purge_old_events()
            deliveries = await db.purge_old_deliveries()
            if events or deliveries:
                log.info("ретеншен: удалено уведомлений %s, обращений %s", events, deliveries)
        except Exception:
            log.exception("retention")
        await asyncio.sleep(RETENTION_SWEEP_SEC)


async def watchdog_loop():
    """Сторожок за кругом диспетчера.

    Смерть таска ловит watch(), а вот ЗАМЕРШИЙ, но живой круг не ловит никто: Docker Compose
    на unhealthy не реагирует (перезапуск по healthcheck умеет Swarm), то есть 503 на
    /ig/health — сигнал без адресата. Здесь у сигнала появляется актор: алерт владельцу и
    тот же SIGTERM себе, что и при смерти цикла, — дальше работает restart: unless-stopped.
    """
    while True:
        await asyncio.sleep(WATCHDOG_SWEEP_SEC)
        last = dispatcher.last_tick_at
        if last is None or dispatcher.stopping.is_set():
            continue
        stale = (datetime.now(timezone.utc) - last).total_seconds()
        if stale <= HEALTH_STALE_SEC:
            continue
        log.error("круг диспетчера замер на %s с — прошу перезапуск контейнера", int(stale))
        try:
            await meta.alert_owner(
                "Instagram: автоответы не уходят — сервис завис и сейчас перезапустит себя "
                "сам.\nДелать ничего не нужно: через минуту очередь разберётся. Но если это "
                "сообщение приходит снова и снова, перезапуск не помогает — тогда смотрите "
                "логи контейнера, там причина.\n"
                f"Технические подробности: круг диспетчера замер на {int(stale)} с."
            )
        finally:
            os.kill(os.getpid(), signal.SIGTERM)
        return


async def token_loop():
    """Продление токена заранее: непродлённый 60 дней умирает навсегда."""
    while True:
        try:
            await tokens.refresh_if_needed()
        except Exception:
            log.exception("token refresh")
        await asyncio.sleep(TOKEN_SWEEP_SEC)


@app.get("/ig/health")
async def health():
    """Живость = свежесть круга диспетчера, а не факт ответа HTTP.

    Безусловные 200 и были той причиной, по которой немой сервис выглядел здоровым:
    контейнер жив, healthcheck зелёный, а отвечать людям некому. В БД не ходим намеренно —
    приёмник вебхуков обязан отвечать Meta и при мигнувшем Postgres.
    """
    last = dispatcher.last_tick_at
    stale = (datetime.now(timezone.utc) - last).total_seconds() if last else None
    body = {"ok": True, "last_tick_at": last.isoformat() if last else None}
    if stale is not None and stale > HEALTH_STALE_SEC:
        body["ok"] = False
        body["stale_sec"] = int(stale)
        return JSONResponse(body, status_code=503)
    return body


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
    # Meta через ON CONFLICT) и наполняет диск установки.
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
    if rejected_logged_at is None or now - rejected_logged_at >= REJECT_LOG_PERIOD_SEC:
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
