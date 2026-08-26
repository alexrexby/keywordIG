"""Машинный админ-API правил: CRUD, предпросмотр шаблона, замена токена, состояние.

Это API, а не страница для человека: JSON, ключ IG_ADMIN_TOKEN в заголовке, никаких
cookie и форм. Снаружи /ig/admin/* закрыт ещё и на прокси (403 в caddy/Caddyfile), то
есть ключ — вторые ворота, а не единственные.

ДВИЖОК ТЕКСТОВ ЖИВЁТ В rules.py, И ТОЛЬКО ТАМ. Форма не считает длину, не раскрывает
варианты и не проверяет скобки сама: два движка неизбежно разъедутся, и человек увидит
в предпросмотре не то, что получит подписчик. Поэтому /ig/admin/preview и валидация
сохранения зовут те же check_template / check_groups / longest / unconfigured, которыми
пользуется диспетчер перед отправкой в Meta.

Что здесь НЕ делается: правила не применяются к уже заведённым доставкам (очередь живёт
своей жизнью), события и доставки не редактируются, тексты не сочиняются. Один модуль —
одна работа; удалить admin.py и строку include_router в main.py достаточно, чтобы приём
вебхуков и доставка продолжили работать как раньше.
"""

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

import db
import dispatcher
import meta
import rules
import tokens
from config import IG_ADMIN_TOKEN, IG_DAILY_DM_LIMIT
from meta import MAX_BUTTONS, MAX_BUTTON_TITLE
from signature import constant_time_eq

log = logging.getLogger("admin")

# Имя заголовка ровно одно, и оно СВОЁ. Алиас под общим именем вроде X-Internal-Token
# когда-то принимался и снят намеренно: прав он не добавлял (сверка всегда с
# IG_ADMIN_TOKEN), но одинаковое имя рано или поздно приводит к «да это же тот самый
# ключ» — и мастер-секрет соседней системы оказывается в интернет-обращённом сервисе.
TOKEN_HEADER = "X-Admin-Token"

# Тело правила — единицы килобайт. Рубеж здесь ЕДИНСТВЕННЫЙ: request_body max_size из
# Caddyfile живёт внутри handle /ig/*, а handle-блоки взаимоисключающие, и на /ig/admin/*
# он не распространяется (видно и в caddy adapt, и живым запросом).
MAX_ADMIN_BODY_BYTES = 64 * 1024
# Сколько раскрытий показываем в предпросмотре: достаточно, чтобы увидеть разброс.
PREVIEW_SAMPLES = 5
MAX_PREVIEW_SAMPLES = 20
# Строка в лог на каждый отказ авторизации — заливка логов с улицы: /ig/admin/* доступен
# из интернета через тот же handle /ig/*, что и вебхук. Считаем, пишем сводкой.
# None, а не 0.0: monotonic идёт от загрузки ХОСТА, и «0 + период» на свежем хосте ещё
# не наступил — ноль съел бы первую сводку целиком.
REJECT_LOG_PERIOD_SEC = 60
_rejected_total = 0
_rejected_logged_at: float | None = None

TRIGGERS = ("COMMENT", "DM", "BOTH")
MATCH_MODES = ("CONTAINS", "EXACT")
LEAD_MODES = ("REPLY", "DM_SENT", "NEVER")
MAX_KEYWORDS = 50
MAX_NAME_LEN = 200
MAX_REPLY_VARIANTS = 50

# Пометка копии в названии и она же — то, что срезается перед новой пометкой. Иначе
# копия копии копии называлась бы «X (копия) (копия) (копия)», а номер поколения читался
# бы подсчётом скобок. Срезается ХВОСТ ЦЕЛИКОМ, а не одна пометка: название со стопкой
# скобок могли набрать и руками, и тогда снятие одной вернуло бы имя, совпадающее
# с исходным, — то самое, от чего пометка и заведена.
COPY_MARK = "копия"
COPY_TAIL = re.compile(rf"(?:\s*\({COPY_MARK}(?:\s+\d+)?\))+\s*$")

_REQUIRED = object()
# Ссылка на фоновый зонд токена (см. replace_token): asyncio держит слабую ссылку на
# задачу, и без сильной её может собрать сборщик мусора прямо посреди запроса в Meta.
_probe_task: asyncio.Task | None = None
# int4 в Postgres: значение вне диапазона — это SQLSTATE 22003 и 500 наружу, если не
# поймать его здесь человеческим текстом.
INT4_MIN, INT4_MAX = -2147483648, 2147483647
# Место ещё не вставленной строки в порядке выбора: id ей выдаст bigserial, и он будет
# больше всех существующих. Потолок bigint, а не «бесконечность», — сравнение идёт
# с настоящими id из таблицы.
INT8_LAST = 9223372036854775807

# Поля правила: имя → (тип, значение по умолчанию при создании).
# Порядок тот же, что в db.ADMIN_RULE_FIELDS; лишние поля в теле — отказ, а не тишина:
# опечатка в имени поля иначе молча сохранит правило не тем, каким его задумали.
FIELDS = {
    "name": ("str", _REQUIRED),
    # Новое правило заводится ВЫКЛЮЧЕННЫМ, хотя в таблице DEFAULT true: включение — это
    # отдельное осознанное действие, а не побочный эффект сохранения черновика.
    "enabled": ("bool", False),
    "trigger": ("enum", "COMMENT"),
    "media_id": ("opt_str", None),
    "keywords": ("list", _REQUIRED),
    "match_mode": ("enum", "CONTAINS"),
    "priority": ("int", 0),
    "public_replies": ("list", []),
    "duplicate_replies": ("list", []),
    "dm_text": ("str", _REQUIRED),
    "dm_buttons": ("buttons", []),
    "create_lead_on": ("enum", "REPLY"),
}
ENUMS = {"trigger": TRIGGERS, "match_mode": MATCH_MODES, "create_lead_on": LEAD_MODES}


def require_admin(request: Request) -> None:
    """Ворота админ-API. Пустой IG_ADMIN_TOKEN не открывает роуты, а закрывает их целиком.

    Fail-closed по образцу signature.verify_signature: ненастроенный секрет — это «никого
    не пускать», а не «пускать всех». Сравнение по байтам постоянным временем; какой
    именно заголовок не подошёл, наружу не сообщаем.
    """
    if IG_ADMIN_TOKEN:
        given = request.headers.get(TOKEN_HEADER)
        if given and constant_time_eq(given, IG_ADMIN_TOKEN):
            return
    _note_rejected(request.url.path)
    raise HTTPException(status_code=403, detail="forbidden")


def _note_rejected(path: str) -> None:
    global _rejected_total, _rejected_logged_at
    _rejected_total += 1
    now = time.monotonic()
    if _rejected_logged_at is None or now - _rejected_logged_at >= REJECT_LOG_PERIOD_SEC:
        _rejected_logged_at = now
        log.warning("админка: отказ по токену (%s); всего с рестарта: %s", path, _rejected_total)


# Зависимость на уровне роутера, а не в каждом обработчике: забыть её в одном новом
# эндпоинте — значит открыть админку в интернет, и такую ошибку не видно в дифе.
router = APIRouter(prefix="/ig/admin", dependencies=[Depends(require_admin)])


# ---------- Правила ----------


@router.get("/rules")
async def list_rules():
    rows = await db.admin_list_rules()
    return {"rules": [_view(row) for row in rows]}


# Отдельного GET /rules/{id} нет намеренно: список отдаёт правила целиком, и форме
# нечего дочитывать. Лишний роут — это лишняя поверхность, которую кто-то будет ревьюить.


@router.post("/rules")
async def create_rule(request: Request):
    body = await _body(request)
    if isinstance(body, JSONResponse):
        return body
    # Соседей читаем, только если правило заводят сразу включённым: черновик никого
    # перекрыть не может, а лишний запрос на каждое сохранение — плата ни за что.
    values, errors, warnings = _prepare(body, current=None, siblings=await _siblings(body, None))
    if errors:
        return _rejected(errors)
    try:
        row = await db.admin_insert_rule(values)
    except db.RuleRejected as exc:
        return _rejected([str(exc)])
    log.info("правило %s заведено: «%s», enabled=%s", row["id"], row["name"], row["enabled"])
    return {"rule": _view(row), "warnings": warnings}


# 201, а не 200 как у POST /rules: это контракт с формой, и он же честнее — в отличие
# от создания, копия рождается без единого поля от клиента, и ссылаться дальше форме
# не на что, кроме id из тела. Разнобой намеренный, выравнивать его не надо.
@router.post("/rules/{rule_id}/copy", status_code=201)
async def copy_rule(rule_id: int):
    """Копия правила под соседний лид-магнит: тексты, кнопки и настройки совпадают,
    заводить их заново по одному полю — работа ни о чём.

    Три отличия копии от исходника, и каждое осознанное:
      • ВЫКЛЮЧЕНА всегда, даже если исходное правило включено. Не потому, что «непонятно,
        какое сработает» — как раз понятно: порядок в rules.match_rule детерминирован
        (привязка к посту → priority DESC → id ASC), поэтому включённая копия с теми же
        словами в той же области не срабатывает НИКОГДА — комментарий забирает исходное
        правило, оно младше по id. Такая копия выглядит работающей и молчит, а это хуже
        отказа. Копия рождается заготовкой; попытка включить её как есть даёт
        предупреждение (_shadowed_by), но не отказ — слово или пост человек меняет сам;
      • НАЗВАНИЕ с пометкой (см. _copy_name) — иначе в списке два одинаковых правила,
        и включают не то;
      • РЕЗЕРВАЦИИ не переносятся: «этому человеку уже выдавали» висит на паре
        человек+правило (ig_contact_rule), у копии пара своя и список пуст. Значит, по
        копии те же люди получат материал ещё раз — это цена того, что копия является
        отдельным правилом; повторная выдача по ОДНОМУ правилу по-прежнему невозможна.

    Само копирование делает база (db.admin_copy_rule) — там же, почему не в питоне.
    Проверки те же и теми же функциями, что при создании руками, но их находки здесь не
    отказ, а ПРЕДУПРЕЖДЕНИЯ — см. ниже по коду.
    """
    current = await db.admin_get_rule(rule_id)
    if current is None:
        return _not_found(rule_id)
    # Из снимка берётся ТОЛЬКО название: его надо придумать до вставки, и оно всё равно
    # своё. Содержимое копии из снимка не берётся вовсе — строку читает сам INSERT.
    taken = await db.admin_rule_names()
    try:
        row = await db.admin_copy_rule(rule_id, _copy_name(current["name"], taken))
    except db.RuleRejected as exc:
        return _rejected([str(exc)])
    if row is None:
        # Правило удалили между чтением и вставкой. Копировать стало нечего.
        return _not_found(rule_id)

    # Разбираем СОЗДАННУЮ строку, а не снимок. Между двумя чтениями исходник мог
    # измениться — руками по рецепту из 003_seed_rule.sql («UPDATE … WHERE name = …»)
    # или вторым админом, — и тогда список «что починить» описывал бы содержимое,
    # которого в копии нет. Блокировок для этого не нужно: то, что легло в таблицу,
    # уже лежит и никуда не денется.
    #
    # Находки проверок здесь не отказ, а список того, что в копии починить. Причина не в
    # снисходительности: строка УЖЕ лежит в таблице, копия ничего нового в базу не
    # приносит и, будучи выключенной, диспетчером не читается вовсе (load_rules берёт
    # только enabled). А 400 запирал бы человека ровно там, где копия нужнее всего:
    # засеянное правило 003_seed_rule.sql валидацию СОЗДАНИЯ не проходит — плейсхолдер
    # ссылки «https://ЗАМЕНИ-НА-…» кириллический, и это ошибка, а не предупреждение.
    # Включить копию, не починив, по-прежнему нельзя: PATCH прогоняет то же самое,
    # и там это снова ошибки.
    values, problems, _ = _prepare({}, current=row)
    warnings = list(problems)
    # Предупреждение _prepare берём не у него: найдя ошибки, до unconfigured он не
    # доходит — а для копии это главная новость (незаполненный плейсхолдер), и терять
    # её из-за соседней жалобы нельзя.
    reason = rules.unconfigured(_probe(values))
    if reason:
        warnings.append(f"копию нельзя будет включить — {reason}")
    log.info("правило %s скопировано в %s: «%s»", rule_id, row["id"], row["name"])
    return {"rule": _view(row), "warnings": warnings}


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: int, request: Request):
    body = await _body(request)
    if isinstance(body, JSONResponse):
        return body
    current = await db.admin_get_rule(rule_id)
    if current is None:
        return _not_found(rule_id)
    values, errors, warnings = _prepare(
        body, current=current, siblings=await _siblings(body, current), rule_id=rule_id
    )
    if errors:
        return _rejected(errors)
    try:
        row = await db.admin_update_rule(rule_id, values)
    except db.RuleRejected as exc:
        return _rejected([str(exc)])
    if row is None:
        return _not_found(rule_id)
    log.info("правило %s изменено: «%s», enabled=%s", row["id"], row["name"], row["enabled"])
    return {"rule": _view(row), "warnings": warnings}


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int):
    """Удаление уносит с собой резервации (ON DELETE CASCADE): люди, которым материал по
    этому правилу уже выдавали, снова становятся «не обслуженными». Сколько их было —
    считаем ДО удаления и возвращаем: восстановить эти строки нечем."""
    released = await db.admin_count_contacts(rule_id)
    if not await db.admin_delete_rule(rule_id):
        return _not_found(rule_id)
    log.info("правило %s удалено, снято резерваций: %s", rule_id, released)
    return {"ok": True, "released_contacts": released}


# ---------- Предпросмотр ----------


@router.post("/preview")
async def preview(request: Request):
    """Раскрытие шаблона и длина худшего раскрытия — тем же движком, что уходит в Meta.

    Длина считается по longest(), а не по случайному раскрытию: правило со случайной
    длиной под лимитом однажды выпадет отказом Meta на неудачном сочетании вариантов,
    и поймать такой плавающий отказ почти невозможно.

    Один запрос — один шаблон: у формы полей несколько (текст DM, публичные ответы,
    заголовки кнопок), и разбирает она их по одному этим же эндпоинтом.
    """
    body = await _body(request)
    if isinstance(body, JSONResponse):
        return body
    text = body.get("text")
    if not isinstance(text, str):
        return _rejected(["поле «text» обязательно и должно быть строкой"])
    count = body.get("samples", PREVIEW_SAMPLES)
    if not isinstance(count, int) or isinstance(count, bool):
        count = PREVIEW_SAMPLES
    count = max(1, min(count, MAX_PREVIEW_SAMPLES))

    broken = rules.check_template(text)
    errors = _text_errors("шаблон", text)
    worst = rules.longest(text)
    return {
        "ok": not errors,
        "errors": errors,
        # Результат check_template отдаём отдельным полем, как просит контракт: форме
        # полезно отличать сломанный синтаксис от «длинновато».
        "check_template": broken,
        "samples": [rules.expand(text) for _ in range(count)],
        "longest": {"text": worst, "bytes": len(worst.encode("utf-8"))},
        "limit_bytes": rules.MAX_MESSAGE_BYTES,
    }


# ---------- Токен и состояние ----------


@router.post("/token")
async def replace_token(request: Request):
    """Замена Instagram User Access Token без правки .env и без рестарта контейнера.

    Значение не возвращается и не логируется никогда — ни в ответе, ни в тексте ошибки
    (фильтр logsafe затирает только то, что дошло до логгера; сюда оно не доходит вовсе).
    """
    body = await _body(request)
    if isinstance(body, JSONResponse):
        return body
    value = body.get("token")
    if not isinstance(value, str) or not value.strip():
        return _rejected(["поле «token» обязательно и должно быть непустой строкой"])
    value = value.strip()
    # Проверяем только форму: длину и отсутствие пробелов. Что токен рабочий, покажет
    # первая же доставка, а держать здесь запрос в Meta нельзя — тогда починка аварии
    # упирается в доступность самой Meta, ради обхода которой всё и затевалось.
    if len(value) < 20 or not value.isascii() or any(ch.isspace() for ch in value):
        return _rejected(["это не похоже на токен: ожидается одна строка латиницей без пробелов"])
    expires_at = await tokens.store(value)
    # Проверка ПОСЛЕ ответа, а не до: ответ владельцу не ждёт Meta (иначе починка аварии
    # зависела бы от доступности той самой платформы), но молча принятый мёртвый токен
    # перестаёт быть возможным — строка в ig_token одна, истории нет, второго шанса тоже.
    # Ссылку на задачу держим: без неё сборщик мусора вправе убить её на полпути.
    global _probe_task
    _probe_task = asyncio.create_task(tokens.probe(value))
    return {
        "ok": True,
        "expires_at": expires_at.isoformat(),
        # Честно: Meta называет срок жизни только в ответе на продление, а продлить токен
        # моложе суток она не даёт. Выдуманные «60 суток» отсекли бы продление на их длину.
        "expires_at_confirmed": False,
        "note": "срок уточнится при первом продлении — Meta не называет его при выдаче",
    }


@router.get("/state")
async def state():
    """Состояние сервиса одним ответом. Секретов в нём нет по составу полей.

    Это же и точка опоры для doctor.sh: он читает отсюда то, что снаружи не наблюдается —
    в первую очередь канал алертов. «Функция не упала» и «сообщение дошло» — разные
    утверждения, поэтому наружу отдаётся ВРЕМЯ последней успешной доставки алерта, а не
    флаг успеха.
    """
    token = await tokens.state()
    pending = await db.count_pending()
    sent_24h = await db.count_dm_sent_since(24)
    last_tick = dispatcher.last_tick_at
    stale = (datetime.now(timezone.utc) - last_tick).total_seconds() if last_tick else None
    limit_reached = IG_DAILY_DM_LIMIT > 0 and sent_24h >= IG_DAILY_DM_LIMIT
    return {
        # ok = «сервис способен отвечать людям прямо сейчас». Замерший круг диспетчера
        # сюда не входит намеренно: за него отвечает stale_sec ниже и /ig/health.
        "ok": token.usable and not limit_reached,
        "token": {
            "present": bool(token.value),
            "invalid_at": _moment(token.invalid_at),
            "expires_at": _moment(token.expires_at),
        },
        "queue": {"pending": pending},
        "dispatcher": {
            "last_tick_at": _moment(last_tick),
            "stale_sec": int(stale) if stale is not None else None,
            "stopping": dispatcher.stopping.is_set(),
        },
        "daily": {"limit": IG_DAILY_DM_LIMIT, "sent_24h": sent_24h, "reached": limit_reached},
        # last_ok_at = null при configured = true означает «канал ни разу не проверен»,
        # а не «аварий не было»: это отдельный вердикт, и закрывает его тестовое
        # сообщение (meta.send_test_alert), которое подтверждает ЧЕЛОВЕК.
        "alerts": meta.channel_state(),
    }


# ---------- Разбор тела и ответы ----------


async def _body(request: Request):
    """Тело запроса как словарь. JSONResponse на выходе — это отказ, отдать его как есть."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_ADMIN_BODY_BYTES:
        return JSONResponse({"error": "тело запроса слишком большое"}, status_code=413)
    raw = await _read_capped(request)
    if raw is None:
        return JSONResponse({"error": "тело запроса слишком большое"}, status_code=413)
    try:
        body = json.loads(raw)
    except ValueError:
        return JSONResponse({"error": "тело запроса не разобралось как JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "ожидается объект JSON"}, status_code=400)
    return body


async def _read_capped(request: Request) -> bytes | None:
    """Тело с обрывом на лимите. None — больше MAX_ADMIN_BODY_BYTES.

    Не request.json()/request.body(): обе склеивают поток в память целиком, а заголовка
    content-length при Transfer-Encoding: chunked нет вовсе — проверка заявленного размера
    в этом случае просто не выполняется. Та же конструкция, что main.read_body; в общий
    модуль намеренно не вынесена: admin.py должен удаляться одной строкой, не задевая
    приёмник вебхуков.
    """
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_ADMIN_BODY_BYTES:
                return None
            chunks.append(chunk)
    except ClientDisconnect:
        return b""
    return b"".join(chunks)


def _rejected(errors: list[str]) -> JSONResponse:
    """Отказ с перечнем причин человеческим текстом: «ошибка валидации» не говорит ничего.

    error — первая причина (её показывают в тосте), errors — все (их показывают у полей).
    """
    return JSONResponse({"error": errors[0], "errors": errors}, status_code=400)


def _not_found(rule_id: int) -> JSONResponse:
    return JSONResponse({"error": f"правила {rule_id} нет"}, status_code=404)


def _view(row: dict) -> dict:
    """Строка таблицы → JSON формы. Массивы Postgres приходят списками, jsonb — списком."""
    return {
        "id": row["id"],
        "name": row["name"],
        "enabled": row["enabled"],
        "trigger": row["trigger"],
        "media_id": row["media_id"],
        "keywords": list(row["keywords"] or []),
        "match_mode": row["match_mode"],
        "priority": row["priority"],
        "public_replies": list(row["public_replies"] or []),
        "duplicate_replies": list(row["duplicate_replies"] or []),
        "dm_text": row["dm_text"],
        "dm_buttons": list(row["dm_buttons"] or []),
        "create_lead_on": row["create_lead_on"],
        "created_at": _moment(row["created_at"]),
        "updated_at": _moment(row["updated_at"]),
    }


def _moment(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _copy_name(source: str, taken: list[str]) -> str:
    """«X» → «X (копия)», «X (копия)» → «X (копия 2)». Номер — первый свободный.

    Свободный именно среди ЗАВЕДЁННЫХ названий, а не следующий по счёту от исходного:
    копировать одно базовое правило под три лид-магнита — обычное дело, а три строки
    «X (копия)» в списке различить нечем. Уникальности названий схема не требует, и
    гонку двух одновременных копий это не закрывает — только избавляет от совпадений
    в тот единственный момент, когда человек смотрит на список.
    """
    base = COPY_TAIL.sub("", source).strip()
    # Исходное название — тоже занятое, даже если вызвавший забыл его передать: копия,
    # названная в точности как оригинал, — это ровно тот случай, который пометка чинит.
    known = set(taken) | {source}
    number = 1
    while True:
        mark = f"({COPY_MARK})" if number == 1 else f"({COPY_MARK} {number})"
        # Потолок названия тот же, что при создании руками (MAX_NAME_LEN). Режем ОСНОВУ,
        # а не пометку: пометка и есть то, ради чего название меняли.
        head = base[: MAX_NAME_LEN - len(mark) - 1].rstrip()
        candidate = f"{head} {mark}" if head else mark
        if candidate not in known:
            return candidate
        number += 1


# ---------- Валидация ----------


async def _siblings(body: dict, current: dict | None) -> list[dict] | None:
    """Остальные правила — для проверки перекрытия слов. None, когда проверять нечего.

    Чтение стоит одного запроса, поэтому идёт только на включённом правиле: сохранение
    черновика (а это большинство сохранений) остаётся ровно таким же, каким было.
    Заодно None здесь — это и есть выключатель проверки для copy_rule: копия рождается
    выключенной, соседей ей читать незачем.
    """
    enabled = body.get("enabled", current["enabled"] if current else False)
    return await db.admin_list_rules() if enabled is True else None


def _prepare(
    body: dict,
    current: dict | None,
    siblings: list[dict] | None = None,
    rule_id: int | None = None,
) -> tuple[dict, list[str], list[str]]:
    """Тело запроса + текущее правило → (значения для записи, ошибки, предупреждения).

    Ошибка — отказ сохранять. Предупреждение — правило сохранится, но работать не будет:
    так сохраняется черновик с незаполненным плейсхолдером (ровно так заведено правило
    из 003_seed_rule.sql). Включить такое правило нельзя — это уже ошибка.

    siblings — остальные правила таблицы; нужны ровно для проверки перекрытия слов
    (_shadowed_by) и потому читаются вызывающим только тогда, когда правило включают.
    rule_id — id правила, которое сейчас правят (None при создании): порядок выбора
    зависит от id, а у ещё не вставленной строки его нет.
    """
    errors: list[str] = []
    unknown = sorted(set(body) - set(FIELDS))
    if unknown:
        errors.append("незнакомые поля: " + ", ".join(unknown))

    values: dict = {}
    for name, (kind, default) in FIELDS.items():
        if name not in body:
            if current is not None:
                # PATCH: поле не прислали — берём как есть из строки таблицы. Массивы
                # Postgres и jsonb psycopg отдаёт уже списками, преобразовывать нечего.
                values[name] = current[name]
            elif default is _REQUIRED:
                errors.append(f"поле «{name}» обязательно")
                values[name] = None
            else:
                values[name] = list(default) if isinstance(default, list) else default
            continue
        value, problem = _coerce(name, kind, body[name])
        if problem:
            errors.append(problem)
        values[name] = value

    if errors:
        return values, errors, []

    errors += _rule_errors(values)
    if errors:
        return values, errors, []

    # Последний рубеж — та же проверка, что стоит у диспетчера перед обращением к Meta.
    # Админ-путь её не обходит: включённое правило, которое unconfigured не пропустит,
    # не сохраняется вовсе, иначе человек получил бы публичное «отправила в директ»
    # и пустоту в директе.
    reason = rules.unconfigured(_probe(values))
    warnings: list[str] = []
    if reason:
        if values["enabled"]:
            errors.append(f"правило нельзя включить — {reason}")
        else:
            warnings.append(f"правило сохранено выключенным: {reason}")

    # Правило включают, а слова у него целиком забирает другое включённое — предупреждаем,
    # но не отказываем: перекрытие бывает и осознанным (правило про запас, замена
    # старому), а запрет заставил бы человека выключать соседа ради сохранения.
    # Отказывать нельзя ещё и потому, что это единственная проверка, которая смотрит
    # на СОСЕДЕЙ, а не на само правило: соседи меняются без нас.
    if values["enabled"] and siblings:
        eclipsed = _shadowed_by(values, rule_id, siblings)
        if eclipsed:
            warnings.append(
                f"правило включено, но сработать не сможет: все его слова забирает"
                f" правило «{eclipsed['name']}» (id {eclipsed['id']}) — оно идёт раньше"
                " по тому же порядку, что у диспетчера (привязка к посту → приоритет →"
                " id). Поменяйте слово, поднимите приоритет или привяжите это правило"
                " к своему посту"
            )
    return values, errors, warnings


def _shadowed_by(values: dict, rule_id: int | None, siblings: list[dict]) -> dict | None:
    """Включённое правило, которое заберёт себе ВСЕ срабатывания этого. None — нет такого.

    Ровно тот порядок, по которому выбирает диспетчер (rules.match_rule): привязанные
    к посту → priority DESC → id ASC. Условия намеренно строгие — предупреждение должно
    быть правдой, а не подозрением:
      • одна и та же область (media_id совпадает). Более узкий сосед (он с постом, мы без)
        отбирает срабатывания только на своём посту, на остальных мы работаем;
      • сосед ловит все наши поводы (trigger): COMMENT+DM у нас против только COMMENT
        у него — не перекрытие;
      • сосед идёт раньше нас в этом порядке. У новой строки id ещё нет, и она заведомо
        последняя — поэтому None здесь означает «самый большой id», а не «нулевой»;
      • КАЖДОЕ наше слово ловится соседом. Подстрочность CONTAINS учтена: сосед со словом
        «гайд» перекрывает наше «гайды», но не наоборот. EXACT перекрывает только
        такое же EXACT-слово: наш CONTAINS ловит и «хочу гайд», а его EXACT — нет.
    """
    words = [w for w in (rules.normalize(k) for k in values["keywords"]) if w]
    if not words:
        return None
    mine = (-values["priority"], rule_id if rule_id is not None else INT8_LAST)
    for other in siblings:
        if not other["enabled"] or other["id"] == rule_id:
            continue
        if other["media_id"] != values["media_id"]:
            continue
        if not _triggers(values["trigger"]) <= _triggers(other["trigger"]):
            continue
        if (-other["priority"], other["id"]) >= mine:
            continue
        theirs = [w for w in (rules.normalize(k) for k in other["keywords"]) if w]
        if all(_caught(word, values["match_mode"], theirs, other["match_mode"])
               for word in words):
            return other
    return None


def _triggers(value: str) -> set[str]:
    return {"COMMENT", "DM"} if value == "BOTH" else {value}


def _caught(word: str, mode: str, theirs: list[str], their_mode: str) -> bool:
    """Ловит ли сосед всё, что ловит наше слово. Тексты сравниваются нормализованными."""
    if their_mode == "CONTAINS":
        # Любой текст с нашим словом содержит и их подстроку — значит, ловит.
        return any(w in word for w in theirs)
    # Сосед EXACT: он срабатывает только на текст, равный слову целиком. Перекрыть нас
    # он может, лишь если и мы EXACT ровно с тем же словом.
    return mode == "EXACT" and word in theirs


def _coerce(name: str, kind: str, raw):
    """Значение поля из тела запроса. Возвращает (значение, текст ошибки или None)."""
    if kind == "str":
        if not isinstance(raw, str) or not raw.strip():
            return raw, f"поле «{name}»: ожидается непустая строка"
        text = raw.strip() if name == "name" else raw
        if name == "name" and len(text) > MAX_NAME_LEN:
            return text, f"название длиннее {MAX_NAME_LEN} символов"
        return text, None
    if kind == "opt_str":
        if raw is None:
            return None, None
        if not isinstance(raw, str):
            return raw, f"поле «{name}»: ожидается строка или null"
        return raw.strip() or None, None
    if kind == "bool":
        if not isinstance(raw, bool):
            return raw, f"поле «{name}»: ожидается true или false"
        return raw, None
    if kind == "int":
        if not isinstance(raw, int) or isinstance(raw, bool):
            return raw, f"поле «{name}»: ожидается целое число"
        if not INT4_MIN <= raw <= INT4_MAX:
            return raw, f"поле «{name}»: число должно быть от {INT4_MIN} до {INT4_MAX}"
        return raw, None
    if kind == "enum":
        allowed = ENUMS[name]
        if raw not in allowed:
            return raw, f"поле «{name}»: допустимо только {', '.join(allowed)}"
        return raw, None
    if kind == "list":
        if not isinstance(raw, list) or any(not isinstance(v, str) for v in raw):
            return raw, f"поле «{name}»: ожидается список строк"
        return [v.strip() for v in raw if v.strip()], None
    if kind == "buttons":
        if not isinstance(raw, list):
            return raw, "поле «dm_buttons»: ожидается список кнопок"
        return raw, None
    return raw, f"поле «{name}»: неизвестный тип"


def _rule_errors(values: dict) -> list[str]:
    """Смысловые проверки правила: слова, шаблоны, кнопки. Тексты — для человека."""
    errors: list[str] = []

    # Нулевой байт Postgres не примет ни в text, ни в jsonb, и psycopg отвергает его ещё
    # на адаптации — без этой проверки кривая вставка из чужого редактора даёт 500.
    if _has_nul(values):
        errors.append("в тексте есть нулевой байт — уберите его (обычно приезжает копипастой)")

    words = values["keywords"]
    if not words:
        errors.append("список ключевых слов пуст — правилу не по чему срабатывать")
    if len(words) > MAX_KEYWORDS:
        errors.append(f"ключевых слов {len(words)} при пределе {MAX_KEYWORDS}")
    dead = [w for w in words if not rules.normalize(w)]
    if dead:
        # normalize выбрасывает всё, кроме букв и цифр: слово из одних эмодзи или знаков
        # после нормализации пусто и не совпадёт ни с чем никогда.
        errors.append("после нормализации пусты и не сработают: " + ", ".join(dead))

    errors += _text_errors("текст DM", values["dm_text"])
    if not values["dm_text"].strip():
        errors.append("текст DM пустой — Meta не примет пустое сообщение")
    for label, key in (
        ("публичный ответ", "public_replies"),
        ("ответ на повтор", "duplicate_replies"),
    ):
        variants = values[key]
        if len(variants) > MAX_REPLY_VARIANTS:
            errors.append(f"{label}: вариантов {len(variants)} при пределе {MAX_REPLY_VARIANTS}")
        for n, variant in enumerate(variants, 1):
            errors += _text_errors(f"{label} {n}", variant)

    errors += _button_errors(values["dm_buttons"])
    return errors


def _has_nul(value) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_has_nul(v) for v in value.values()) or any(_has_nul(k) for k in value)
    if isinstance(value, list):
        return any(_has_nul(v) for v in value)
    return False


def _text_errors(label: str, text: str, limit: int | None = rules.MAX_MESSAGE_BYTES) -> list[str]:
    """Шаблон глазами того же движка, что и при отправке: скобки, пустые блоки, длина."""
    broken = rules.check_template(text)
    if broken:
        # Дальше разбирать несбалансированный шаблон бессмысленно: парсер трактует
        # незакрытую скобку как обычный символ, и вторая ошибка только запутает.
        return [f"{label}: {broken}"]
    errors = []
    empty = rules.check_groups(text)
    if empty:
        errors.append(f"{label}: {empty}")
    if limit is not None:
        worst = len(rules.longest(text).encode("utf-8"))
        if worst > limit:
            errors.append(
                f"{label}: самое длинное раскрытие — {worst} байт при лимите {limit}."
                " Считается по худшему сочетанию вариантов, а не по случайному"
            )
    return errors


def _button_errors(buttons: list) -> list[str]:
    errors: list[str] = []
    if len(buttons) > MAX_BUTTONS:
        errors.append(f"кнопок {len(buttons)} при пределе платформы {MAX_BUTTONS}")
    for n, button in enumerate(buttons, 1):
        if not isinstance(button, dict):
            errors.append(f"кнопка {n}: ожидается объект с полями title и url")
            continue
        title = str(button.get("title") or "").strip()
        url = str(button.get("url") or "").strip()
        if not title:
            errors.append(f"кнопка {n}: пустой заголовок")
        else:
            errors += _text_errors(f"кнопка {n}, заголовок", title, limit=None)
            worst = len(rules.longest(title))
            if worst > MAX_BUTTON_TITLE:
                errors.append(
                    f"кнопка {n}: заголовок в {worst} символов при пределе {MAX_BUTTON_TITLE} —"
                    " Meta обрежет его посреди слова"
                )
        if not url.startswith("https://") or not url.isascii():
            errors.append(f"кнопка {n}: ссылка должна начинаться с https:// и быть латиницей")
    return errors


def _probe(values: dict) -> rules.Rule:
    """Правило в том виде, в каком его увидит диспетчер. id ещё нет — он не участвует."""
    return rules.Rule(
        id=0,
        name=values["name"],
        trigger=values["trigger"],
        media_id=values["media_id"],
        keywords=values["keywords"],
        match_mode=values["match_mode"],
        priority=values["priority"],
        public_replies=values["public_replies"],
        duplicate_replies=values["duplicate_replies"],
        dm_text=values["dm_text"],
        dm_buttons=values["dm_buttons"],
    )
