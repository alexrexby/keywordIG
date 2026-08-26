"""Панель установки: серверный HTML для человека, который этот код видит впервые.

Панель — ЛИЦО машинного API, а не второй его экземпляр. Правила она сохраняет тем же
admin.save_rule, копирует тем же admin.duplicate_rule, токен принимает тем же
admin.accept_token, состояние берёт тем же admin.state(), тексты раскрывает тем же
rules.expand. Второго движка проверок и второго набора текстов отказа в проекте нет:
разъехавшись, они однажды покажут в форме не то, что получит подписчик.

Главная страница — не дамп полей, а ВЕРДИКТ: что не работает для дела и что нажать.
Поддержки у установки нет; в момент аварии у человека есть ровно три вещи — сообщение
в мессенджере, эта страница и doctor.sh. Порядок вердиктов и их тексты живут в
docs/copy.md, там же объяснено, почему первый подходящий вытесняет остальные.

Ворота свои и другие, чем у admin.py: там ключ в заголовке для машины, здесь форма,
пароль и подписанная cookie для человека. /ig/admin/* закрыт снаружи на прокси, /panel/*
открыт намеренно — установку чинят с телефона, и лишний рубеж здесь означал бы, что
чинить её нельзя вовсе.

ПАРОЛЬ В ОКРУЖЕНИИ НЕ ХРАНИТСЯ, только его хеш (IG_ADMIN_PASSWORD_HASH). Посчитать:

    docker compose run --rm --no-deps instagram-service python panel.py

Пароль читается со STDIN, а не из аргументов: argv виден в `ps aux` любому пользователю
хоста — тот же довод, что у IG_PW в docker-compose.

Удаляется вместе с templates/ и двумя строками include_router в main.py: приём вебхуков
и доставка от панели не зависят.
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import math
import random
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

import admin
import db
import dispatcher
import meta
import rules
from config import (
    DELIVERY_RETENTION_DAYS,
    EVENT_RETENTION_DAYS,
    HEALTH_STALE_SEC,
    IG_ADMIN_PASSWORD_HASH,
    IG_ADMIN_SECRET,
)
from meta import MAX_BUTTONS, MAX_BUTTON_TITLE
from signature import constant_time_eq

log = logging.getLogger("panel")

# Jinja берётся ради ОДНОГО: автоэкранирования. Тексты правил пишет человек, рисуются они
# в HTML, и «<» в ответе под комментарием не должен превращаться в разметку.
# StrictUndefined — чтобы опечатка в имени переменной падала ошибкой, а не тихой пустотой
# на странице, которую человек читает в момент аварии.
TEMPLATES = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
    autoescape=select_autoescape(("html",)),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)

COOKIE_NAME = "ig_panel"
LOGIN_PATH = "/panel/login"
HOME_PATH = "/panel/"
# Полсуток: панель однопользовательская, а слишком короткая сессия означает ввод пароля
# посреди починки аварии — с телефона, в спешке, с опечатками.
SESSION_TTL_SEC = 12 * 60 * 60
# Подпись сессии — это ВТОРОЙ пароль, а не служебный ключ: cookie самодостаточна, и
# подобравший ключ входит, не притронувшись к паролю. Замок, scrypt и «пять попыток»
# стоят на другой двери. token_urlsafe(32) даёт 43 символа — образец окружения советует
# ровно это, а короткое значение закрывает панель так же, как пустое.
MIN_SECRET_LEN = 32
# Онлайн-перебор пароля: /panel/login доступен из интернета по устройству (иначе установку
# нельзя починить с телефона).
#
# ПАРОЛЬ СВЕРЯЕТСЯ ДО ЗАМКА, и это не послабление. Замок «до» отвергал верный пароль:
# пять запросов раз в пять минут из одной консоли — и владелец не входит НИКОГДА, а
# панель у него единственный способ заменить умерший токен без ssh. Того же добивается
# без умысла первый попавшийся сканер админок. Защита, которая защищает от хозяина,
# в этом пакете дороже перебора.
#
# Перебор ограничен иначе: счёт неудач ПО АДРЕСУ (Caddy подставляет свой X-Forwarded-For
# и входящему не верит — проверено ревью на боевом Caddyfile) плюс дешёвый глобальный
# интервал между проверками, чтобы поток попыток не занимал event loop счётом scrypt.
LOGIN_FAILS_BEFORE_LOCK = 5
LOGIN_LOCK_SEC = 300
# Минимальный промежуток между двумя проверками пароля во всём процессе. Дешёвый рубеж
# ПЕРЕД scrypt: сам счёт стоит 60 мс, и без него поток попыток тормозил бы приём вебхуков.
LOGIN_MIN_INTERVAL_SEC = 0.25
# Сколько адресов помним. Словарь без потолка — это память, которую наполняет улица.
LOGIN_ADDRESSES = 100
# Форма правила — единицы килобайт: тексты ответов ограничены 4096 байтами каждый.
# Рубеж здесь ЕДИНСТВЕННЫЙ: request_body max_size из Caddyfile живёт внутри handle /ig/*,
# а /panel/* попадает в другой блок — тот же расклад, что у admin.MAX_ADMIN_BODY_BYTES.
MAX_FORM_BYTES = 64 * 1024
# Ноль здесь означал бы «замок только что кончился» на хосте, загрузившемся минуту назад:
# time.monotonic() считается от загрузки ХОСТА. Тот же капкан чинили в диспетчере.
_login_fails: dict[str, int] = {}
_login_locked_at: dict[str, float] = {}
_login_checked_at: float | None = None
# Отказы по подписи сессии: подделку cookie иначе не видно вообще ничем — в отличие от
# пароля, у неё нет ни счётчика, ни замка. Пишем сводкой, как main.note_rejected:
# строка на каждый отказ — это заливка логов с улицы.
_bad_session_total = 0
_bad_session_logged_at: float | None = None
REJECT_LOG_PERIOD_SEC = 60
# Сессии, выданные раньше этого момента, недействительны. Кнопка «Выйти» иначе гасит
# cookie только в ЭТОМ браузере, а подписанный токен живёт своей жизнью ещё 12 часов —
# при том, что панель открывают в том числе с чужого телефона. Переменная процесса:
# после рестарта отзыв теряется, и это честно сказано в отчёте, а не спрятано.
_valid_after: float = 0.0

# Параметры scrypt. n=2**14 при r=8 требует 16 МБ на проверку — это заметно для перебора
# и незаметно для одного входа в сутки; в контейнере с mem_limit 256m помещается.
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LEN = 2**14, 8, 1, 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
# Потолок на разобранный из окружения n: кривое значение иначе выедает память контейнера,
# до которого достаёт интернет.
SCRYPT_MAX_N = 2**20

# Сколько раскрытий показывает предпросмотр. Столько же, сколько отдаёт машинный
# /ig/admin/preview: разное число примеров в двух местах читается как разное поведение.
PREVIEW_SAMPLES = admin.PREVIEW_SAMPLES
# За сколько суток до конца срока говорить про токен вслух. Столько же, за сколько
# сервис начинает продлевать (tokens.REFRESH_BEFORE_DAYS): попав в это окно и оставшись
# в нём, токен сообщает, что продление не проходит.
TOKEN_WARN_DAYS = 10
# Молчание платформы дольше этого срока — повод сказать вслух. Не авария: под постами
# просто может быть тихо, поэтому вердикт предлагает проверку, а не починку.
SILENCE_ALERT_DAYS = 3
# Микрокопия ответов на действие. Коды, а не тексты, ездят в query-строке: подставлять
# в страницу произвольную строку из адреса — это отражённый XSS даже при автоэкранировании
# (человек прочитает в панели то, что ему прислали ссылкой).
NOTES = {
    "saved": "Правило сохранено.",
    "enabled": "Включено. Работает со следующего комментария.",
    "disabled": "Выключено. Отметки о выданных материалах сохранились.",
    "deleted": "Правило удалено.",
    "copied": "Копия готова. Она выключена — включите, когда допишете.",
    "token": (
        "Токен сохранён. Очередь разберётся сама, перезапуск не нужен."
        " Срок жизни уточним при первом продлении: Meta называет его только тогда."
    ),
    "alert-sent": (
        "Отправили. Пришло? Если через минуту тишина — проверьте chat_id"
        " и то, что боту написали первым."
    ),
    "alert-failed": "Не ушло. Причина — в вердикте выше.",
    "released": (
        "Бронь снята. Материал уйдёт этому человеку, когда он обратится снова:"
        " сама по себе снятая бронь отправку не запускает."
    ),
    "no-hold": "Брони на этой доставке уже нет — снимать нечего.",
}


# ---------- Пароль ----------


def hash_password(password: str) -> str:
    """Хеш для IG_ADMIN_PASSWORD_HASH. Формат: scrypt:n:r:p:соль_b64:хеш_b64.

    РАЗДЕЛИТЕЛЬ ДВОЕТОЧИЕ, А НЕ ДОЛЛАР, хотя привычный вид scrypt-хеша именно
    с долларом. Причина не косметическая и найдена живым прогоном: значение проходит
    через docker compose, а тот подставляет `$16384` и `$1` в файле окружения как
    переменные — от строки остаются огрызки, панель закрывается невнятным 503, и связать
    это с долларом внутри хеша не может никто. Тот же класс капкана, что у спецсимволов
    в пароле базы: они рвут строку подключения, и отказ выглядит как «неверный пароль».
    Двоеточие уже служит разделителем в конверте токена (tokens.encrypt) — новой
    договорённости здесь не заводится.
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=SCRYPT_LEN, maxmem=SCRYPT_MAXMEM,
    )
    return ":".join(
        ("scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P),
         base64.b64encode(salt).decode(), base64.b64encode(digest).decode())
    )


def _parsed_hash() -> tuple | None:
    """Разобранный хеш из окружения. None — сверять пароль нечем, значит панель закрыта."""
    parts = IG_ADMIN_PASSWORD_HASH.split(":")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    try:
        n, r, p = (int(part) for part in parts[1:4])
        salt = base64.b64decode(parts[4], validate=True)
        digest = base64.b64decode(parts[5], validate=True)
    except ValueError:
        return None
    if not (1 < n <= SCRYPT_MAX_N and 0 < r <= 32 and 0 < p <= 16 and salt and digest):
        return None
    return n, r, p, salt, digest


def check_password(password: str) -> bool:
    parsed = _parsed_hash()
    if parsed is None:
        return False
    n, r, p, salt, digest = parsed
    try:
        candidate = hashlib.scrypt(
            password.encode(), salt=salt, n=n, r=r, p=p,
            dklen=len(digest), maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, MemoryError):
        # Параметры из окружения не приняты библиотекой: это не «пароль не подошёл»,
        # а «сверять нечем», и знать об этом надо из лога, а не по бесконечным 401.
        log.error("IG_ADMIN_PASSWORD_HASH: параметры scrypt не приняты, вход невозможен")
        return False
    return hmac.compare_digest(candidate, digest)


# ---------- Сессия ----------


def _sign(payload: str) -> str:
    return hmac.new(IG_ADMIN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _issue_session() -> str:
    payload = f"{secrets.token_urlsafe(12)}.{int(time.time())}"
    return f"{payload}.{_sign('session.' + payload)}"


def _read_session(raw: str | None) -> str | None:
    """Идентификатор живой сессии или None. Почему именно не пустили, наружу не сообщаем.

    Сверка через signature.constant_time_eq, а не hmac.compare_digest напрямую: на СТРОКАХ
    тот требует ASCII в обоих аргументах и иначе бросает TypeError. Cookie starlette
    декодирует как latin-1, тело формы — как utf-8, то есть не-ASCII доезжает сюда обоими
    путями и превращал бы каждый такой запрос в 500 с пятью килобайтами трейса — ротацию
    лога установки вымывает парой тысяч запросов с улицы. Ровно это уже чинили в
    signature.py, функция лежит там же.
    """
    parts = (raw or "").split(".")
    if len(parts) != 3:
        if raw:
            _note_bad_session()
        return None
    sid, issued, signature = parts
    if not constant_time_eq(signature, _sign(f"session.{sid}.{issued}")):
        _note_bad_session()
        return None
    if not issued.isdigit() or time.time() - int(issued) > SESSION_TTL_SEC:
        return None
    if int(issued) < _valid_after:
        return None  # сессии, отозванные кнопкой «Выйти»
    return sid


def _note_bad_session() -> None:
    """Счёт подделок cookie. Ни значения, ни адреса: строка в лог на каждый отказ — это
    и есть заливка логов, от которой лог перестаёт быть диагностическим каналом."""
    global _bad_session_total, _bad_session_logged_at
    _bad_session_total += 1
    now = time.monotonic()
    if _bad_session_logged_at is None or now - _bad_session_logged_at >= REJECT_LOG_PERIOD_SEC:
        _bad_session_logged_at = now
        log.warning(
            "панель: отказ по подписи сессии; всего с рестарта: %s", _bad_session_total
        )


def _csrf(sid: str) -> str:
    """Метка формы, привязанная к сессии. Проверяется на КАЖДОМ POST.

    SameSite=Strict на cookie закрывает тот же класс атак, но зависит от браузера;
    метка не зависит ни от чего и стоит одну строку в шаблоне.
    """
    return _sign(f"csrf.{sid}")


def _closed_reason() -> str:
    """Почему панель не открывается вовсе. Пустая строка — открывается.

    Fail-closed по образцу signature.verify_signature и require_admin: ненастроенный
    секрет закрывает вход, а не открывает его всем.
    """
    if not IG_ADMIN_SECRET:
        return (
            "Панель закрыта: не задан IG_ADMIN_SECRET — подписывать сессию нечем."
            " Задайте его в файле окружения и поднимите сервис заново."
        )
    if len(IG_ADMIN_SECRET) < MIN_SECRET_LEN:
        return (
            f"Панель закрыта: IG_ADMIN_SECRET короче {MIN_SECRET_LEN} символов."
            " Этим ключом подписана сессия, и подобрать его — то же самое, что узнать"
            " пароль, только без пароля. Возьмите длинный:"
            " python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            " — и поднимите сервис заново."
        )
    if _parsed_hash() is None:
        return (
            "Панель закрыта: IG_ADMIN_PASSWORD_HASH пуст или не разобрался."
            " Посчитайте хеш пароля заново и поднимите сервис."
        )
    return ""


def require_open() -> None:
    reason = _closed_reason()
    if reason:
        raise HTTPException(status_code=503, detail=reason)


def require_session(request: Request) -> str:
    """Ворота панели. Возвращает идентификатор сессии — из него считается метка формы."""
    require_open()
    sid = _read_session(request.cookies.get(COOKIE_NAME))
    if sid is None:
        # 302, а не 401: на той стороне браузер, и человеку нужна форма входа,
        # а не код ответа.
        raise HTTPException(status_code=302, detail="нужен вход", headers={"Location": LOGIN_PATH})
    return sid


async def read_form(request: Request) -> dict[str, str]:
    """Тело формы разбирается стандартной библиотекой, а не request.form().

    Причина найдена живым прогоном: starlette для ЛЮБОЙ формы, включая обычную
    urlencoded, требует пакет python-multipart — иначе AssertionError и 500 на входе
    в панель. Заводить зависимость ради разбора «a=1&b=2» не за что: parse_qsl делает
    ровно это, а заодно тело здесь получает свой потолок (у admin.py он есть, у панели
    иначе не было бы).

    Загрузки файлов в панели нет и не планируется, поэтому multipart отвергается прямо:
    молча разобрать его в пустую форму — значит показать человеку «поле обязательно»
    там, где он всё заполнил.
    """
    kind = request.headers.get("content-type", "").split(";")[0].strip()
    if kind and kind != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="панель принимает только обычные формы")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_FORM_BYTES:
        raise HTTPException(status_code=413, detail="слишком большая форма")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_FORM_BYTES:
            raise HTTPException(status_code=413, detail="слишком большая форма")
        chunks.append(chunk)
    body = b"".join(chunks).decode("utf-8", "replace")
    return dict(parse_qsl(body, keep_blank_values=True))


async def require_form(request: Request, sid: str = Depends(require_session)) -> dict[str, str]:
    """Тело формы вместе с проверкой метки: получить одно без другого нельзя.

    Отдельной зависимостью, а не строкой в каждом обработчике, ровно по той же причине,
    по которой ворота admin.py висят на роутере: забыть проверку в одном новом POST
    значит открыть его любому сайту, и в диффе это не видно.
    """
    form = await read_form(request)
    given = str(form.get("_csrf") or "")
    # Байтами (см. _read_session): не-ASCII в поле формы иначе даёт 500 вместо честного 403.
    if not constant_time_eq(given, _csrf(sid)):
        raise HTTPException(
            status_code=403,
            detail="Страница устарела или пришла не из панели. Откройте её заново.",
        )
    return form


# Два роутера, а не один с исключением для входа: путь-исключение внутри общей проверки —
# это ровно та конструкция, в которой однажды оказывается открыт лишний адрес.
login_router = APIRouter(prefix="/panel")
router = APIRouter(prefix="/panel", dependencies=[Depends(require_session)])


# ---------- Вход ----------


@login_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    require_open()
    if _read_session(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse(HOME_PATH, status_code=302)
    return _render("login.html", error="")


@login_router.post("/login")
async def login(request: Request):
    require_open()
    global _login_checked_at
    address = _address(request)
    form = await read_form(request)

    # Дешёвый рубеж ПЕРЕД scrypt: сам счёт стоит 60 мс, и поток попыток без него занимал
    # бы event loop, в котором принимаются вебхуки.
    now = time.monotonic()
    if _login_checked_at is not None and now - _login_checked_at < LOGIN_MIN_INTERVAL_SEC:
        return _render("login.html", status=429, error="Слишком часто. Повторите через секунду.")
    _login_checked_at = now

    # scrypt в отдельном потоке: 16 МБ и 60 мс в общем цикле — это пауза в приёме
    # вебхуков ровно тогда, когда кто-то ломится в панель.
    ok = await asyncio.to_thread(check_password, str(form.get("password") or ""))
    if ok:
        # ВЕРНЫЙ ПАРОЛЬ ПРОХОДИТ ВСЕГДА, замок он же и снимает: иначе пять чужих попыток
        # раз в пять минут держат владельца снаружи, а внутри — единственная кнопка
        # замены умершего токена.
        _login_fails.pop(address, None)
        _login_locked_at.pop(address, None)
        response = RedirectResponse(HOME_PATH, status_code=303)
        response.set_cookie(
            COOKIE_NAME,
            _issue_session(),
            max_age=SESSION_TTL_SEC,
            httponly=True,
            # Secure — не перестраховка: callback URL Meta принимает только HTTPS, значит
            # установка без TLS не работает в принципе, и незашифрованного входа здесь нет.
            secure=True,
            samesite="strict",
            path="/panel",
        )
        return response

    left = _lock_left(address)
    if left:
        return _render(
            "login.html",
            status=429,
            error=f"Слишком много попыток. Следующая — через {left} с.",
        )
    _note_login_fail(address)
    # 401, а не 500 и не 200: неверный пароль — это штатный исход, и он обязан
    # выглядеть как штатный исход в любом логе и в любом мониторинге.
    return _render("login.html", status=401, error="Пароль не подошёл.")


@router.post("/logout")
async def logout(form: dict = Depends(require_form)):
    """Выход гасит и cookie, и саму подпись: cookie убирается у этого браузера, а
    выданные до сих пор сессии перестают приниматься. Панель открывают с чужого телефона
    в момент аварии — кнопка «Выйти» обязана делать то, что обещает."""
    global _valid_after
    _valid_after = time.time()
    response = RedirectResponse(LOGIN_PATH, status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/panel")
    return response


def _address(request: Request) -> str:
    """Адрес, с которого пришла попытка. За Caddy заголовку можно верить: он не доверяет
    входящему X-Forwarded-For и подставляет свой (проверено ревью на боевом Caddyfile),
    поэтому берём последний элемент, а без прокси падаем на адрес соединения."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()[:64]
    return request.client.host if request.client else "-"


def _note_login_fail(address: str) -> None:
    global _login_fails
    if len(_login_fails) >= LOGIN_ADDRESSES:
        # Словарь без потолка наполняет улица. Забываем всё разом, а не по одному:
        # выбирать «наименее важный» адрес не на чем, а замок — вещь короткая.
        _login_fails.clear()
    _login_fails[address] = _login_fails.get(address, 0) + 1
    if _login_fails[address] >= LOGIN_FAILS_BEFORE_LOCK:
        _login_locked_at[address] = time.monotonic()
        _login_fails.pop(address, None)
        log.warning("панель: подбор пароля с %s — закрыт на %s с", address, LOGIN_LOCK_SEC)


def _lock_left(address: str) -> int:
    """Сколько секунд осталось до конца замка для этого адреса. 0 — замка нет."""
    locked_at = _login_locked_at.get(address)
    if locked_at is None:
        return 0
    left = LOGIN_LOCK_SEC - (time.monotonic() - locked_at)
    if left <= 0:
        _login_locked_at.pop(address, None)
        return 0
    return int(left) + 1


# ---------- Состояние ----------


@router.get("/", response_class=HTMLResponse)
async def state_page(sid: str = Depends(require_session), note: str = ""):
    facts = await admin.state()
    return _render(
        "state.html",
        sid=sid,
        note=NOTES.get(note, ""),
        active="state",
        verdict=_verdict(facts),
        summary=_summary(facts),
        facts=facts,
        last_tick=(
            _when(facts["dispatcher"]["last_tick_at"])
            if facts["dispatcher"]["last_tick_at"]
            else "ещё не начинался"
        ),
    )


@router.post("/alerts/test")
async def alerts_test(form: dict = Depends(require_form)):
    """Проверочное сообщение в мессенджер. Машина видит «Telegram принял», человек —
    дошло ли; поэтому подтверждает человек, а панель показывает время последней удачи."""
    ok = await meta.send_test_alert()
    return RedirectResponse(f"{HOME_PATH}?note={'alert-sent' if ok else 'alert-failed'}", 303)


def _verdict(facts: dict) -> dict:
    """Первый подходящий диагноз. Порядок и тексты — docs/copy.md, раздел 1.

    Один вердикт, а не список: нижние причины часто оказываются следствием верхних, и
    экран из шести красных плашек не говорит, с чего начать. Всё остальное — строками
    ниже (_summary), там ни одна поломка не пропадает.
    """
    token = facts["token"]
    queue = facts["queue"]
    daily = facts["daily"]
    alerts = facts["alerts"]
    account = facts["account"]
    hooks = facts["webhooks"]
    pending = queue["pending"]

    if not token["present"] and not token["invalid_at"]:
        return _card(
            "down",
            "Отвечать нечем",
            [
                "Уведомления от Instagram сервис принимает, но ответить на них не может:"
                f" токена нет. Уже ждут ответа: {pending}. Всё, что придёт до этого"
                " момента, копится в очереди и уйдёт само, как только токен появится.",
                "Пройдите Instagram Business Login под своим аккаунтом и вставьте токен.",
            ],
            action=("Вставить токен", "/panel/token"),
        )

    if token["invalid_at"]:
        return _card(
            "down",
            "Instagram отключил доступ",
            [
                f"Автоответы стоят с {_when(token['invalid_at'])}. Комментарии и сообщения"
                f" продолжают приходить и ждут в очереди — сейчас там {pending}.",
                "Токен живёт 60 суток и после смерти не восстанавливается: нужен новый."
                " Пройдите Instagram Business Login под своим аккаунтом и вставьте свежий"
                " токен. Перезапускать сервис не нужно — очередь разберётся сама.",
            ],
            action=("Вставить новый токен", "/panel/token"),
        )

    expires_at = _at(token["expires_at"])
    if expires_at is not None and token["present"]:
        left_sec = (expires_at - datetime.now(timezone.utc)).total_seconds()
        if left_sec <= 0 and token["expires_at_confirmed"]:
            return _card(
                "down",
                "Срок доступа к Instagram истёк",
                [
                    f"Meta называла срок до {_when(token['expires_at'])}, продлить его"
                    " сервис не смог. Автоответы могут ещё идти по инерции, но следующий"
                    " же отказ платформы остановит их совсем.",
                    "Токен живёт 60 суток и после смерти не восстанавливается: пройдите"
                    " Instagram Business Login и вставьте свежий.",
                ],
                action=("Вставить новый токен", "/panel/token"),
            )
        if left_sec <= 0:
            return _card(
                "warn",
                "Продление доступа не проходит",
                [
                    "Сервис продлевает токен сам, но Meta уже которые сутки не"
                    f" подтверждает срок: последняя отметка — {_when(token['expires_at'])}."
                    " Пока автоответы работают, но проверить это нечем, кроме живого"
                    " комментария.",
                    "Надёжнее не ждать: пройдите Instagram Business Login и вставьте"
                    " свежий токен — счёт пойдёт заново.",
                ],
                action=("Вставить новый токен", "/panel/token"),
            )
        if token["expires_at_confirmed"] and left_sec < TOKEN_WARN_DAYS * 86400:
            return _card(
                "warn",
                # Вверх, а не вниз: «через 3 суток» при трёх сутках и 23 часах — занижение,
                # а человек по этому числу решает, идти ли ему за токеном сегодня.
                f"Доступ истекает через {_days(math.ceil(left_sec / 86400))}",
                [
                    "Сервис продлевает токен сам и обычно делает это заранее. Раз срок"
                    " всё ещё близко, продление не проходит — а после истечения токен"
                    " не восстанавливается никак.",
                    "Не дожидаясь: пройдите Instagram Business Login и вставьте свежий"
                    " токен.",
                ],
                action=("Вставить новый токен", "/panel/token"),
            )

    stale = facts["dispatcher"]["stale_sec"]
    if facts["dispatcher"]["last_tick_at"] is None or (stale is not None and stale > HEALTH_STALE_SEC):
        return _card(
            "down",
            "Отправка встала: сервис не делает круг",
            [
                "Приём уведомлений работает и ничего не теряется, но материал сейчас"
                " никому не уходит. Сервис перезапустит себя сам в течение минуты —"
                " обновите страницу.",
                "Если это держится дольше пары минут, перезапуск не помогает: смотрите"
                " логи контейнера, docker compose logs --tail=100 instagram-service.",
            ],
        )

    if not alerts["configured"]:
        return _card(
            "down",
            "Канал алертов не настроен",
            [
                "Если автоответы встанут, вы об этом не узнаете. Со стороны поломка"
                " выглядит спокойно: сервис жив, ошибок нет, просто никто никому"
                " не отвечает.",
                "Заведите бота в телеграм, положите его токен в IG_ALERT_BOT_TOKEN,"
                " свой chat_id — в IG_ALERT_CHAT_ID и поднимите сервис заново.",
            ],
        )

    if alerts["last_error"]:
        return _card(
            "down",
            "Алерты не доходят",
            [
                "Последняя попытка отправить сигнал в телеграм закончилась отказом:"
                f" {alerts['last_error']}",
                "Пока это не починено, о любой другой поломке вы узнаете только отсюда,"
                " из панели. Чаще всего дело в chat_id (у групп он с минусом впереди)"
                " или в том, что боту не написали первым — пока диалог не начат, бот"
                " писать не может.",
            ],
            action=("Проверить ещё раз", "/panel/alerts/test", True),
        )

    if alerts["configured"] and not alerts["last_ok_at"]:
        return _card(
            "warn",
            "Канал алертов не проверен",
            [
                "Настройки есть, но ни одно сообщение по ним ещё не уходило."
                " «Настроено» и «доходит» — разные вещи: неверный chat_id выяснится"
                " ровно в тот момент, когда сигнал будет нужен.",
                "Отправьте себе проверочное сообщение и убедитесь, что оно пришло.",
            ],
            action=("Отправить проверочное сообщение", "/panel/alerts/test", True),
        )

    if daily["reached"]:
        return _card(
            "warn",
            "Сработал суточный потолок",
            [
                f"За последние сутки ушло {daily['sent_24h']} сообщений из"
                f" {daily['limit']} — дальше сервис ждёт. Чинить нечего: отправка"
                " продолжится сама, как только с самой ранней отправки пройдёт сутки."
                " Счёт идёт скользящими сутками, а не с полуночи.",
                "Потолок стоит не ради сервера, а ради вашего аккаунта: сотня"
                " автоматических сообщений незнакомым людям за час — ровно тот профиль,"
                " который платформа ловит как спам. Поднять его можно переменной"
                " IG_DAILY_DM_LIMIT, но сначала посмотрите, кому и что уже ушло.",
            ],
            action=("Посмотреть очередь", "/panel/queue"),
        )

    if queue["retrying"]:
        return _card(
            "warn",
            "Instagram не принимает отправки",
            [
                f"Сервис пробует снова: {queue['retrying']} доставок ждут следующей"
                f" попытки, последний отказ был {_when(queue['last_error_at'])}."
                " Между попытками пауза, она растёт — так платформа не получает одно"
                " и то же тело подряд.",
                "Делать ничего не нужно. Если это держится дольше часа, посмотрите,"
                " не сломалось ли что-то на стороне Instagram — а если сообщения об"
                " отказах приходят к вам в телеграм, перешлите последнее разработчику"
                " пакета: по коду отказа его можно научить распознавать.",
            ],
            action=("Посмотреть очередь", "/panel/queue"),
        )

    if not account["ig_user_id"]:
        return _card(
            "down",
            "Сервис не знает, чей аккаунт обслуживает",
            [
                "IG_USER_ID не заполнен. Без него сервис не отличает свои комментарии"
                " от чужих и чужие уведомления от ваших: отвечать он не будет никому.",
                "Нужен номер, который Instagram сам ставит в уведомление о комментарии"
                " (поле entry.id). Второй номер аккаунта выдаётся приложению,"
                " в уведомлениях не встречается и сюда не годится.",
                "Впишите его в IG_USER_ID и поднимите сервис заново.",
            ],
        )

    if account["wrong_ig_user_id"]:
        # Номер живёт в памяти процесса (dispatcher.last_foreign_entry_id), а сам вердикт
        # считается по суточным счётчикам из базы — те рестарт переживают. Значит после
        # перезапуска номера может не быть, и печатать «впишите None» нельзя: человек
        # получит инструкцию, которую нельзя выполнить.
        seen = account["last_foreign_entry_id"]
        return _card(
            "down",
            "Ни на один комментарий не ответили: сервис слушает другой аккаунт",
            [
                f"За сутки пришло {account['handled_24h']} уведомлений, и все — про"
                " аккаунт, который сервис не обслуживает. Ни на одно он не ответил"
                " и не ответит, пока настройка не изменится.",
                "Почти всегда причина одна: у аккаунта в Instagram два разных номера,"
                " и в настройки попал не тот. Нужен тот, который Instagram сам ставит"
                " в уведомление о комментарии; второй выдаётся приложению,"
                " в уведомлениях не встречается и сюда не годится.",
                (
                    f"Номер из уведомления сервис уже видел, вот он: {seen}."
                    f" Сейчас в настройках стоит {account['ig_user_id']}."
                    if seen
                    else "Номер из уведомления сервис показывал до перезапуска и покажет"
                    " снова со следующим комментарием — загляните сюда после него."
                    f" Сейчас в настройках стоит {account['ig_user_id']}."
                ),
                (
                    f"Если {seen} — ваш аккаунт, впишите это число в IG_USER_ID"
                    " и поднимите сервис заново."
                    if seen
                    else "Если номер из уведомления окажется вашим — впишите его"
                    " в IG_USER_ID и поднимите сервис заново."
                )
                + " Если аккаунт правда чужой, значит одно приложение Meta подписано"
                " на два аккаунта. Так нельзя: второй молча перехватывает события первого.",
            ],
        )

    if not hooks["ever_received"]:
        return _card(
            "down",
            "От Instagram не пришло ни одного уведомления",
            [
                "Сервис поднят и ждёт, но платформа ему ещё ничего не присылала."
                " Ошибок при этом нет и не будет — тишина здесь выглядит точно так же,"
                " как исправная работа в выходной день.",
                "Проверьте по порядку: приложение в дашборде Meta опубликовано (в самом"
                " дашборде это написано прямо: для получения уведомлений у приложения"
                " должен быть статус «Опубликовано»); в подписке отмечены поля comments"
                " и messages; адрес вебхука указан на этот домен и заканчивается"
                " на /ig/webhook.",
                "Потом оставьте тестовый комментарий под своим постом с другого"
                " аккаунта — свои сервис пропускает намеренно, иначе он отвечал бы"
                " сам себе.",
            ],
        )

    silent = _days_since(hooks["last_at"])
    if hooks["ever_received"] and hooks["last_at"] is None:
        # Уведомления когда-то приходили, а в журнале пусто: значит последнее старше
        # EVENT_RETENTION_DAYS и его вычистил ретеншен. Без этой строки самая долгая
        # тишина из возможных проваливалась в «Сервис отвечает» — зелёным.
        silent = EVENT_RETENTION_DAYS
    if silent is not None and silent >= SILENCE_ALERT_DAYS:
        return _card(
            # Журнал пуст — значит тишина заведомо длиннее срока хранения, и это уже
            # не «под постами тихо», а самая долгая тишина из возможных.
            "down" if hooks["last_at"] is None else "warn",
            f"Тишина уже {_days(silent)}",
            [
                (
                    f"Последнее уведомление от Instagram пришло {_when(hooks['last_at'])}."
                    if hooks["last_at"]
                    else "Последнее уведомление приходило так давно, что журнал его уже"
                    f" не хранит: он живёт {_days(EVENT_RETENTION_DAYS)}."
                )
                + " Это может быть нормой — под постами просто никто не пишет кодовых"
                " слов. А может быть тишиной после поломки: отвалилась подписка,"
                " сменился домен, приложение ушло на проверку.",
                "Отличить одно от другого можно за минуту: оставьте комментарий"
                " с кодовым словом под своим постом с чужого аккаунта. Ответ пришёл —"
                " всё работает.",
            ],
        )

    queue_line = (
        "Очередь пуста."
        if not pending
        else f"В очереди {pending}, разбирается."
    )
    return _card(
        "ok",
        "Сервис отвечает",
        [
            f"За сутки разобрано {account['handled_24h']} уведомлений, отправлено"
            f" {daily['sent_24h']} сообщений. {queue_line}"
            f" Алерты в телеграм доходили {_when(alerts['last_ok_at'])}.",
        ],
    )


def _summary(facts: dict) -> list[dict]:
    """Строки «мелким шрифтом» под вердиктом: ни одна поломка не должна пропасть из виду
    только потому, что другая оказалась выше в списке."""
    token = facts["token"]
    hooks = facts["webhooks"]
    queue = facts["queue"]
    daily = facts["daily"]
    alerts = facts["alerts"]
    account = facts["account"]

    expires_at = _at(token["expires_at"])
    left_sec = (
        (expires_at - datetime.now(timezone.utc)).total_seconds() if expires_at else None
    )
    if not token["present"]:
        token_line, token_level = "не вставлен", "down"
    elif token["invalid_at"]:
        token_line, token_level = "отвергнут Instagram", "down"
    elif left_sec is not None and left_sec <= 0:
        # Дата в прошлом и слово «живой» рядом — это и есть зелёное поверх сломанного.
        token_line, token_level = (
            f"срок истёк {_when(token['expires_at'])}, продлить не удалось",
            "down" if token["expires_at_confirmed"] else "warn",
        )
    elif token["expires_at_confirmed"] and left_sec is not None:
        days = math.ceil(left_sec / 86400)
        token_line = f"живой, срок до {_when(token['expires_at'])}"
        token_level = "warn" if days < TOKEN_WARN_DAYS else "ok"
    else:
        # Обратный отсчёт по неподтверждённому сроку соврал бы: до первого продления
        # в expires_at стоит горизонт зонда, а не срок жизни токена.
        token_line, token_level = "живой; срок уточним при первом продлении", "ok"

    if not hooks["ever_received"]:
        hooks_line, hooks_level = "не приходили ни разу", "down"
    elif hooks["last_at"] is None:
        # Журнал вычищен ретеншеном, нового не приходило: тишина дольше срока хранения.
        hooks_line = f"тишина дольше {_days(EVENT_RETENTION_DAYS)} — журнал пуст"
        hooks_level = "down"
    else:
        silent = _days_since(hooks["last_at"]) or 0
        hooks_line = f"последнее {_when(hooks['last_at'])}, в журнале {hooks['kept']}"
        hooks_level = "warn" if silent >= SILENCE_ALERT_DAYS else "ok"

    if alerts["last_error"]:
        alerts_line, alerts_level = f"не работает — {alerts['last_error']}", "down"
    elif not alerts["configured"]:
        alerts_line, alerts_level = "не настроен", "down"
    elif not alerts["last_ok_at"]:
        alerts_line, alerts_level = "не проверен ни разу", "warn"
    else:
        alerts_line, alerts_level = f"доходили {_when(alerts['last_ok_at'])}", "ok"

    rows = [
        {"label": "Токен", "text": token_line, "level": token_level},
        {"label": "Уведомления", "text": hooks_line, "level": hooks_level},
        {
            "label": "Очередь",
            "text": (
                "пусто"
                if not queue["pending"]
                else f"{queue['pending']} ждут, из них {queue['retrying']} после отказа"
            ),
            "level": "warn" if queue["retrying"] else "ok",
        },
        {
            "label": "За сутки",
            "text": (
                f"{daily['sent_24h']} отправлено, потолок снят —"
                " сервис отправит столько, сколько попросят"
                if not daily["limit"]
                else f"{daily['sent_24h']} из {daily['limit']}"
            ),
            # Снятый предохранитель — не «ок»: рискует аккаунт владельца установки,
            # а не сервер, и на экране «всё ли в порядке» это должно быть видно.
            "level": "warn" if daily["reached"] or not daily["limit"] else "ok",
        },
        {"label": "Алерты", "text": alerts_line, "level": alerts_level},
        {
            "label": "Аккаунт",
            "text": (
                "не задан: IG_USER_ID пуст"
                if not account["ig_user_id"]
                else f"{account['ig_user_id']} — уведомления приходят чужому аккаунту"
                if account["wrong_ig_user_id"]
                else account["ig_user_id"]
            ),
            "level": (
                "down"
                if account["wrong_ig_user_id"] or not account["ig_user_id"]
                else "ok"
            ),
        },
        {
            "label": "Хранение",
            "text": (
                "обращения не удаляются"
                if not DELIVERY_RETENTION_DAYS
                else f"обращения {_days(DELIVERY_RETENTION_DAYS)},"
                f" журнал уведомлений {_days(EVENT_RETENTION_DAYS)}"
            ),
            "level": "ok",
        },
    ]
    stale = facts["dispatcher"]["stale_sec"]
    if facts["dispatcher"]["last_tick_at"] is None:
        rows.append(
            {
                "label": "Круг доставки",
                "text": "не начинался ни разу — отправка не работает",
                "level": "down",
            }
        )
    elif stale is not None and stale > HEALTH_STALE_SEC:
        rows.append(
            {
                "label": "Круг доставки",
                "text": f"замер на {stale} с — сервис сейчас перезапустит себя сам",
                "level": "down",
            }
        )
    return rows


def _card(level: str, title: str, body: list[str], action: tuple | None = None) -> dict:
    """Диагноз с действием. action = (надпись, адрес[, форма?]): третий элемент отличает
    кнопку, которая ДЕЛАЕТ (POST с меткой формы), от ссылки, которая просто ведёт."""
    return {
        "level": level,
        "title": title,
        "body": body,
        "action": (
            {"label": action[0], "href": action[1], "post": len(action) > 2 and action[2]}
            if action
            else None
        ),
    }


# ---------- Правила ----------


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(sid: str = Depends(require_session), note: str = ""):
    rows = await db.admin_list_rules()
    items = [
        {
            "rule": admin.rule_view(row),
            # Тот же приговор, что вынесет диспетчер перед отправкой: «сохранено, но
            # не работает» человек должен видеть в списке, а не узнавать из алерта.
            "problem": rules.unconfigured(dispatcher.to_rule(row)),
        }
        for row in rows
    ]
    return _render(
        "rules.html",
        sid=sid,
        note=NOTES.get(note, ""),
        active="rules",
        items=items,
        all_off=bool(items) and not any(item["rule"]["enabled"] for item in items),
    )


@router.get("/rules/new", response_class=HTMLResponse)
async def rule_new(sid: str = Depends(require_session)):
    return _render("rule.html", sid=sid, note="", **_form_context(_blank(), rule=None))


@router.post("/rules/new")
async def rule_create(sid: str = Depends(require_session), form: dict = Depends(require_form)):
    body, problems = _form_body(form)
    if _wants_preview(form):
        return _render("rule.html", sid=sid, note="",
                       **_form_context(body, rule=None, preview=_preview(body)))
    if problems:
        return _render("rule.html", status=400, sid=sid, note="",
                       **_form_context(body, rule=None, errors=problems))
    row, errors, warnings = await admin.save_rule(body, current=None)
    if errors:
        return _render("rule.html", status=400, sid=sid, note="",
                       **_form_context(body, rule=None, errors=errors))
    return _saved(sid, row, warnings)


@router.get("/rules/{rule_id}", response_class=HTMLResponse)
async def rule_page(rule_id: int, sid: str = Depends(require_session), note: str = ""):
    row = await db.admin_get_rule(rule_id)
    if row is None:
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    return _render(
        "rule.html",
        sid=sid,
        note=NOTES.get(note, ""),
        **_form_context(admin.rule_view(row), rule=admin.rule_view(row)),
    )


@router.post("/rules/{rule_id}")
async def rule_save(
    rule_id: int, sid: str = Depends(require_session), form: dict = Depends(require_form)
):
    current = await db.admin_get_rule(rule_id)
    if current is None:
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    body, problems = _form_body(form)
    view = admin.rule_view(current)
    if _wants_preview(form):
        return _render("rule.html", sid=sid, note="",
                       **_form_context(body, rule=view, preview=_preview(body)))
    if problems:
        return _render("rule.html", status=400, sid=sid, note="",
                       **_form_context(body, rule=view, errors=problems))
    row, errors, warnings = await admin.save_rule(body, current=current)
    if errors:
        return _render("rule.html", status=400, sid=sid, note="",
                       **_form_context(body, rule=view, errors=errors))
    if row is None:
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    return _saved(sid, row, warnings)


@router.post("/rules/{rule_id}/enabled")
async def rule_toggle(
    rule_id: int, sid: str = Depends(require_session), form: dict = Depends(require_form)
):
    """Включить или выключить одним нажатием, не открывая форму.

    Ходит тем же save_rule: включение прогоняет ровно те же проверки, что сохранение
    руками, — иначе кнопкой можно было бы включить правило, которое форма не пустила.
    """
    current = await db.admin_get_rule(rule_id)
    if current is None:
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    wanted = str(form.get("enabled") or "") == "1"
    row, errors, _ = await admin.save_rule({"enabled": wanted}, current=current)
    if errors:
        # Чаще всего это «правило нельзя включить — …»: причина обязана оказаться перед
        # глазами, а не в логе, поэтому форма, а не редирект.
        view = admin.rule_view(current)
        return _render("rule.html", status=400, sid=sid, note="",
                       **_form_context(view, rule=view, errors=errors))
    return _back(f"/panel/rules/{row['id']}", note="enabled" if wanted else "disabled")


@router.post("/rules/{rule_id}/copy")
async def rule_copy(
    rule_id: int, sid: str = Depends(require_session), form: dict = Depends(require_form)
):
    row, errors, warnings = await admin.duplicate_rule(rule_id)
    # Порядок тот же, что в машинном API: сперва причина отказа, и только потом «нечего
    # копировать». Обратный порядок показывал «правило уже удалено» вместо настоящей причины.
    if errors:
        current = await db.admin_get_rule(rule_id)
        if current is None:
            return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
        view = admin.rule_view(current)
        return _render("rule.html", status=400, sid=sid, note="",
                       **_form_context(view, rule=view, errors=errors))
    if row is None:
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    view = admin.rule_view(row)
    return _render(
        "rule.html", sid=sid, note=NOTES["copied"],
        **_form_context(view, rule=view, warnings=warnings),
    )


@router.get("/rules/{rule_id}/delete", response_class=HTMLResponse)
async def rule_delete_page(rule_id: int, sid: str = Depends(require_session)):
    row = await db.admin_get_rule(rule_id)
    if row is None:
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    return _render(
        "delete.html",
        sid=sid,
        active="rules",
        rule=admin.rule_view(row),
        # Сколько людей снова станут «не обслуженными»: удаление уносит резервации
        # каскадом, восстановить их нечем — значит, число человек должен увидеть ДО.
        released=await db.admin_count_contacts(rule_id),
    )


@router.post("/rules/{rule_id}/delete")
async def rule_delete(
    rule_id: int, sid: str = Depends(require_session), form: dict = Depends(require_form)
):
    released = await db.admin_count_contacts(rule_id)
    if not await db.admin_delete_rule(rule_id):
        return _render("gone.html", status=404, sid=sid, active="rules", what="правило")
    log.info("правило %s удалено из панели, снято резерваций: %s", rule_id, released)
    return _back("/panel/rules", note="deleted")


# ---------- Очередь ----------


@router.get("/queue", response_class=HTMLResponse)
async def queue_page(sid: str = Depends(require_session), note: str = ""):
    rows = await db.admin_list_deliveries(admin.DELIVERIES_PAGE)
    # Брони, чья карточка уже вычищена ретеншеном: без отдельного списка снять такую
    # из панели нельзя вообще никак — кнопку рисует строка очереди, а строки больше нет.
    orphans = await db.admin_orphan_holds(admin.DELIVERIES_PAGE)
    return _render(
        "queue.html",
        sid=sid,
        note=NOTES.get(note, ""),
        active="queue",
        # Состояние словами и время по-человечески: машинный вид ISO в этой таблице
        # читает doctor.sh через /ig/admin/deliveries, а здесь читает человек.
        items=[
            {
                **admin.delivery_view(row),
                "label": STATE_LABELS.get(row["state"], row["state"]),
                "when": _when(_moment(row["created_at"])),
                "next_try": _when(_moment(row["run_after"])),
            }
            for row in rows
        ],
        orphans=[
            {
                "delivery_id": row["delivery_id"],
                "igsid": row["igsid"],
                "rule_name": row["rule_name"],
                "when": _when(_moment(row["created_at"])),
            }
            for row in orphans
        ],
        retention=DELIVERY_RETENTION_DAYS,
    )


@router.post("/queue/{delivery_id}/release")
async def queue_release(
    delivery_id: int, sid: str = Depends(require_session), form: dict = Depends(require_form)
):
    released = await db.admin_release_contact(delivery_id)
    if not released:
        return _back("/panel/queue", note="no-hold")
    log.info("доставка %s: бронь снята из панели", delivery_id)
    return _back("/panel/queue", note="released")


# Состояния доставки человеческими словами. Незнакомое состояние показывается как есть:
# следующий этап заводит свои, и «неизвестно» на экране хуже, чем сырое имя.
STATE_LABELS = {
    "PENDING": "ждёт отправки",
    "CLAIMED": "отправляется",
    "REPLIED_PUBLIC": "ответили под постом",
    "SENT_DM": "материал ушёл",
    "DONE": "готово",
    "FAILED": "не получилось",
    "EXPIRED": "окно платформы закрылось",
    "SKIPPED_NO_RULE": "нет подходящего правила",
    "SKIPPED_SELF": "свой же комментарий",
    "SKIPPED_DUPLICATE": "повтор, отвечать было нечем",
    "REPLIED_DUPLICATE": "повтор, ответили под постом",
    "SKIPPED_FOREIGN_ACCOUNT": "чужой аккаунт",
}


# ---------- Токен ----------


@router.get("/token", response_class=HTMLResponse)
async def token_page(sid: str = Depends(require_session), note: str = ""):
    facts = await admin.state()
    return _render(
        "token.html",
        sid=sid,
        note=NOTES.get(note, ""),
        active="token",
        token=facts["token"],
        invalid_at=_when(facts["token"]["invalid_at"]),
        expires_at=_when(facts["token"]["expires_at"]),
        error="",
    )


@router.post("/token")
async def token_save(sid: str = Depends(require_session), form: dict = Depends(require_form)):
    """Замена токена — только по явно нажатой кнопке.

    Поле-НАМЕРЕНИЕ, а не надежда на атрибуты разметки: страница живёт на том же адресе,
    где браузер сохранил пароль от панели, и менеджер паролей охотно подставляет его
    в одинокое поле. Записанный поверх живого токена пароль стирает единственную копию
    (строка в ig_token одна, истории нет) и следующим кругом уезжает в чужие логи
    параметром запроса на продление. Атрибут autocomplete Chromium для полей пароля
    игнорирует по документированному поведению — поэтому поле обычное текстовое,
    а решение принимает нажатие.
    """
    if str(form.get("__set__token") or "") != "1":
        facts = await admin.state()
        return _render(
            "token.html", status=400, sid=sid, note="", active="token",
            token=facts["token"], invalid_at=_when(facts["token"]["invalid_at"]),
            expires_at=_when(facts["token"]["expires_at"]),
            error="Нажмите кнопку «Вставить токен» — форма пришла без неё.",
        )
    value = str(form.get("token") or "").strip()
    if not value:
        facts = await admin.state()
        return _render(
            "token.html", status=400, sid=sid, note="", active="token",
            token=facts["token"], invalid_at=_when(facts["token"]["invalid_at"]),
            expires_at=_when(facts["token"]["expires_at"]),
            error="Поле пустое — вставлять нечего.",
        )
    expires_at, error = await admin.accept_token(value)
    if error:
        facts = await admin.state()
        return _render(
            "token.html", status=400, sid=sid, note="", active="token",
            token=facts["token"], invalid_at=_when(facts["token"]["invalid_at"]),
            expires_at=_when(facts["token"]["expires_at"]), error=error,
        )
    return _back("/panel/token", note="token")


# ---------- Форма правила ----------


def _blank() -> dict:
    """Пустое правило в том же виде, в каком приходит сохранённое: у формы один источник."""
    return {
        "id": None, "name": "", "enabled": False, "trigger": "COMMENT", "media_id": None,
        "keywords": [], "match_mode": "CONTAINS", "priority": 0, "public_replies": [],
        "duplicate_replies": [], "dm_text": "", "dm_buttons": [],
    }


def _form_context(values: dict, rule: dict | None, errors: list[str] | None = None,
                  warnings: list[str] | None = None, preview: dict | None = None) -> dict:
    """Контекст формы. values — то, что человек только что набрал (или строка из базы),
    rule — СОХРАНЁННОЕ правило (None у нового): по нему рисуются кнопки копии и удаления
    и по нему же считается «сохранено, но не работает».

    problem считается по сохранённой строке, а не по набранному: приговор в шапке формы
    должен описывать то, что лежит в базе и что увидит диспетчер, а не черновик в полях.
    """
    buttons = list(values["dm_buttons"]) + [{"title": "", "url": ""}] * MAX_BUTTONS
    return {
        "active": "rules",
        "warnings": warnings or [],
        "problem": rules.unconfigured(dispatcher.to_rule(rule)) if rule else None,
        "values": values,
        "rule": rule,
        "errors": errors or [],
        "preview": preview,
        "buttons": buttons[:MAX_BUTTONS],
        "triggers": admin.TRIGGERS,
        "match_modes": admin.MATCH_MODES,
        "limits": {
            "message_bytes": rules.MAX_MESSAGE_BYTES,
            "buttons": MAX_BUTTONS,
            "button_title": MAX_BUTTON_TITLE,
            "keywords": admin.MAX_KEYWORDS,
            "variants": admin.MAX_REPLY_VARIANTS,
            "name": admin.MAX_NAME_LEN,
        },
    }


def _form_body(form: dict) -> tuple[dict, list[str]]:
    """Форма → тело правила для admin.save_rule.

    Здесь ТОЛЬКО перевод типов: строка формы в число, строки текста в список. Смысловых
    проверок нет ни одной — они живут в admin/rules, и второй их набор здесь означал бы
    форму, которая пускает не то же, что API.
    """
    problems: list[str] = []
    raw_priority = str(form.get("priority") or "0").strip() or "0"
    try:
        priority = int(raw_priority)
    except ValueError:
        problems.append("Приоритет: ожидается целое число")
        priority = 0

    buttons = []
    for index in range(MAX_BUTTONS):
        title = str(form.get(f"button_title_{index}") or "").strip()
        url = str(form.get(f"button_url_{index}") or "").strip()
        if title or url:
            buttons.append({"title": title, "url": url})

    body = {
        "name": str(form.get("name") or "").strip(),
        "enabled": str(form.get("action") or "") == "save_on" or form.get("enabled") == "on",
        "trigger": str(form.get("trigger") or "COMMENT"),
        "media_id": str(form.get("media_id") or "").strip() or None,
        "keywords": _words(str(form.get("keywords") or "")),
        "match_mode": str(form.get("match_mode") or "CONTAINS"),
        "priority": priority,
        "public_replies": _lines(str(form.get("public_replies") or "")),
        "duplicate_replies": _lines(str(form.get("duplicate_replies") or "")),
        "dm_text": str(form.get("dm_text") or ""),
        "dm_buttons": buttons,
    }
    return body, problems


def _wants_preview(form: dict) -> bool:
    return str(form.get("action") or "") == "preview"


def _preview(body: dict) -> dict:
    """Раскрытия ТЕМ ЖЕ движком, что уходит в Meta, и в том же порядке действий,
    что у диспетчера: сначала случайный вариант из списка, потом раскрытие скобок.

    Длина считается по longest(), а не по показанному раскрытию: правило со случайной
    длиной однажды выпадет отказом на неудачном сочетании вариантов, и поймать такой
    плавающий отказ почти невозможно.
    """
    worst = rules.longest(body["dm_text"])
    broken = rules.check_template(body["dm_text"])
    return {
        "broken": broken,
        "dm": [] if broken else [rules.expand(body["dm_text"]) for _ in range(PREVIEW_SAMPLES)],
        "worst_bytes": len(worst.encode("utf-8")),
        "limit_bytes": rules.MAX_MESSAGE_BYTES,
        "public": _rolls(body["public_replies"]),
        "duplicate": _rolls(body["duplicate_replies"]),
    }


def _rolls(variants: list[str]) -> list[str]:
    if not variants:
        return []
    return [rules.expand(random.choice(variants)) for _ in range(PREVIEW_SAMPLES)]


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _words(text: str) -> list[str]:
    """Ключевые слова: по строке или через запятую — как человеку удобнее набрать.
    Запятая внутри слова смысла не имеет, её всё равно съедает rules.normalize."""
    parts: list[str] = []
    for line in text.splitlines():
        parts += [word.strip() for word in line.split(",")]
    return [word for word in parts if word]


# ---------- Ответы и форматирование ----------


def _render(name: str, status: int = 200, sid: str = "", **ctx) -> HTMLResponse:
    """Страница. csrf кладётся здесь, а не в каждом обработчике: забытая метка — это
    форма, которую не примет require_form, и человек упрётся в отказ на ровном месте."""
    ctx.setdefault("note", "")
    ctx.setdefault("active", "")
    return HTMLResponse(
        TEMPLATES.get_template(name).render(csrf=_csrf(sid) if sid else "", **ctx),
        status_code=status,
    )


def _saved(sid: str, row: dict, warnings: list[str]) -> HTMLResponse | RedirectResponse:
    """Ответ на удачное сохранение.

    С предупреждениями — сразу страница, без редиректа: «сохранено, но работать не будет»
    человек обязан прочитать, а редирект унёс бы этот текст (хранить его на сервере ради
    одной строки — заводить сессионное состояние там, где его нет).
    """
    view = admin.rule_view(row)
    if warnings:
        return _render(
            "rule.html", sid=sid, note=NOTES["saved"],
            **_form_context(view, rule=view, warnings=warnings),
        )
    return _back(f"/panel/rules/{row['id']}", note="saved")


def _back(path: str, note: str = "", warnings: list[str] | None = None) -> RedirectResponse:
    """POST → редирект → GET: обновление страницы не повторяет действие.

    В адрес уходит КОД известного сообщения, а не текст: подставлять в страницу
    произвольную строку из адреса — это отражённый XSS даже при автоэкранировании.
    """
    if warnings:
        log.info("панель: %s", "; ".join(warnings))
    return RedirectResponse(f"{path}?note={note}" if note else path, status_code=303)


def _at(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _moment(value: datetime | None) -> str | None:
    """Строка ISO из объекта времени: панель читает и готовые ответы admin.state()
    (там уже строки), и сырые строки таблицы — формат у обеих дорог один."""
    return value.isoformat() if value else None


def _when(value: str | None) -> str:
    """Момент времени так, как его читает человек: и абсолютно, и «сколько назад»."""
    moment = _at(value)
    if moment is None:
        return "никогда"
    return f"{moment.strftime('%d.%m.%Y %H:%M UTC')} ({_ago(moment)})"


def _ago(moment: datetime) -> str:
    seconds = (datetime.now(timezone.utc) - moment).total_seconds()
    if seconds < 90:
        return "только что"
    if seconds < 3600:
        return f"{int(seconds // 60)} мин назад"
    if seconds < 86400:
        return f"{int(seconds // 3600)} ч назад"
    return f"{_days(int(seconds // 86400))} назад"


def _days(count: int) -> str:
    tail = "сутки" if count % 10 == 1 and count % 100 != 11 else "суток"
    return f"{count} {tail}"


def _days_since(value: str | None) -> int | None:
    moment = _at(value)
    if moment is None:
        return None
    return int((datetime.now(timezone.utc) - moment).total_seconds() // 86400)


# ---------- Отказы ----------


async def on_http_error(request: Request, exc: HTTPException):
    """Отказ панели — страницей, а не JSON'ом: на той стороне человек в браузере.

    Тексты у отказов правильные (fail-closed, устаревшая форма, слишком большое тело),
    оболочка была нет: `{"detail": …}` посреди аварии читается как поломка панели.
    Редиректы (302 на форму входа) проходят насквозь — это не отказ.
    """
    if not request.url.path.startswith("/panel"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                            headers=exc.headers)
    if 300 <= exc.status_code < 400 and (exc.headers or {}).get("Location"):
        return RedirectResponse(exc.headers["Location"], status_code=exc.status_code)
    return _render("closed.html", status=exc.status_code, sid="", active="",
                   reason=str(exc.detail))


async def on_error(request: Request, exc: Exception):
    """Всё, что не поймали: почти всегда это упавшая база.

    Панель — единственный инструмент диагностики установки, и голый «Internal Server
    Error» на английском не даёт человеку отличить «упала база» от «сломалась панель».
    Приём вебхуков при этом продолжает работать, и сказать об этом важнее всего.
    """
    log.exception("панель: необработанный отказ на %s", request.url.path)
    if not request.url.path.startswith("/panel"):
        return JSONResponse({"error": "internal"}, status_code=500)
    return _render("down.html", status=503, sid="", active="")


if __name__ == "__main__":
    # Хеш пароля панели для файла окружения. Пароль читается со STDIN, а не из
    # аргументов: argv виден в `ps aux` любому пользователю хоста.
    import sys

    print(hash_password(sys.stdin.readline().rstrip("\n")))

