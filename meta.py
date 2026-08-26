"""Исходящий HTTP сервиса: Graph API Instagram и аварийный сигнал владельцу.

Хост Graph один — graph.instagram.com (флоу Instagram Login; graph.facebook.com этот
маркер не принимает, отвечает 401 «Cannot parse access token»).

Второй адресат — telegram-service по внутренней сети docker. Отдельный модуль ради
одной функции алерта — лишняя сущность, а прятать её в диспетчер нельзя: продление
токена сигналит владельцу мимо диспетчера.

Токен в лог не попадает никогда: в POST он уходит в теле, а у GET-продления из
сообщений об ошибке режется query-строка.
"""

import logging
from typing import Any

import httpx

from rules import MAX_MESSAGE_BYTES, clip
from config import (
    IG_ALERT_TG_USER_ID,
    IG_ALERT_TOKEN,
    IG_GRAPH_VERSION,
    TELEGRAM_SERVICE_URL,
)

log = logging.getLogger("meta")

GRAPH_HOST = "https://graph.instagram.com"
HTTP_TIMEOUT_SEC = 20

# Лимит платформы на текст сообщения живёт в rules вместе с движком текстов: считать
# длину нужно на РАСКРЫТОЙ строке, и обе операции должны видеть одну и ту же константу.
# Кнопок в button template не больше трёх, заголовок — до 20 символов.
MAX_BUTTONS = 3
MAX_BUTTON_TITLE = 20

# Как поступать с отказом Meta. Слепой ретрай запрещён: он либо жжёт попытки на
# терминальной ошибке, либо долбит платформу тем же телом до отключения подписки.
RETRY = "RETRY"
RATE_LIMIT = "RATE_LIMIT"
TERMINAL = "TERMINAL"
# Тот же отказ по последствиям, но КОДА мы такого не знаем: доставка закрывается, и
# владельцу сразу летит сигнал с кодом. Так таблица ниже пополняется живыми отказами,
# а не догадками, и неизвестный код не тонет под порогом «5 отказов за час».
TERMINAL_UNKNOWN = "TERMINAL_UNKNOWN"
EXPIRED = "EXPIRED"
TOKEN_INVALID = "TOKEN_INVALID"
ALREADY_DONE = "ALREADY_DONE"

# Решение принимается по (code, error_subcode) и НИКОГДА по тексту сообщения: формулировки
# Meta не контракт, они меняются между версиями Graph и локализуются по locale приложения.
# Промах текстом в сторону ALREADY_DONE — это доставка, объявленная успешной без единого
# признака успеха («this media has already been deleted» тоже содержит "already").
TOKEN_CODES = {190}
RATE_CODES = {4, 17, 32, 613}
# Зондировано владельцем 25.08.2026 живым запросом: получателя не существует, тело принято.
TERMINAL_CODES = {(100, 2534014)}
# ПУСТЫ НАМЕРЕННО. Заполняются двумя зондами на живом аккаунте (приёмка этапа 2 всё равно
# требует живого прогона), после чего сюда вписывается пара из ответа:
#   1) POST /{comment_id}/replies ... затем POST /me/messages с recipient:{comment_id}
#      ДВАЖДЫ на один и тот же комментарий  → пара для DUPLICATE_CODES;
#   2) POST /me/messages в диалог, где 24-часовое окно закрыто → пара для WINDOW_CODES.
# До этого такой отказ попадёт в TERMINAL_UNKNOWN и придёт владельцу алертом с кодом —
# это и есть способ узнать пару, не гадая.
WINDOW_CODES: set[tuple[int, int]] = set()
DUPLICATE_CODES: set[tuple[int, int]] = set()


class MetaError(Exception):
    """Ошибка Graph API в разобранном виде: по ней принимается решение о ретрае."""

    def __init__(self, status: int, code: int | None, subcode: int | None, message: str):
        self.status = status
        self.code = code
        self.subcode = subcode
        self.message = message
        super().__init__(f"Meta {status} code={code} sub={subcode}: {message}")


_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    """Единственный HTTP-клиент сервиса. Тест подменяет его транспортом, а не сетью."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC)
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# ---------- Ответы человеку ----------


async def reply_to_comment(comment_id: str, text: str, token: str) -> str:
    """Публичный ответ под комментарием. Возвращает id ответа."""
    data = await _post(
        f"{GRAPH_HOST}/{IG_GRAPH_VERSION}/{comment_id}/replies",
        data={"message": _fit(text), "access_token": token},
    )
    return str(data.get("id") or "")


async def send_private_reply(comment_id: str, text: str, buttons: list, token: str) -> str:
    """Private reply на комментарий: окно 7 суток и РОВНО ОДНО сообщение на комментарий.

    Второй такой отправки не бывает по определению — платформа её запрещает, поэтому
    вызов защищён и уникальностью (source, source_id), и проверкой dm_message_id.
    """
    return await _message({"comment_id": str(comment_id)}, text, buttons, token)


async def send_direct_message(igsid: str, text: str, buttons: list, token: str) -> str:
    """Ответ в диалоге: человек написал сам, окно 24 часа с его сообщения."""
    return await _message({"id": str(igsid)}, text, buttons, token)


async def _message(recipient: dict, text: str, buttons: list, token: str) -> str:
    body = {
        "recipient": recipient,
        "message": _payload(text, buttons),
        "access_token": token,
    }
    data = await _post(f"{GRAPH_HOST}/{IG_GRAPH_VERSION}/me/messages", json_body=body)
    return str(data.get("message_id") or "")


def _payload(text: str, buttons: list) -> dict:
    """Текст или button template. Кнопок нет — уходит обычный текст, как раньше."""
    items = normalize_buttons(buttons)
    if not items:
        return {"text": _fit(text)}
    return {
        "attachment": {
            "type": "template",
            "payload": {"template_type": "button", "text": _fit(text), "buttons": items},
        }
    }


def normalize_buttons(buttons: Any) -> list[dict]:
    """[{title,url}] → кнопки web_url. Лишнее и кривое отбрасываем, а не отправляем."""
    if not isinstance(buttons, list):
        return []
    items = []
    for raw in buttons[:MAX_BUTTONS]:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or "")
        title = str(raw.get("title") or "").strip()
        if not title or not url.startswith("https://"):
            continue
        items.append({"type": "web_url", "url": url, "title": title[:MAX_BUTTON_TITLE]})
    return items


def _fit(text: str) -> str:
    """Последний рубеж лимита — на строке, которая реально уходит в Meta.

    Сюда доходить не должно: правило с длинным худшим раскрытием отсекается раньше
    (rules.unconfigured), поэтому срабатывание здесь — повод посмотреть в правило.
    """
    out = clip(text)
    if out != (text or ""):
        log.warning(
            "текст обрезан по лимиту платформы: %s байт → %s",
            len((text or "").encode("utf-8")),
            MAX_MESSAGE_BYTES,
        )
    return out


# ---------- Токен ----------


async def refresh_token(token: str) -> tuple[str, int]:
    """Продление long-lived токена. Возвращает (новый токен, секунд жизни).

    Ограничения платформы: токен должен быть старше 24 часов и ещё живым;
    непродлённый 60 дней умирает НАВСЕГДА — восстанавливается только ручным re-auth.
    """
    url = f"{GRAPH_HOST}/refresh_access_token"
    try:
        resp = await client().get(
            url, params={"grant_type": "ig_refresh_token", "access_token": token}
        )
    except httpx.HTTPError as exc:
        raise _transport(exc, url) from exc
    data = _unwrap(resp, url)
    return str(data.get("access_token") or ""), int(data.get("expires_in") or 0)


# ---------- Алерт владельцу ----------


async def alert_owner(text: str) -> None:
    """Аварийный сигнал в бот. Через web не идём — лишнее звено на пути аварийного сигнала.

    Молчать здесь нельзя: тихая деградация в этой механике неотличима от «всё работает»,
    потому что отсутствие DM никто не наблюдает. Если отправить не удалось — пишем ERROR,
    это единственный оставшийся канал.
    """
    log.warning("алерт владельцу: %s", text)
    if not IG_ALERT_TG_USER_ID.isdigit() or not IG_ALERT_TOKEN:
        log.error("алерт отправить некому: не задан IG_ALERT_TG_USER_ID или IG_ALERT_TOKEN")
        return
    try:
        resp = await client().post(
            f"{TELEGRAM_SERVICE_URL}/bot/send",
            json={"tg_user_id": int(IG_ALERT_TG_USER_ID), "text": text},
            headers={"X-Internal-Token": IG_ALERT_TOKEN},
            timeout=10,
        )
        if resp.is_error:
            log.error("алерт не доставлен, бот ответил %s", resp.status_code)
    except Exception:
        log.exception("алерт не доставлен")


# ---------- Транспорт ----------


async def _post(url: str, data: dict | None = None, json_body: dict | None = None) -> dict:
    try:
        resp = await client().post(url, data=data, json=json_body)
    except httpx.HTTPError as exc:
        raise _transport(exc, url) from exc
    return _unwrap(resp, url)


def _transport(exc: httpx.HTTPError, url: str) -> MetaError:
    """Сетевой сбой — это 0 в статусе: ретраится, но кодом Meta не притворяется."""
    return MetaError(0, None, None, f"{type(exc).__name__} на {safe_url(url)}")


def _unwrap(resp: httpx.Response, url: str) -> dict:
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    error = data.get("error")
    if resp.is_error or isinstance(error, dict):
        error = error if isinstance(error, dict) else {}
        # Тело ответа дословно не цитируем НИКОГДА: у продления токен лежит в query-строке,
        # и страница промежуточного прокси, эхом отдающая URL, утащила бы его в лог и в алерт.
        # В сообщении только то, что Graph положил в error.message.
        message = str(error.get("message") or "")[:500]
        if not message:
            message = f"нераспознанный ответ ({len(resp.content)} байт) от {safe_url(url)}"
        raise MetaError(
            resp.status_code, _int(error.get("code")), _int(error.get("error_subcode")), message
        )
    return data


def safe_url(url: str) -> str:
    """URL без query: у продления в ней лежит токен."""
    return url.split("?", 1)[0]


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def classify(exc: Exception) -> str:
    """Что делать с отказом. Решение — по кодам; текст ответа только подсказка в лог."""
    if not isinstance(exc, MetaError):
        return RETRY  # неизвестное исключение — считаем сбоем среды, но попытки считаем
    pair = (exc.code, exc.subcode)
    if exc.code in TOKEN_CODES:
        # Системный отказ: отправлять нечем НИЧЕМ, а не только этой доставкой.
        return TOKEN_INVALID
    if exc.code in RATE_CODES or exc.status == 429:
        return RATE_LIMIT
    if pair in TERMINAL_CODES:
        return TERMINAL
    if pair in WINDOW_CODES:
        return EXPIRED
    if pair in DUPLICATE_CODES:
        # Meta уже доставила это сообщение: ретрай запрещён платформой, а FAILED соврал бы.
        return ALREADY_DONE
    if exc.status == 0 or exc.status >= 500:
        return RETRY
    _hint(exc)
    return TERMINAL_UNKNOWN


def _hint(exc: "MetaError") -> None:
    """Подсказка в лог, на что ПОХОЖ незнакомый отказ. Решением не является."""
    lowered = exc.message.lower()
    if "window" in lowered or "already" in lowered:
        log.warning(
            "незнакомый код %s/%s похож на окно или на повторную отправку — "
            "впишите пару в WINDOW_CODES/DUPLICATE_CODES после зонда",
            exc.code,
            exc.subcode,
        )
