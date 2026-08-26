"""Сверка секретов Meta постоянным временем: подпись вебхука и verify token."""

import hashlib
import hmac

PREFIX = "sha256="


def constant_time_eq(a: str, b: str) -> bool:
    """compare_digest только по байтам.

    На str он требует ASCII в ОБОИХ аргументах и иначе бросает TypeError: не-ASCII
    в заголовке подписи или в IG_VERIFY_TOKEN превратился бы в 500 с публичного адреса,
    а 500 Meta ретраит до отключения подписки.
    """
    return hmac.compare_digest(
        a.encode("utf-8", "surrogateescape"), b.encode("utf-8", "surrogateescape")
    )


def verify_signature(raw_body: bytes, header: str | None, app_secret: str) -> bool:
    """HMAC-SHA256 от СЫРОГО тела запроса с ключом App Secret.

    Тело обязано быть теми же байтами, что пришли по сети: пересериализованный
    JSON даёт другую подпись. Пустой секрет закрывает роут целиком (fail-closed),
    как пустой verify token закрывает handshake.
    """
    if not app_secret or not header or not header.startswith(PREFIX):
        return False
    expected = hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return constant_time_eq(expected, header[len(PREFIX) :])


def verify_token(given: str | None, expected: str) -> bool:
    """Сверка hub.verify_token на handshake. Пустой ожидаемый токен — всегда отказ."""
    if not expected or not given:
        return False
    return constant_time_eq(given, expected)
