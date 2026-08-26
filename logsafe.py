"""Затирание секретов в логах — централизованно, а не точечными настройками уровней.

Зачем отдельным модулем. Meta требует передавать токен продления в АДРЕСЕ запроса
(`GET /refresh_access_token?access_token=…`), а httpx на уровне INFO печатает адрес
целиком. Мы уже глушили access-лог uvicorn и перестали цитировать тела ответов — и всё
равно получили токен в `docker logs`, потому что напечатала его третья сторона.
Точечная настройка уровня спасает от ИЗВЕСТНОЙ библиотеки; фильтр на обработчике
логирования спасает и от следующей, которую добавят завтра.

Фильтр вешается на обработчики корневого логгера: фильтр на самом логгере записи
дочерних логгеров (httpx, uvicorn, psycopg) не увидит — они идут в обработчик напрямую.
"""

import logging
import re

# Секрет в параметре адреса или в теле сообщения. Значение режется до первого разделителя.
SECRET_PARAM = re.compile(
    r"(?i)\b(access_token|client_secret|app_secret|verify_token|hub\.verify_token)=([^&\s\"'<>]+)"
)
# Токен Instagram узнаётся и без имени параметра: у него собственный префикс.
BARE_TOKEN = re.compile(r"\bIGAA[A-Za-z0-9_\-]{10,}")
MASK = "<скрыто>"

# Болтливые библиотеки: печатают адрес запроса на INFO. Уровень поднимаем, но полагаться
# на это нельзя — фильтр ниже закрывает и то, что мы не предусмотрели.
NOISY = ("httpx", "httpcore")


def redact(text: str) -> str:
    text = SECRET_PARAM.sub(lambda m: f"{m.group(1)}={MASK}", text)
    return BARE_TOKEN.sub(MASK, text)


class Redactor(logging.Filter):
    """Затирает секреты в УЖЕ собранном сообщении записи.

    Именно в собранном, а не в шаблоне: затирание в record.msg съедает плейсхолдер
    («access_token=%s» → «access_token=<скрыто>»), после чего args остаются лишними,
    logging падает на форматировании и ТЕРЯЕТ запись целиком. Поймано положительным
    контролем — фильтр, роняющий логи, хуже утечки, ради которой он написан.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            text = record.getMessage()
        except Exception:
            return True  # кривая запись — не наша забота, ломать её нельзя
        cleaned = redact(text)
        if cleaned != text:
            record.msg = cleaned
            record.args = ()
        return True


def install() -> None:
    """Идемпотентно: поднять уровень болтливых библиотек и повесить фильтр на обработчики.

    Обработчики НЕ создаёт: basicConfig ничего не делает, если они уже есть, и создание
    обработчика здесь тихо отменило бы `basicConfig(level=INFO)` вызывающего.
    """
    for name in NOISY:
        logging.getLogger(name).setLevel(logging.WARNING)
    root = logging.getLogger()
    for handler in root.handlers:
        if not any(isinstance(f, Redactor) for f in handler.filters):
            handler.addFilter(Redactor())
