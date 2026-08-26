import os
from pathlib import Path

from dotenv import load_dotenv

# .env лежит в корне монорепо
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
load_dotenv()  # локальный .env сервиса: без override= он лишь ДОБАВЛЯЕТ недостающее

# App Secret приложения Meta: им подписан вебхук (не verify token).
# Пустой секрет НЕ открывает роут, а закрывает его — см. signature.verify_signature.
IG_APP_SECRET = os.environ.get("IG_APP_SECRET", "")
IG_VERIFY_TOKEN = os.environ.get("IG_VERIFY_TOKEN", "")

# В проде URL собирается из IG_DB_PASSWORD в docker-compose.prod.yml; локально — из .env.
# Роль ig_service: без прав на схему public, search_path = instagram.
IG_DATABASE_URL = os.environ.get("IG_DATABASE_URL", "")

# Ретеншен сырого журнала. Окно РЕТРАЯ Meta измеряется часами, поэтому ключам дедупликации
# 30 суток хватает с многократным запасом; срок выбран из полезности журнала для разбора
# (7 суток private reply — это про ig_delivery этапа 2, другая таблица).
EVENT_RETENTION_DAYS = 30

# ---------- Этап 2: правила и доставка ----------

# Свой Instagram-аккаунт: комментарий от него самого пропускается, иначе сервис
# отвечает на собственный публичный ответ и уходит в петлю.
IG_USER_ID = os.environ.get("IG_USER_ID", "")
IG_GRAPH_VERSION = os.environ.get("IG_GRAPH_VERSION", "v25.0")

# Первичная загрузка токена: значение переезжает в instagram.ig_token зашифрованным и
# дальше НЕ участвует ни в чём — сервис продлевает токен сам, а источник правды — таблица.
# Засев происходит, только когда строки в таблице ещё нет.
#
# Починка после протухания (и после смены IG_TOKEN_KEY — тогда строка перестаёт
# расшифровываться) РОВНО в таком порядке, иначе рестарт ничего не изменит:
#   1) docker compose -f docker-compose.prod.yml exec -T postgres \
#        psql -U ig -d ig -c "delete from instagram.ig_token"
#   2) положить свежий токен в IG_ACCESS_TOKEN
#   3) docker compose -f docker-compose.prod.yml up -d instagram-service
IG_ACCESS_TOKEN = os.environ.get("IG_ACCESS_TOKEN", "")
# Ключ конверта для токена (sha256 от него). Отдельный от AUTH_SECRET намеренно —
# обоснование в шапке tokens.py. Пустой ключ ничего не шифрует, а бросает.
IG_TOKEN_KEY = os.environ.get("IG_TOKEN_KEY", "")

# Аварийный сигнал владельцу идёт напрямую в telegram-service, минуя web:
# лишнее звено на пути сигнала о том, что механика встала.
IG_ALERT_TG_USER_ID = os.environ.get("IG_ALERT_TG_USER_ID", "")
TELEGRAM_SERVICE_URL = os.environ.get("TELEGRAM_SERVICE_URL", "http://telegram-service:8010")
# Узкий токен ровно под POST /bot/send, а НЕ общий INTERNAL_TOKEN. Общим ключом middleware
# telegram-service пускает во все роуты (переписка менеджера, сканирование диалогов, привязка
# аккаунтов), и роуты web — тоже. Интернет-обращённому контейнеру такой ключ давать нельзя:
# этап 1 специально убрал отсюда общий набор секретов, здесь то же самое решение.
IG_ALERT_TOKEN = os.environ.get("IG_ALERT_TOKEN", "")


def _positive_int(name: str, default: int) -> int:
    """Кривое значение не роняет старт: приёмник вебхуков важнее темпа отправки."""
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else default


# Потолок отправок в минуту: виральный пост не должен упереть аккаунт в лимиты Meta.
IG_DISPATCH_RATE = _positive_int("IG_DISPATCH_RATE", 20)
# Потолок отправок в сутки. Темп ограничивает скорость, бюджет — объём: сотня одноразовых
# аккаунтов с ключевым словом под открытым постом иначе превращает механику в рассылку,
# и рискует этим аккаунт владельца, а не наш сервер. 0 — снять ограничение.
# 50 — значение на ПЕРВУЮ кампанию: радиус любой ошибки классификации ограничен объёмом,
# а поднять число, увидев живую механику, дешевле, чем объясняться с платформой.
IG_DAILY_DM_LIMIT = _positive_int("IG_DAILY_DM_LIMIT", 50)

# IG_APP_ID читает только человек при настройке приложения — сервису он не нужен.
