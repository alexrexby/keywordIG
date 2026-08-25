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

# IG_APP_ID, IG_USER_ID, IG_GRAPH_VERSION, IG_ALERT_TG_USER_ID, IG_DISPATCH_RATE
# заводятся на проде уже сейчас (.env.example), но читает их этап 2 — приёмник
# ничего в Meta не отправляет и правил не знает.
