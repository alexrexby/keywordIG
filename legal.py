"""Публичные страницы установки: политика конфиденциальности и удаление данных.

Они обязательны не для красоты. Публикацию приложения Meta блокирует пустой
privacy policy URL, а неопубликованное приложение не присылает вебхуков вовсе — и
выглядит это как «сервис не работает». Отдаёт их сам сервис, чтобы адрес не зависел
от чужого хостинга и не протухал отдельно от установки.

РЕНДЕР FAIL-CLOSED. Не хватает обязательного реквизита — 503 с перечнем незаполненного,
а не страница, где на месте имени владельца пусто. Тот же приём, что rules.unconfigured():
недонастроенное людям не показывается. Причина здесь та же, что у правил: документ
с дырой хуже отсутствующего документа — его прочитают и поверят.

Срок хранения обращений в текст НЕ вписывается руками: он берётся из той же переменной,
по которой сервис реально удаляет карточки (config.DELIVERY_RETENTION_DAYS,
db.purge_old_deliveries). Два источника — число в коде и срок в документе — разъезжаются
на первой правке, и тогда политика обещает то, чего установка не делает.

Ни авторизации, ни редиректов, ни cookie: страницу открывает проверяющий Meta, а не
владелец. Удаляется одной строкой include_router в main.py вместе с этим файлом и
двумя шаблонами.
"""

import logging
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from config import (
    DELIVERY_RETENTION_DAYS,
    EVENT_RETENTION_DAYS,
    OWNER_ACCOUNT,
    OWNER_ADDRESS,
    OWNER_CONTACT_EMAIL,
    OWNER_LEGAL_NAME,
    OWNER_POLICY_UPDATED,
    OWNER_SERVICE_NAME,
    OWNER_TAX_ID,
)
log = logging.getLogger("legal")

# Своё окружение шаблонов, а не общее с панелью: публичные страницы обязаны пережить
# удаление панели, а панель — удаление публичных страниц. Стоит это четырёх строк,
# а связка стоила бы каскадного падения.
TEMPLATES = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
    autoescape=select_autoescape(("html",)),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)

router = APIRouter()

# Что обязано быть заполнено, чтобы страницу вообще показывать. Имя переменной → зачем.
# ИНН и почтовый адрес сюда не входят намеренно: у частного лица ИНН может отсутствовать
# законно, и строка о нём просто не печатается, — а вот документ без ответственного
# и без адреса для обращений не документ.
REQUIRED = {
    "OWNER_SERVICE_NAME": "как называется то, что стоит на этом домене",
    "OWNER_ACCOUNT": "аккаунт в Instagram, который обслуживает установка",
    "OWNER_LEGAL_NAME": "кто отвечает за данные: юрлицо, ИП или человек",
    "OWNER_CONTACT_EMAIL": "почта для обращений, её читает живой человек",
}


def _values() -> dict:
    return {
        "OWNER_SERVICE_NAME": OWNER_SERVICE_NAME,
        "OWNER_ACCOUNT": OWNER_ACCOUNT,
        "OWNER_LEGAL_NAME": OWNER_LEGAL_NAME,
        "OWNER_CONTACT_EMAIL": OWNER_CONTACT_EMAIL,
    }


def _missing() -> list[str]:
    return [name for name, value in _values().items() if not value]


def _page(name: str) -> HTMLResponse:
    missing = _missing()
    if missing:
        # 503, а не 200 с пустотами: страница-полуфабрикат уедет в дашборд Meta, будет
        # там принята и останется публичным документом установки навсегда.
        log.error("публичная страница не отдана: не заполнено %s", ", ".join(missing))
        return HTMLResponse(
            TEMPLATES.get_template("legal_unset.html").render(
                missing=[{"name": name, "why": REQUIRED[name]} for name in missing]
            ),
            status_code=503,
        )
    return HTMLResponse(
        TEMPLATES.get_template(name).render(
            service=OWNER_SERVICE_NAME,
            account=OWNER_ACCOUNT,
            operator=OWNER_LEGAL_NAME,
            email=OWNER_CONTACT_EMAIL,
            tax_id=OWNER_TAX_ID,
            address=OWNER_ADDRESS,
            updated=OWNER_POLICY_UPDATED,
            retention_days=DELIVERY_RETENTION_DAYS,
            event_days=EVENT_RETENTION_DAYS,
        )
    )


@router.get("/privacy", response_class=HTMLResponse)
async def privacy():
    return _page("privacy.html")


@router.get("/data-deletion", response_class=HTMLResponse)
async def data_deletion():
    return _page("data_deletion.html")
