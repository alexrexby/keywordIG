"""Postgres схемы instagram: пул, мигратор, журнал событий. Прямые запросы, ORM нет."""

import asyncio
import logging
import time
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from config import EVENT_RETENTION_DAYS, IG_DATABASE_URL

log = logging.getLogger("db")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
# Роль и схему заводит суперюзер при первом старте Postgres (файл смонтирован в
# /docker-entrypoint-initdb.d), сервису это не по правам — мигратор его пропускает.
BOOTSTRAP_SQL = "000_role.sql"
# Два контейнера сервиса не должны поехать миграциями одновременно.
MIGRATION_LOCK_KEY = 8020_2608
LOCK_WAIT_SEC = 60

pool: AsyncConnectionPool | None = None


def make_pool() -> AsyncConnectionPool:
    if not IG_DATABASE_URL:
        raise RuntimeError("IG_DATABASE_URL пуст — сервис не поднимается без БД")
    # timeout: вебхук не должен висеть 30 с (дефолт пула) — Meta столько не ждёт, она ретраит.
    # check: Postgres перезапускается на каждом деплое, без проверки пул отдаст мёртвое
    # соединение и первая же доставка после рестарта потеряется в 503.
    return AsyncConnectionPool(
        IG_DATABASE_URL,
        min_size=1,
        max_size=4,
        open=False,
        timeout=5,
        check=AsyncConnectionPool.check_connection,
        kwargs={"connect_timeout": 5},
    )


def pool_ref() -> AsyncConnectionPool:
    if pool is None:
        raise RuntimeError("пул не открыт — lifespan не отработал")
    return pool


async def migrate() -> list[str]:
    """Применяет невыполненные .sql под advisory-lock. Возвращает применённые версии."""
    applied: list[str] = []
    # Лок сессионный: его снимает закрытие соединения на выходе из async with,
    # отдельный unlock в finally только заслонял бы собой настоящую ошибку миграции.
    async with await psycopg.AsyncConnection.connect(
        IG_DATABASE_URL, autocommit=True, connect_timeout=5
    ) as conn:
        await take_lock(conn)
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS instagram.schema_migrations ("
            " version text PRIMARY KEY,"
            " applied_at timestamptz NOT NULL DEFAULT now())"
        )
        cur = await conn.execute("SELECT version FROM instagram.schema_migrations")
        done = {row[0] for row in await cur.fetchall()}
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if path.name == BOOTSTRAP_SQL or path.name in done:
                continue
            log.info("миграция %s: применяю", path.name)
            async with conn.transaction():
                await conn.execute(path.read_text(encoding="utf-8"))
                await conn.execute(
                    "INSERT INTO instagram.schema_migrations (version) VALUES (%s)",
                    (path.name,),
                )
            applied.append(path.name)
    return applied


async def take_lock(conn) -> None:
    """pg_try_advisory_lock с дедлайном вместо бесконечного ожидания.

    Ждущий вечно pg_advisory_lock вешает lifespan ДО yield: uvicorn не слушает порт,
    healthcheck рестарта не вызывает, наружу это 502 от Caddy без единой строки в логах.
    Лучше упасть с внятной ошибкой — рестарт контейнера сам повторит попытку.
    """
    deadline = time.monotonic() + LOCK_WAIT_SEC
    while True:
        cur = await conn.execute("SELECT pg_try_advisory_lock(%s)", (MIGRATION_LOCK_KEY,))
        if (await cur.fetchone())[0]:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"миграции заняты другим инстансом дольше {LOCK_WAIT_SEC} с")
        await asyncio.sleep(1)


async def insert_events(events: list[tuple[str, str, dict]]) -> int:
    """Пишет пачку событий, возвращает число НОВЫХ (остальные — повтор доставки).

    Одно соединение на запрос: батч Meta не должен выедать пул на 4 соединения.
    Коммит на событие: частично упавший батч при ретрае допишется, а уже записанное
    упрётся в ON CONFLICT — Meta ретраит агрессивно, повтор это норма, а не ошибка.
    signature_ok всегда true: неподписанное сюда не доходит, подпись стоит воротами в main.
    """
    fresh = 0
    async with pool_ref().connection() as conn:
        for field, event_key, payload in events:
            async with conn.transaction():
                cur = await conn.execute(
                    "INSERT INTO instagram.ig_event (field, event_key, signature_ok, payload)"
                    " VALUES (%s, %s, true, %s) ON CONFLICT (field, event_key) DO NOTHING",
                    (field, event_key, Jsonb(payload)),
                )
            if cur.rowcount > 0:
                fresh += 1
    return fresh


async def purge_old_events() -> int:
    """Ретеншен журнала: старше EVENT_RETENTION_DAYS и УЖЕ обработанное.

    Необработанное не выбрасываем: диспетчер может стоять на паузе (мёртвый токен —
    штатный сценарий плана), и тогда эта строка — единственный след, что комментарий
    приходил и остался без ответа.
    """
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "DELETE FROM instagram.ig_event"
            " WHERE received_at < now() - make_interval(days => %s)"
            "   AND processed_at IS NOT NULL",
            (EVENT_RETENTION_DAYS,),
        )
        return cur.rowcount


# ---------- Правила и доставка ----------
# Весь SQL сервиса живёт здесь: прямые запросы, значения только через %s.
# Форма claim'а обычная для очереди на Postgres: FOR UPDATE SKIP LOCKED.


async def load_rules(conn) -> list[dict]:
    """Включённые правила целиком: их единицы, а порядок выбора решает rules.match_rule."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id, name, \"trigger\", media_id, keywords, match_mode, priority,"
            "       public_replies, duplicate_replies, dm_text, dm_buttons"
            "  FROM instagram.ig_rule WHERE enabled"
        )
        return await cur.fetchall()


async def load_rule(rule_id: int) -> dict | None:
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id, name, \"trigger\", media_id, keywords, match_mode, priority,"
                "       public_replies, duplicate_replies, dm_text, dm_buttons"
                "  FROM instagram.ig_rule WHERE id = %s AND enabled",
                (rule_id,),
            )
            return await cur.fetchone()


async def claim_event(conn) -> dict | None:
    """Забирает одно необработанное подписанное событие. Только signature_ok:
    поддельное событие не должно становиться командой на отправку сообщения человеку."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "UPDATE instagram.ig_event SET processed_at = now()"
            " WHERE id = ("
            "   SELECT id FROM instagram.ig_event"
            "    WHERE processed_at IS NULL AND signature_ok"
            "    ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)"
            " RETURNING id, field, event_key, payload, received_at"
        )
        return await cur.fetchone()


async def insert_delivery(conn, cand, rule_id: int | None, state: str) -> int | None:
    """Строка доставки. None — доставка по этому источнику уже есть (повтор вебхука).

    UNIQUE (source, source_id) и есть гарантия «одно private reply на комментарий»:
    вторая доставка по тому же comment_id физически не заводится.
    """
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO instagram.ig_delivery"
            " (source, source_id, rule_id, igsid, username, media_id, source_text,"
            "  state, expires_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (source, source_id) DO NOTHING RETURNING id",
            (
                cand.source,
                cand.source_id,
                rule_id,
                cand.igsid,
                cand.username,
                cand.media_id,
                cand.text[:2000],
                state,
                cand.expires_at,
            ),
        )
        row = await cur.fetchone()
        return row[0] if row else None


async def mark_event_processed(event_id: int) -> None:
    """Событие, на котором разбор упал, помечается обработанным отдельной транзакцией.

    Иначе одна ядовитая строка вечно занимает голову очереди и блокирует доставку всем
    остальным: транзакция intake откатывается вместе с processed_at, и круг повторяется.
    """
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_event SET processed_at = now() WHERE id = %s", (event_id,)
        )


async def claim_delivery() -> dict | None:
    """Атомарно забирает одну готовую доставку — форма claimJob из queue.ts."""
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "UPDATE instagram.ig_delivery"
                "   SET state = 'CLAIMED', attempts = attempts + 1, updated_at = now()"
                " WHERE id = ("
                "   SELECT id FROM instagram.ig_delivery"
                "    WHERE state = 'PENDING' AND run_after <= now()"
                "    ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)"
                " RETURNING id, source, source_id, rule_id, igsid, username, media_id,"
                "           attempts, expires_at, public_reply_id, dm_message_id, dm_attempts"
            )
            return await cur.fetchone()


async def reserve_contact_rule(rule_id: int, igsid: str, delivery_id: int) -> int:
    """Резервация пары (правило, человек) ДО отправки. Возвращает id доставки-владельца.

    Не равен нашему — материал этому человеку по этому правилу уже выдали (или выдаёт
    параллельная доставка). Отметка ПОСЛЕ отправки от гонки не спасает, поэтому здесь
    именно резервация.
    """
    async with pool_ref().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO instagram.ig_contact_rule (rule_id, igsid, delivery_id)"
                " VALUES (%s, %s, %s) ON CONFLICT (rule_id, igsid) DO NOTHING"
                " RETURNING delivery_id",
                (rule_id, igsid, delivery_id),
            )
            row = await cur.fetchone()
            if row:
                return row[0]
            await cur.execute(
                "SELECT delivery_id FROM instagram.ig_contact_rule"
                " WHERE rule_id = %s AND igsid = %s",
                (rule_id, igsid),
            )
            row = await cur.fetchone()
            return row[0] if row else delivery_id


async def release_contact_rule(rule_id: int, igsid: str, delivery_id: int) -> int:
    """Снимает ТОЛЬКО свою резервацию и ТОЛЬКО если DM доказанно не уходил.

    Иначе терминальный отказ запирает человека от материала навсегда: следующий его
    комментарий получит публичное «уже отправила», хотя не отправляли.

    Условий два, и второе важнее первого: dm_attempts = 0 означает «к Meta с этим
    сообщением не ходили ни разу». Пустого dm_message_id мало — он пуст и когда ответ
    Meta потерян, а сообщение доставлено; снятая в этом случае бронь выдаёт материал дважды.
    """
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "DELETE FROM instagram.ig_contact_rule c"
            " USING instagram.ig_delivery d"
            " WHERE c.rule_id = %s AND c.igsid = %s AND c.delivery_id = %s"
            "   AND d.id = c.delivery_id AND d.dm_message_id IS NULL AND d.dm_attempts = 0",
            (rule_id, igsid, delivery_id),
        )
        return cur.rowcount


async def mark_public_reply(delivery_id: int, reply_id: str) -> None:
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_delivery"
            "   SET state = 'REPLIED_PUBLIC', public_reply_id = %s, updated_at = now()"
            " WHERE id = %s",
            (reply_id, delivery_id),
        )


async def note_dm_attempt(delivery_id: int) -> None:
    """Отметка «идём отправлять» ДО запроса в Meta. Короткая запись, транзакция через сеть
    не живёт. С этого момента «ответа не видели» перестаёт означать «не отправляли»."""
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_delivery"
            "   SET dm_attempts = dm_attempts + 1, updated_at = now() WHERE id = %s",
            (delivery_id,),
        )


async def clear_dm_attempt(delivery_id: int) -> None:
    """Meta ОТВЕТИЛА отказом с кодом — исход известен: сообщение не ушло.

    Метка неизвестности снимается, иначе условие «dm_attempts = 0» в release_contact_rule
    делает бронь вечной на любом отказе, а не только на по-настоящему неизвестном.
    """
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_delivery SET dm_attempts = 0, updated_at = now() WHERE id = %s",
            (delivery_id,),
        )


async def mark_dm_sent(delivery_id: int, message_id: str) -> None:
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_delivery"
            "   SET state = 'SENT_DM', dm_message_id = %s, updated_at = now()"
            " WHERE id = %s",
            (message_id, delivery_id),
        )


async def finish_delivery(delivery_id: int, state: str, error: str | None = None) -> None:
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_delivery"
            "   SET state = %s, last_error = %s, updated_at = now() WHERE id = %s",
            (state, error, delivery_id),
        )


async def reschedule_delivery(
    delivery_id: int, delay_sec: float, error: str | None, count_attempt: bool
) -> None:
    """Возврат в очередь с задержкой. count_attempt=False откатывает инкремент claim'а:
    лимит темпа Meta и мёртвый токен — не вина этой доставки, жечь её попытки нельзя."""
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_delivery"
            "   SET state = 'PENDING', last_error = %s, attempts = attempts - %s,"
            "       run_after = now() + make_interval(secs => %s), updated_at = now()"
            " WHERE id = %s",
            (error, 0 if count_attempt else 1, delay_sec, delivery_id),
        )


async def recover_stuck_deliveries() -> int:
    """Доставки, зависшие в работе дольше 30 минут (упавший процесс), — назад в очередь.

    REPLIED_PUBLIC и SENT_DM здесь обязательны наравне с CLAIMED: смерть процесса между
    публичным ответом и директом иначе оставляла бы строку навсегда — под постом висит
    «отправила в директ», а директа нет, и ни ретрая, ни FAILED, ни алерта.
    Повторно отправить уже отправленное не дают public_reply_id/dm_message_id: шаги,
    у которых есть id ответа Meta, при повторном проходе пропускаются.
    """
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "UPDATE instagram.ig_delivery SET state = 'PENDING', updated_at = now()"
            " WHERE state IN ('CLAIMED', 'REPLIED_PUBLIC', 'SENT_DM')"
            "   AND updated_at < now() - interval '30 minutes'"
        )
        return cur.rowcount


async def count_failed_since(minutes: int) -> int:
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM instagram.ig_delivery"
            " WHERE state = 'FAILED' AND updated_at > now() - make_interval(mins => %s)",
            (minutes,),
        )
        return (await cur.fetchone())[0]


async def count_pending() -> int:
    """Сколько доставок ждёт отправки. Пауза при непустой очереди — повод для алерта."""
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM instagram.ig_delivery WHERE state = 'PENDING'"
        )
        return (await cur.fetchone())[0]


async def count_dm_sent_since(hours: int) -> int:
    """Сколько сообщений реально ушло за окно. Это бюджет аккаунта, а не темп сервера."""
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM instagram.ig_delivery"
            " WHERE dm_message_id IS NOT NULL AND updated_at > now() - make_interval(hours => %s)",
            (hours,),
        )
        return (await cur.fetchone())[0]


# ---------- Токен ----------


async def load_token() -> dict | None:
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT ig_user_id, token_enc, scopes, expires_at, refreshed_at,"
                "       invalid_at, last_error, updated_at"
                "  FROM instagram.ig_token WHERE id = 1"
            )
            return await cur.fetchone()


async def save_token(ig_user_id: str, token_enc: str, expires_at, refreshed_at) -> None:
    """Запись токена снимает паузу: новый токен — это и есть починка."""
    async with pool_ref().connection() as conn:
        await conn.execute(
            "INSERT INTO instagram.ig_token (id, ig_user_id, token_enc, expires_at, refreshed_at)"
            " VALUES (1, %s, %s, %s, %s)"
            " ON CONFLICT (id) DO UPDATE SET ig_user_id = EXCLUDED.ig_user_id,"
            "   token_enc = EXCLUDED.token_enc, expires_at = EXCLUDED.expires_at,"
            "   refreshed_at = EXCLUDED.refreshed_at, invalid_at = NULL, last_error = NULL,"
            "   updated_at = now()",
            (ig_user_id, token_enc, expires_at, refreshed_at),
        )


async def mark_token_invalid(reason: str) -> None:
    """invalid_at ставится один раз: он же метка «когда механика встала»."""
    async with pool_ref().connection() as conn:
        await conn.execute(
            "UPDATE instagram.ig_token"
            "   SET invalid_at = coalesce(invalid_at, now()), last_error = %s, updated_at = now()"
            " WHERE id = 1",
            (reason,),
        )


# ---------- Админ-API правил ----------
# CRUD для панели. Читает и пишет ТОЛЬКО instagram.ig_rule: правило — это
# единственное, что человек заводит руками. Доставки, события и токен админка не трогает.


class RuleRejected(Exception):
    """Ограничение таблицы не пустило правило. Наружу уходит человеческим текстом,
    а не CheckViolation: форма не должна показывать владельцу сырую ошибку Postgres."""


# Правило целиком, как его видит форма: то же, что читает диспетчер, плюс enabled,
# create_lead_on и метки времени — редактору нужна вся строка, а не только поля доставки.
ADMIN_RULE_COLUMNS = (
    'id, name, enabled, "trigger", media_id, keywords, match_mode, priority,'
    " public_replies, duplicate_replies, dm_text, dm_buttons, create_lead_on,"
    " created_at, updated_at"
)
# Порядок записи. Ровно эти двенадцать полей админка и меняет; id и метки времени
# ставит база. Список один на INSERT и UPDATE, чтобы они не разъехались.
ADMIN_RULE_FIELDS = (
    "name",
    "enabled",
    "trigger",
    "media_id",
    "keywords",
    "match_mode",
    "priority",
    "public_replies",
    "duplicate_replies",
    "dm_text",
    "dm_buttons",
    "create_lead_on",
)


def _rule_params(values: dict) -> tuple:
    """Значения в порядке ADMIN_RULE_FIELDS. jsonb-поле оборачивается явно."""
    return tuple(
        Jsonb(values[name]) if name == "dm_buttons" else values[name]
        for name in ADMIN_RULE_FIELDS
    )


# Что именно ловим при записи правила. Не psycopg.Error целиком: тогда отказ соединения
# превратился бы в «правило не приняла база», а это разные новости для того, кто читает.
#   IntegrityError — нарушены ограничения (CHECK, уникальность);
#   DataError      — значение не лезет в колонку (int4 вне диапазона, нулевой байт).
WRITE_ERRORS = (psycopg.errors.IntegrityError, psycopg.DataError)


def _rule_rejected(exc: psycopg.Error) -> RuleRejected:
    constraint = getattr(exc.diag, "constraint_name", "") or ""
    if exc.sqlstate == "22003":
        return RuleRejected("число не помещается в колонку: priority — 32-битное целое")
    if constraint == "ig_rule_dm_text_len":
        return RuleRejected(
            "текст DM длиннее 4096 байт в самом шаблоне — дальше его не разбирает и"
            " движок текстов (rules.MAX_TEMPLATE_BYTES). Лимит платформы тут ни при чём:"
            " он считается по худшему раскрытию и проверяется до записи."
        )
    return RuleRejected(f"правило не приняла база (ограничение {constraint or exc.sqlstate})")


async def admin_list_rules() -> list[dict]:
    """Все правила, включая выключенные: форма показывает и черновики."""
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {ADMIN_RULE_COLUMNS} FROM instagram.ig_rule"
                " ORDER BY priority DESC, id"
            )
            return await cur.fetchall()


async def admin_get_rule(rule_id: int) -> dict | None:
    """Правило по id БЕЗ фильтра enabled — в отличие от load_rule, который читает
    диспетчер: тому выключенное правило не нужно, а редактору нужно именно оно."""
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {ADMIN_RULE_COLUMNS} FROM instagram.ig_rule WHERE id = %s",
                (rule_id,),
            )
            return await cur.fetchone()


async def admin_rule_names() -> list[str]:
    """Только названия — их читает пометка копии (admin._copy_name). Тащить ради номера
    в скобках все тексты правил незачем."""
    async with pool_ref().connection() as conn:
        cur = await conn.execute("SELECT name FROM instagram.ig_rule")
        return [row[0] for row in await cur.fetchall()]


async def admin_insert_rule(values: dict) -> dict:
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            try:
                await cur.execute(
                    "INSERT INTO instagram.ig_rule"
                    ' (name, enabled, "trigger", media_id, keywords, match_mode, priority,'
                    "  public_replies, duplicate_replies, dm_text, dm_buttons, create_lead_on)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    f" RETURNING {ADMIN_RULE_COLUMNS}",
                    _rule_params(values),
                )
            except WRITE_ERRORS as exc:
                raise _rule_rejected(exc) from exc
            return await cur.fetchone()


async def admin_update_rule(rule_id: int, values: dict) -> dict | None:
    """Пишет все двенадцать полей разом: частичные правки сводит воедино админка,
    а сюда приходит уже целое правило. Динамического SQL поэтому нет вовсе."""
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            try:
                await cur.execute(
                    "UPDATE instagram.ig_rule SET"
                    '   name = %s, enabled = %s, "trigger" = %s, media_id = %s,'
                    "   keywords = %s, match_mode = %s, priority = %s,"
                    "   public_replies = %s, duplicate_replies = %s, dm_text = %s,"
                    "   dm_buttons = %s, create_lead_on = %s, updated_at = now()"
                    f" WHERE id = %s RETURNING {ADMIN_RULE_COLUMNS}",
                    _rule_params(values) + (rule_id,),
                )
            except WRITE_ERRORS as exc:
                raise _rule_rejected(exc) from exc
            return await cur.fetchone()


async def admin_copy_rule(rule_id: int, name: str) -> dict | None:
    """Копия правила ЦЕЛИКОМ, средствами базы. None — исходного правила уже нет.

    Строка размножается через to_jsonb → jsonb_populate_record, а не собирается в питоне
    из перечисленных колонок. Перечисление здесь — мина: колонка, добавленная миграцией
    завтра, в копию бы не попала, ошибку никто бы не увидел (SQL остаётся валидным), а
    вылезла бы она правилом, которое «скопировалось, но работает не так». Список колонок
    берёт сама база из типа строки.

    Подменяются ровно пять полей:
      id                      — новая строка; nextval по той же последовательности, что
                                стоит в DEFAULT (перечислив колонки явно, мы лишаемся
                                DEFAULT'ов — их применить уже не к чему);
      name                    — с пометкой копии, считает её админка;
      enabled                 — копия всегда выключена (решение — в admin.copy_rule);
      created_at, updated_at  — метки про ЭТУ строку, а не про исходную.
    Резервации ig_contact_rule («этому человеку по этому правилу уже выдавали») не
    копируются: бронь висит на паре человек+правило, у копии она своя и пустая.

    Чего конструкция не переживёт — не гадательно, а по замеру ревью (четвёртый круг):
      • колонка с UNIQUE (slug, внешний id) — копия ляжет с тем же значением, и вторая
        строка не пройдёт: IntegrityError → RuleRejected → 400 с именем ограничения.
        Ломается ГРОМКО, человек увидит отказ;
      • колонка с персональным для правила значением, но БЕЗ уникальности (секрет
        доставки, токен партнёра) — скопируется дословно, и два правила молча поделят
        один секрет. Вот это тихо, и ради этого случая здесь предупреждение: заводишь
        такую колонку — впиши её в jsonb_build_object ниже, рядом с id и name.
    Проверенное вручную и НЕ опасное: обычная новая колонка переносится сама (замысел),
    порядок колонок роли не играет (populate_record сопоставляет по имени), а тип без
    обратного преобразования через jsonb не нашёлся ни на одном из 16 проверенных.
    """
    async with pool_ref().connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            try:
                # Подзапрос не для красоты: `(f(x)).*` Postgres раскрывает в
                # `(f(x)).col1, (f(x)).col2, …` и зовёт f по разу НА КАЖДУЮ колонку.
                # Внутри стоит nextval — волатильный; замер ревью: 15 колонок = 15
                # обращений к последовательности, id прыгали 1 → 2 → 17 → 32, и владелец
                # читал в логах дыры как «кто-то удалил четырнадцать правил». Собранная
                # в подзапросе запись вычисляется один раз (в PG16 он не разворачивается),
                # и сдвиг ровно один. Инлайнить обратно нельзя: следующее волатильное
                # значение здесь дало бы РАЗНЫЕ значения в разных колонках одной строки.
                await cur.execute(
                    "INSERT INTO instagram.ig_rule"
                    " SELECT (rec).* FROM ("
                    "   SELECT jsonb_populate_record("
                    "            NULL::instagram.ig_rule,"
                    "            to_jsonb(r) || jsonb_build_object("
                    "              'id', nextval(pg_get_serial_sequence("
                    "                              'instagram.ig_rule', 'id')),"
                    "              'name', %s::text,"
                    "              'enabled', false,"
                    "              'created_at', now(),"
                    "              'updated_at', now()"
                    "            )) AS rec"
                    "   FROM instagram.ig_rule r WHERE r.id = %s"
                    " ) s"
                    f" RETURNING {ADMIN_RULE_COLUMNS}",
                    (name, rule_id),
                )
            except WRITE_ERRORS as exc:
                raise _rule_rejected(exc) from exc
            return await cur.fetchone()


async def admin_delete_rule(rule_id: int) -> bool:
    """Удаление правила уносит с собой резервации (ON DELETE CASCADE в 002) — то есть
    снимает запрет «этому человеку уже выдавали». Сколько именно, админка считает ДО
    удаления и говорит вслух: восстановить их нечем."""
    async with pool_ref().connection() as conn:
        cur = await conn.execute("DELETE FROM instagram.ig_rule WHERE id = %s", (rule_id,))
        return cur.rowcount > 0


async def admin_count_contacts(rule_id: int) -> int:
    async with pool_ref().connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM instagram.ig_contact_rule WHERE rule_id = %s", (rule_id,)
        )
        return (await cur.fetchone())[0]
