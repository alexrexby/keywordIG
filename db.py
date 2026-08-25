"""Postgres схемы instagram: пул, мигратор, журнал событий. Прямые запросы, ORM нет."""

import asyncio
import logging
import time
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from config import EVENT_RETENTION_DAYS, IG_DATABASE_URL

log = logging.getLogger("db")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
# Роль и схему заводит суперюзер (scripts/deploy.sh до up -d), сервису это не по правам.
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

    Необработанное не выбрасываем: диспетчер этапа 2 может стоять на паузе (мёртвый токен —
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
