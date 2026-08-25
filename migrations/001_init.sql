-- Сырое событие Meta. Единственный источник правды о том, что реально пришло.
-- Пишется ДО любой бизнес-логики, включая события, для которых правила нет.
-- Таблицу schema_migrations заводит сам мигратор (db.py) до применения файлов —
-- иначе первая же миграция не смогла бы отметить сама себя.
CREATE TABLE instagram.ig_event (
  id            bigserial PRIMARY KEY,
  field         text        NOT NULL,        -- 'comments' | 'messages' | иное
  event_key     text        NOT NULL,        -- comment_id | mid
  signature_ok  boolean     NOT NULL,
  payload       jsonb       NOT NULL,
  received_at   timestamptz NOT NULL DEFAULT now(),
  processed_at  timestamptz,
  UNIQUE (field, event_key)                  -- дедупликация повторной доставки
);
CREATE INDEX ON instagram.ig_event (received_at DESC);
CREATE INDEX ON instagram.ig_event (id) WHERE processed_at IS NULL;
