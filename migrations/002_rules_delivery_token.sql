-- Этап 2: правила, доставка, токен.
-- Три инварианта защищены схемой, а не аккуратностью кода:
--   1) одно private reply на комментарий      — UNIQUE (source, source_id) в ig_delivery;
--   2) один DM на пару (правило, человек)     — PRIMARY KEY (rule_id, igsid) в ig_contact_rule;
--   3) один Instagram-аккаунт                 — CHECK (id = 1) в ig_token.

CREATE TABLE instagram.ig_rule (
  id              bigserial   PRIMARY KEY,
  name            text        NOT NULL,
  enabled         boolean     NOT NULL DEFAULT true,
  -- trigger — зарезервированное слово Postgres, поэтому колонка в кавычках везде.
  "trigger"       text        NOT NULL DEFAULT 'COMMENT',   -- COMMENT | DM | BOTH
  media_id        text,                                     -- NULL = любой пост
  keywords        text[]      NOT NULL,                     -- сравниваются после нормализации
  match_mode      text        NOT NULL DEFAULT 'CONTAINS',  -- CONTAINS | EXACT
  priority        int         NOT NULL DEFAULT 0,
  public_replies  text[]      NOT NULL DEFAULT '{}',        -- варианты; пустой массив = не отвечать публично
  -- Ответ тому, кто написал слово повторно. Материал второй раз не уходит (запрет платформы),
  -- но молчание под постом видят посторонние — это хуже отказа.
  duplicate_replies text[]    NOT NULL DEFAULT '{}',
  dm_text         text        NOT NULL,
  dm_buttons      jsonb       NOT NULL DEFAULT '[]',        -- [{"title":"…","url":"https://…"}], максимум 3
  create_lead_on  text        NOT NULL DEFAULT 'REPLY',     -- REPLY | DM_SENT | NEVER (этап 3)
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  -- Лимит платформы на текст сообщения — в схеме, а не в комментарии: правила правят
  -- SQL-строкой в обход кода. Это первый барьер; окончательная проверка стоит на СОБРАННОЙ
  -- строке перед POST /me/messages — подставленная ссылка с utm добавляет под сотню байт.
  CONSTRAINT ig_rule_dm_text_len CHECK (octet_length(dm_text) <= 1000)
);

-- Резервация «этот человек по этому правилу уже обслужен». Вставляется ДО отправки DM:
-- отметка ПОСЛЕ не защищает от второго комментария, пришедшего параллельно.
CREATE TABLE instagram.ig_contact_rule (
  rule_id     bigint      NOT NULL REFERENCES instagram.ig_rule(id) ON DELETE CASCADE,
  igsid       text        NOT NULL,
  delivery_id bigint      NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (rule_id, igsid)
);

-- Одна строка на одно исходное сообщение человека (комментарий или входящий DM).
-- Не на диалог: переписка с продолжением — отдельный этап, и надстраивается она поверх
-- этих строк по igsid, а не переписыванием их смысла.
CREATE TABLE instagram.ig_delivery (
  id              bigserial   PRIMARY KEY,
  source          text        NOT NULL,      -- COMMENT | DM
  source_id       text        NOT NULL,      -- comment_id | mid — ключ идемпотентности
  rule_id         bigint      REFERENCES instagram.ig_rule(id) ON DELETE SET NULL,
  igsid           text        NOT NULL,
  username        text,
  media_id        text,
  source_text     text,
  -- PENDING → CLAIMED → REPLIED_PUBLIC → SENT_DM → DONE.
  -- Терминальные: SKIPPED_NO_RULE, SKIPPED_SELF, SKIPPED_DUPLICATE (повтор, ответить было нечем),
  -- REPLIED_DUPLICATE (повтор: ответили публично, материал НЕ выдавали — иначе статистика
  -- выдач соврёт), EXPIRED, FAILED. CHECK'а на список намеренно нет: следующие этапы
  -- добавляют состояния, а миграция ради каждого — цена без выгоды.
  state           text        NOT NULL DEFAULT 'PENDING',
  attempts        int         NOT NULL DEFAULT 0,
  last_error      text,
  run_after       timestamptz NOT NULL DEFAULT now(),
  -- Окно платформы, посчитанное от времени СОБЫТИЯ: комментарий — 7 суток (private reply),
  -- входящий DM — 24 часа (ответ в диалоге). Разные каналы, разные окна.
  expires_at      timestamptz NOT NULL,
  public_reply_id text,
  dm_message_id   text,
  crm_lead_id     text,                      -- этап 3
  crm_synced_at   timestamptz,               -- этап 3
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source, source_id)
);
CREATE INDEX ON instagram.ig_delivery (state, run_after);
CREATE INDEX ON instagram.ig_delivery (igsid);

-- Ровно одна строка: аккаунт один.
CREATE TABLE instagram.ig_token (
  id            int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  ig_user_id    text        NOT NULL,
  token_enc     text        NOT NULL,   -- enc:<iv_b64>:<tag_b64>:<ct_b64>, AES-256-GCM
  scopes        text[]      NOT NULL DEFAULT '{}',
  expires_at    timestamptz NOT NULL,
  refreshed_at  timestamptz,
  invalid_at    timestamptz,            -- NOT NULL ⇒ диспетчер на паузе
  last_error    text,
  updated_at    timestamptz NOT NULL DEFAULT now()
);
