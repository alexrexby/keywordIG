-- Роль и схема сервиса. Выполняется СУПЕРЮЗЕРОМ: scripts/deploy.sh делает это шагом
-- ДО `up -d`, повторный запуск безопасен (роль может уже существовать).
-- Сам сервис ходит под ig_service и CREATE ROLE выполнить не может; мигратор (db.py)
-- этот файл пропускает по имени.
--
-- Пароль берётся из ОКРУЖЕНИЯ psql (IG_PW), а не из argv: argv виден в `ps aux`
-- любому пользователю хоста и оседает в истории шелла.
--   docker exec -i -e IG_PW <контейнер postgres> \
--     psql -U ig -d ig -v ON_ERROR_STOP=1 < migrations/000_role.sql
--
-- Проверка изоляции от CRM — обязательно с явной схемой public: при search_path=instagram
-- короткое `from "Lead"` ответит «relation does not exist», и тест соврёт про изоляцию.
--   psql "postgresql://ig_service:<pw>@postgres:5432/ig" -c 'select 1 from public."Lead"'
--   ожидается: ERROR: permission denied for table Lead

\getenv pw IG_PW
\if :{?pw}
\else
\echo '!! IG_PW не задан в окружении psql — пароль роли брать неоткуда, дальше будет ошибка'
\endif

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ig_service') THEN
    CREATE ROLE ig_service LOGIN;
  END IF;
END
$$;

ALTER ROLE ig_service PASSWORD :'pw';
CREATE SCHEMA IF NOT EXISTS instagram AUTHORIZATION ig_service;
REVOKE ALL ON SCHEMA public FROM ig_service;
ALTER ROLE ig_service SET search_path = instagram;
