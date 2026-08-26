-- Роль и схема сервиса. Выполняется СУПЕРЮЗЕРОМ, поэтому запускает файл не сервис:
-- он смонтирован в /docker-entrypoint-initdb.d контейнера postgres и отрабатывает один
-- раз, при создании базы. Сам сервис ходит под ig_service и CREATE ROLE выполнить не
-- может; мигратор (db.py) этот файл пропускает по имени.
--
-- Повторный запуск безопасен: роль может уже существовать. Но помните, что ALTER ROLE
-- ниже МЕНЯЕТ ПАРОЛЬ — прогонять файл руками на живой базе, не сверив IG_PW с тем, что
-- лежит в IG_DATABASE_URL, значит запереть сервис от собственной базы.
--
-- Пароль берётся из ОКРУЖЕНИЯ psql (IG_PW), а не из argv: argv виден в `ps aux`
-- любому пользователю хоста и оседает в истории шелла.
--
-- Зачем отдельная роль, если база всё равно только наша: ig_service не имеет прав на
-- схему public и ходит с search_path = instagram. Это стоит одной строки и оставляет
-- установщику возможность поселить сервис в базу, где уже что-то живёт.
-- Проверка изоляции — обязательно с ЯВНОЙ схемой public: при search_path = instagram
-- короткое `from "Foo"` ответит «relation does not exist», и тест соврёт про изоляцию.
--   psql "postgresql://ig_service:<pw>@postgres:5432/ig" -c 'select 1 from public."Foo"'
--   ожидается: ERROR: permission denied for table Foo (а не «no such relation»)

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
