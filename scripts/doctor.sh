#!/bin/bash
# Проверка установки на реальность вместо доверия инструкции.
#
# У каждой строки рядом написано, ЧЕМ ОНА МОЖЕТ СОВРАТЬ. Зелёная галочка, про которую
# известно, как она обманывает, стоит дороже десяти, про которые не известно ничего:
# отказы этой механики молчаливые, и живут они ровно в слепых пятнах проверок.
#
#   ./scripts/doctor.sh                — только смотрит, ничего никуда не шлёт
#   ./scripts/doctor.sh --alert-test   — плюс пробное аварийное сообщение вам в мессенджер
#
# Без -e намеренно: доктор обязан дойти до конца и показать ВСЕ строки, а не остановиться
# на первой плохой. Итог — числом плохих проверок в последней строке и кодом возврата.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

COMPOSE="docker compose -f docker-compose.prod.yml"
ENV_PATH="$ROOT/.env"
ALERT_TEST=no
BAD=0

case "${1:-}" in
--alert-test) ALERT_TEST=yes ;;
"") ;;
*)
	printf 'Использование: ./scripts/doctor.sh [--alert-test]\n' >&2
	exit 1
	;;
esac

say() { printf '%s\n' "$*"; }
head2() { printf '\n-- %s\n' "$*"; }
ok() { printf '[ ок ]    %s\n' "$*"; }
bad() {
	printf '[ ПЛОХО ] %s\n' "$*"
	BAD=$((BAD + 1))
}
huh() { printf '[  ?  ]   %s\n' "$*"; }
note() { printf '          %s\n' "$*"; }
lie() {
	printf '          чем может соврать: %s\n' "$1"
	shift
	local line
	for line in "$@"; do printf '                             %s\n' "$line"; done
}

[ -f "$ENV_PATH" ] || {
	printf '!! файла окружения нет — установка ещё не делалась: ./scripts/install.sh ваш-домен.ru\n' >&2
	exit 1
}

env_value() {
	# Разбор файла окружения теми же формами записи, что понимает docker compose:
	# `KEY=value`, `export KEY=value`, пробелы вокруг знака равенства, значение в кавычках
	# и хвостовой комментарий у значения без кавычек. Разойдясь с compose, доктор поставит
	# неверный диагноз на ИСПРАВНОЙ машине — а это ровно то, ради чего его не пишут.
	sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=[[:space:]]*//p" "$ENV_PATH" |
		tail -1 |
		sed -E -e 's/^"([^"]*)".*$/\1/;t' -e "s/^'([^']*)'.*\$/\1/;t" -e 's/[[:space:]]+#.*$//' -e 's/[[:space:]]+$//'
}

oneline() {
	# Список адресов в одну строку, без хвостового пробела: строку читает человек.
	tr '\n' ' ' | sed -e 's/  */ /g' -e 's/ *$//'
}

DOMAIN="$(env_value IG_DOMAIN)"
[ -n "$DOMAIN" ] || {
	printf '!! в файле окружения не задан IG_DOMAIN — проверять нечего\n' >&2
	exit 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Проверка установки на домене $DOMAIN, $(date '+%F %T')"

# ---------- Контейнеры ----------

head2 "состав"
for svc in caddy postgres instagram-service; do
	cid="$($COMPOSE ps -q "$svc" 2>/dev/null)"
	if [ -z "$cid" ]; then
		bad "$svc не запущен"
		note "поднять: docker compose -f docker-compose.prod.yml up -d"
		continue
	fi
	status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null)"
	health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}без проверки{{end}}' "$cid" 2>/dev/null)"
	restarts="$(docker inspect -f '{{.RestartCount}}' "$cid" 2>/dev/null)"
	if [ "$status" = "running" ] && { [ "$health" = "healthy" ] || [ "$health" = "без проверки" ]; }; then
		ok "$svc: $status, здоровье — $health, перезапусков: $restarts"
	else
		bad "$svc: $status, здоровье — $health, перезапусков: $restarts"
		note "журнал: docker compose -f docker-compose.prod.yml logs --tail=30 $svc"
	fi
done
lie "«running» не означает «работает»: контейнер, который перезапускается каждые" \
	"полминуты, в момент проверки тоже running — потому и смотрим на здоровье" \
	"и на число перезапусков. У самого здоровья слепота своя: оно проверяет" \
	"сервис ИЗНУТРИ контейнера и ничего не знает о том, доходит ли до него интернет."

# ---------- Домен ----------

head2 "домен"
if command -v dig >/dev/null 2>&1; then
	resolved="$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$')"
	resolver="dig"
else
	resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u)"
	resolver="getent (системный резолвер)"
fi
# `|| true` у каждого источника: `hostname -I` есть не во всякой системе, а с pipefail
# один такой отказ превратил бы проверку в молчание.
ips="$({
	ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]}' || true
	hostname -I 2>/dev/null | tr ' ' '\n' || true
} | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u || true)"
if [ -z "$resolved" ]; then
	bad "A-записи на $DOMAIN нет — домен никуда не указывает ($resolver)"
	note "завести у регистратора: A $DOMAIN -> $(echo "$ips" | head -1)"
elif [ -n "$ips" ] && comm -12 <(echo "$resolved" | sort -u) <(echo "$ips") | grep -q .; then
	ok "домен указывает сюда: $(echo "$resolved" | oneline)"
else
	huh "домен указывает на $(echo "$resolved" | oneline), адреса этой машины — $(echo "$ips" | oneline)"
	note "нормально при CDN или прокси перед сервером; ошибка, если запись от старого сервера"
fi
lie "перед сервером стоит CDN или прокси — тогда адрес чужой, и это НЕ поломка." \
	"Доставку до вас доказывает не адрес, а факт, что Meta приняла callback URL:" \
	"дашборд не сохраняет адрес, пока handshake не дошёл и не ответил верно." \
	"И наоборот: getent смотрит ещё и в /etc/hosts, то есть на этой машине домен" \
	"может «указывать сюда» просто строкой в файле."

# ---------- TLS и публичные адреса ----------

head2 "снаружи"
code="$(curl -sS --max-time 10 -o "$TMP/health" -w '%{http_code}' "https://$DOMAIN/ig/health" 2>"$TMP/curl-err")"
if [ "$code" = "200" ]; then
	ok "TLS работает, https://$DOMAIN/ig/health отвечает 200"
elif [ "$code" = "000" ]; then
	bad "до https://$DOMAIN не достучаться: $(tr -d '\n' <"$TMP/curl-err")"
	note "если жалоба на сертификат — его не выдали: чаще всего до порта 80 не пускают снаружи"
	note "журнал прокси: docker compose -f docker-compose.prod.yml logs --tail=20 caddy"
else
	bad "https://$DOMAIN/ig/health отвечает $code вместо 200"
fi
lie "проверка идёт С ЭТОЙ ЖЕ машины. Прозрачный прокси, запись в /etc/hosts или" \
	"кэш резолвера здесь ответят за сервер, и сертификат будет выглядеть выданным." \
	"Честно это проверяется только с ДРУГОЙ машины — откройте https://$DOMAIN/privacy" \
	"с телефона по мобильному интернету, не по своему Wi-Fi."

if [ "$code" = "200" ]; then
	if grep -q '"ok": *true' "$TMP/health"; then
		ok "сервис жив: круг рассылки шевелится"
	else
		bad "сервис отвечает, но говорит о себе: $(tr -d '\n' <"$TMP/health")"
		note "круг рассылки замер — сообщения не уходят, даже если вебхуки приходят"
	fi
	lie "проверка живости намеренно НЕ ходит в базу: приёмник вебхуков обязан отвечать" \
		"Meta и при мигнувшей базе. Значит «жив» не означает «база отвечает» —" \
		"за базу отвечает раздел «состояние» ниже, он читается именно из неё."
fi

code="$(curl -sS --max-time 10 -o "$TMP/admin" -w '%{http_code}' "https://$DOMAIN/ig/admin/state" 2>/dev/null)"
if [ "$code" = "403" ] && [ ! -s "$TMP/admin" ]; then
	ok "машинная админка закрыта снаружи: 403 с пустым телом"
elif [ "$code" = "403" ]; then
	bad "админка отвечает 403, но С ТЕЛОМ — значит запрос дошёл до приложения, а прокси не применился"
	note "применить конфиг прокси: ./scripts/update.sh"
else
	bad "https://$DOMAIN/ig/admin/state отвечает $code — снаружи этот адрес обязан быть закрыт"
fi
lie "пустое тело — единственный признак, что закрыл именно прокси. Приложение на этом" \
	"же адресе отдаёт 403 с телом, а с верным ключом и вовсе 200: по коду ответа" \
	"эти два случая неразличимы."

for page in privacy data-deletion; do
	code="$(curl -sS --max-time 10 -o "$TMP/page" -w '%{http_code}' "https://$DOMAIN/$page" 2>/dev/null)"
	# Без `|| echo 0`: grep печатает ноль и сам, а код возврата 1 при нулевом счёте
	# дописал бы вторую строку — и сравнение с нулём переставало бы работать молча.
	holes="$(grep -c '{{' "$TMP/page" 2>/dev/null)"
	holes="${holes:-0}"
	if [ "$code" = "200" ] && [ "$holes" = "0" ]; then
		ok "страница /$page отдаётся и заполнена целиком"
	elif [ "$code" = "503" ]; then
		bad "страница /$page не отдаётся (503): не заполнены реквизиты владельца"
		note "какие именно — видно на самой странице; правятся в файле окружения, поля OWNER_*"
	else
		bad "страница /$page: код $code, незаполненных мест в тексте: $holes"
	fi
done
lie "счёт незаполненных мест равен нулю и на отрендеренной странице, и на 503 —" \
	"страницы отказа их просто не содержит. Поэтому код ответа проверяется отдельно," \
	"и только вместе эти два наблюдения что-то значат."

# ---------- Состояние сервиса ----------

head2 "состояние сервиса"
$COMPOSE exec -T instagram-service python - >"$TMP/state.json" 2>"$TMP/state-err" <<'PY'
import json
import os
import urllib.error
import urllib.request

# Запрос идёт по HTTP на самого себя тем же путём и с тем же заголовком, каким ходит
# любой клиент админки: проверяется заодно, что ключ на месте. Ключ берётся из окружения
# КОНТЕЙНЕРА — в окружении доктора и в его аргументах ему делать нечего.
request = urllib.request.Request(
    "http://localhost:8020/ig/admin/state",
    headers={"X-Admin-Token": os.environ.get("IG_ADMIN_TOKEN", "")},
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        print(response.read().decode())
except urllib.error.HTTPError as exc:
    print(json.dumps({"__error": "ответ %s на /ig/admin/state" % exc.code}))
except Exception as exc:
    print(json.dumps({"__error": "сервис не ответил: %s" % type(exc).__name__}))
PY

jget() {
	python3 - "$TMP/state.json" "$1" <<'PY' 2>/dev/null
import json
import sys

try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print("")
    raise SystemExit
for part in sys.argv[2].split("."):
    if not isinstance(data, dict) or part not in data:
        print("")
        raise SystemExit
    data = data[part]
print("" if data is None else data)
PY
}

STATE_OK=no
if [ ! -s "$TMP/state.json" ]; then
	bad "состояние прочитать не удалось: контейнер сервиса не ответил"
	note "$(tr -d '\n' <"$TMP/state-err" | cut -c1-200)"
elif [ -n "$(jget __error)" ]; then
	bad "состояние прочитать не удалось: $(jget __error)"
	note "если ответ 403 — пуст IG_ADMIN_TOKEN в файле окружения, и админка закрыта целиком"
else
	STATE_OK=yes
fi

if [ "$STATE_OK" = "yes" ]; then
	# Порог «сколько простоя уже смерть» живёт в одном месте — в самом сервисе, и вердикт
	# по нему уже вынесен выше проверкой живости. Здесь только наблюдение, иначе число
	# пришлось бы держать в двух местах, и разъехались бы они на первой правке.
	ok "круг рассылки: последний оборот $(jget dispatcher.last_tick_at), простой $(jget dispatcher.stale_sec) с"

	if [ "$(jget account.wrong_ig_user_id)" = "True" ]; then
		bad "все события за сутки — от ЧУЖОГО аккаунта: в IG_USER_ID записан не тот номер"
		note "у аккаунта два идентификатора, и в файл окружения нужен тот, что приходит в вебхуке"
		note "в событиях приходит: $(jget account.last_foreign_entry_id), в окружении: $(jget account.ig_user_id)"
		lie "этот вердикт молчит, пока событий нет вообще: ноль событий — это «ещё не" \
			"приходило», а не «номер верный». Пока вебхуки не пошли, проверить номер нечем."
	else
		ok "события разбираются как свои (аккаунт в окружении: $(jget account.ig_user_id))"
	fi

	if [ "$(jget daily.reached)" = "True" ]; then
		bad "суточный предохранитель сработал: отправлено $(jget daily.sent_24h) при пределе $(jget daily.limit)"
		note "это защита вашего аккаунта, а не поломка; предел меняется в файле окружения"
	else
		ok "отправлено за сутки: $(jget daily.sent_24h) при пределе $(jget daily.limit)"
	fi

	pending="$(jget queue.pending)"
	retrying="$(jget queue.retrying)"
	if [ -n "$retrying" ] && [ "$retrying" -gt 0 ] 2>/dev/null; then
		bad "в очереди $pending обращений, из них $retrying ждут повторной попытки после отказа Meta"
		note "последний отказ: $(jget queue.last_error_at); подробности — в панели, раздел «Очередь»"
	else
		ok "очередь: $pending обращений ждут отправки, повторных попыток нет"
	fi

	head2 "канал аварийных сообщений"
	if [ "$(jget alerts.configured)" != "True" ]; then
		bad "канал не настроен: пусты IG_ALERT_BOT_TOKEN или IG_ALERT_CHAT_ID"
		note "без него об остановке автоответов вам скажут подписчики, а не сервис"
	else
		last_ok="$(jget alerts.last_ok_at)"
		last_err="$(jget alerts.last_error)"
		if [ -n "$last_err" ]; then
			bad "последняя попытка не удалась: $last_err"
		elif [ -z "$last_ok" ]; then
			huh "канал настроен, но НИ РАЗУ не проверялся"
			note "проверить: ./scripts/doctor.sh --alert-test"
		else
			ok "канал настроен, последняя подтверждённая отправка: $last_ok"
		fi
	fi
	lie "машина видит только «Telegram принял сообщение». Дошло ли оно до мессенджера," \
		"знает лишь тот, кто в него смотрит: заблокированный бот, чужой chat_id или" \
		"вышедшее из аккаунта устройство машине не видны. Поэтому подтверждает человек."
fi

if [ "$ALERT_TEST" = "yes" ]; then
	result="$($COMPOSE exec -T instagram-service python - <<'PY' 2>/dev/null || true
import asyncio

import db
import meta


async def main():
    # Свой пул: процесс живёт вне lifespan, а отметку об успешной доставке нужно положить
    # в базу — её читают панель и этот же доктор при следующем запуске.
    db.pool = db.make_pool()
    await db.pool.open()
    try:
        ok = await meta.send_test_alert()
    finally:
        await meta.close()
        await db.pool.close()
    print("SENT" if ok else "FAILED: " + (meta.last_alert_error or "причина не названа"))


asyncio.run(main())
PY
	)"
	case "$result" in
	SENT*) note "пробное сообщение отправлено — загляните в мессенджер. Не пришло, значит канал не работает, чей бы код ни отвечал «принято»." ;;
	FAILED*) bad "пробное сообщение не отправлено. $result" ;;
	*) bad "проба не выполнилась: сервис не ответил" ;;
	esac
fi

# ---------- Токен и подписка: живые запросы к Meta ----------

head2 "токен и подписка"
$COMPOSE exec -T instagram-service python - >"$TMP/probe.json" 2>/dev/null <<'PY'
import asyncio
import json

import db
import meta
import tokens
from config import IG_GRAPH_VERSION


async def subscribed(token: str) -> dict:
    """Подписка на события. Тело ответа наружу не цитируем: у Graph токен лежит в
    query-строке, и эхо адреса утащило бы его в вывод доктора."""
    url = f"{meta.GRAPH_HOST}/{IG_GRAPH_VERSION}/me/subscribed_apps"
    try:
        response = await meta.client().get(url, params={"access_token": token})
    except Exception as exc:
        return {"verdict": "UNKNOWN", "why": type(exc).__name__}
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    error = body.get("error")
    if response.is_error or isinstance(error, dict):
        message = str((error or {}).get("message") or "")[:200]
        return {"verdict": "ERROR", "status": response.status_code, "why": message}
    data = body.get("data") if isinstance(body.get("data"), list) else []
    cursors = (body.get("paging") or {}).get("cursors") or {}
    fields = sorted(
        {
            name
            for item in data
            if isinstance(item, dict)
            for name in (item.get("subscribed_fields") or [])
        }
    )
    return {
        "verdict": "OK" if data else "EMPTY",
        "fields": fields,
        # Непустые курсоры при пустом списке — признак урезанного доступа, а не отсутствия
        # подписки: коллекция есть, элементы вырезаны фильтром прав.
        "cursors": bool(cursors.get("before") or cursors.get("after")),
    }


async def main():
    out = {}
    db.pool = db.make_pool()
    await db.pool.open()
    try:
        state = await tokens.state(force=True)
        if not state.value:
            out["token"] = {"verdict": "NONE"}
        else:
            try:
                me = await meta.fetch_me(state.value)
                out["token"] = {
                    "verdict": "LIVE",
                    "who": me.get("username") or me.get("user_id") or me.get("id"),
                }
            except Exception as exc:
                # Решение по КОДУ отказа, а не по факту ошибки: сетевой сбой и мёртвый
                # токен выглядят одинаково, если смотреть только на «не получилось».
                out["token"] = {"verdict": meta.classify(exc), "why": str(exc)[:200]}
            out["subs"] = await subscribed(state.value)
    finally:
        await meta.close()
        await db.pool.close()
    print(json.dumps(out, ensure_ascii=False, default=str))


asyncio.run(main())
PY

pget() {
	python3 - "$TMP/probe.json" "$1" <<'PY' 2>/dev/null
import json
import sys

try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print("")
    raise SystemExit
for part in sys.argv[2].split("."):
    if not isinstance(data, dict) or part not in data:
        print("")
        raise SystemExit
    data = data[part]
if isinstance(data, list):
    print(", ".join(str(item) for item in data))
else:
    print("" if data is None else data)
PY
}

case "$(pget token.verdict)" in
LIVE) ok "токен живой, Meta отвечает за аккаунт: $(pget token.who)" ;;
NONE)
	huh "токена нет — рассылка стоит на паузе, вебхуки при этом принимаются"
	note "вставить: https://$DOMAIN/panel, раздел «Токен». Это нормальное состояние свежей установки"
	;;
TOKEN_INVALID)
	bad "Meta отвергла токен: $(pget token.why)"
	note "пройдите вход через Instagram заново и вставьте свежий токен: https://$DOMAIN/panel"
	;;
RETRY)
	huh "спросить Meta не удалось: $(pget token.why)"
	note "это НЕ приговор токену: так выглядит и сетевой сбой, и отказ самой платформы"
	;;
"")
	bad "зонд токена не выполнился: контейнер сервиса не ответил"
	;;
*)
	huh "неожиданный ответ Meta на проверку токена: $(pget token.why)"
	;;
esac
lie "«не получилось» и «токен мёртв» — разные утверждения. Мёртвым токен считается" \
	"только по коду 190 в ответе Meta; сетевой сбой и пятисотка платформы дают тот же" \
	"внешний вид отказа, и принимать их за смерть токена значит менять рабочий токен." \
	"И наоборот: ответ на /me не доказывает прав на комментарии — их видно только по" \
	"тому, приходят ли события."

case "$(pget subs.verdict)" in
OK)
	fields="$(pget subs.fields)"
	case "$fields" in
	*comments*)
		case "$fields" in
		*messages*) ok "подписка есть: $fields" ;;
		*)
			bad "подписка есть, но только на $fields — директ приходить не будет"
			;;
		esac
		;;
	*)
		bad "подписка есть, но без comments ($fields) — кодовые слова в комментариях не сработают"
		;;
	esac
	;;
EMPTY)
	if [ "$(pget subs.cursors)" = "True" ]; then
		huh "список подписок пуст, НО курсоры непустые — это урезанный доступ, а не отсутствие подписки"
		note "проверьте, что аккаунт добавлен в роли приложения и приглашение ПРИНЯТО"
	else
		bad "подписки на события нет — вебхуки приходить не будут"
		note "в дашборде Meta: Instagram -> Webhooks -> подписаться на comments и messages"
	fi
	;;
ERROR) bad "Meta отказала на запросе подписки ($(pget subs.status)): $(pget subs.why)" ;;
UNKNOWN) huh "спросить про подписку не удалось: $(pget subs.why)" ;;
"") note "подписку не проверяли: без живого токена этот вопрос Meta не задать" ;;
esac
lie "пустой список при непустых курсорах читается как «подписки нет», хотя означает" \
	"обратное: коллекция есть, а элементы вырезаны фильтром прав. Самая дорогая ошибка" \
	"в разборе этой платформы — принять пустой ответ за отсутствие данных."

# ---------- Публикация приложения ----------

head2 "приложение опубликовано"
huh "МАШИННОЙ ПРОВЕРКИ ЭТОГО НЕ СУЩЕСТВУЕТ."
note "Дашборд Meta про публикацию врёт даже человеку: кнопка «Опубликовать» остаётся"
note "в разметке и у опубликованного приложения, а API об этом не спрашивают."
note "Единственный честный признак — доходят ли до сервиса события."
if [ "$STATE_OK" = "yes" ]; then
	if [ "$(jget webhooks.ever_received)" = "True" ]; then
		note "события приходили; последнее: $(jget webhooks.last_at)"
	else
		note "событий не приходило НИ РАЗУ за всю жизнь установки."
		note "Если аккаунт, роли и подписка настроены, остаётся ровно одна причина —"
		note "приложение не опубликовано. Вебхуки при этом не приходят вообще и без ошибок."
	fi
fi
note "Как проверить руками: оставьте под своим постом комментарий с кодовым словом,"
note "подождите минуту и запустите доктора снова. Время последнего события не изменилось —"
note "почти наверняка приложение не опубликовано."

# ---------- Итог ----------

printf '\n'
if [ "$BAD" -eq 0 ]; then
	say "Плохих проверок нет. Не проверено машиной: доставка аварийных сообщений в мессенджер"
	say "и публикация приложения — оба вопроса закрывает человек, способами выше."
	exit 0
fi
say "Плохих проверок: $BAD. Разбирайтесь сверху вниз: нижние строки часто следствие верхних."
exit 1
