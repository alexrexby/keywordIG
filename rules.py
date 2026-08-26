"""Правила: разбор события Meta, выбор правила по слову и движок текстов.

Здесь только чистые функции — ни БД, ни сети. Всё, что можно проверить без живого
Postgres и без Graph API, живёт в этом файле специально: нормализация, матчинг и
раскрытие вариантов ломаются молча (регистр, эмодзи, кириллица, неудачное сочетание
вариантов на границе лимита), а увидеть это можно только тестом.

Два канала и два РАЗНЫХ окна платформы разведены явно, а не подразумеваются:
  комментарий → private reply, окно 7 суток, ровно одно сообщение на комментарий;
  входящий DM → обычный ответ в диалоге, окно 24 часа с сообщения человека.
"""

import random
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

COMMENT = "COMMENT"
DM = "DM"

# Окна Meta. Числа здесь, а не в комментарии к схеме: диспетчер сверяется с expires_at
# и до Meta с просрочкой не идёт вовсе.
PRIVATE_REPLY_WINDOW = timedelta(days=7)
DM_REPLY_WINDOW = timedelta(hours=24)

# Лимит платформы на текст сообщения. Байты, а не символы: кириллица в UTF-8 весит два.
MAX_MESSAGE_BYTES = 1000
# Плейсхолдер в тексте правила = правило ещё не настроено.
PLACEHOLDER = "{{"
# Предохранители движка вариантов. Шаблон приходит от человека (SQL-строкой сейчас,
# из панели), а разбор идёт в том же event loop, где живёт приёмник вебхуков:
# дорогой шаблон — это не «кривой текст», а стоящий сервис.
MAX_TEMPLATE_BYTES = 4096
MAX_GROUP_DEPTH = 8


@dataclass(frozen=True)
class Candidate:
    """Событие, приведённое к тому, что нужно доставке. Одна строка ig_delivery."""

    source: str  # COMMENT | DM
    source_id: str  # comment_id | mid — ключ идемпотентности
    igsid: str
    username: str | None
    media_id: str | None
    text: str
    occurred_at: datetime
    expires_at: datetime
    self_authored: bool


@dataclass(frozen=True)
class Rule:
    id: int
    name: str
    trigger: str
    media_id: str | None
    keywords: list[str]
    match_mode: str
    priority: int
    public_replies: list[str]
    duplicate_replies: list[str]
    dm_text: str
    dm_buttons: list[dict] = field(default_factory=list)


# ---------- Нормализация и матчинг ----------


def normalize(text: str | None) -> str:
    """NFKC → casefold → выкинуть всё, кроме букв и цифр → схлопнуть пробелы.

    Эмодзи и пунктуация превращаются в пробел, а не выбрасываются: «слово🌴» и
    «слово,» должны дать «слово», но «гайд!скидка» не должны склеиться в одно слово.
    """
    folded = unicodedata.normalize("NFKC", text or "").casefold()
    kept = [ch if unicodedata.category(ch)[0] in ("L", "N") else " " for ch in folded]
    return " ".join("".join(kept).split())


def match_rule(rule_list: list[Rule], cand: Candidate) -> Rule | None:
    """Первое подходящее правило. Более специфичное побеждает общее.

    Порядок: сначала привязанные к этому посту (media_id), потом общие (media_id IS NULL);
    внутри — priority DESC, id ASC. Сортировка здесь, а не в SQL, ровно потому, что
    правил единицы, а порядок выбора — то, что нужно проверять тестом.
    """
    text = normalize(cand.text)
    if not text:
        return None
    ordered = sorted(
        (r for r in rule_list if _applies(r, cand)),
        key=lambda r: (0 if r.media_id else 1, -r.priority, r.id),
    )
    for rule in ordered:
        if _hits(rule, text):
            return rule
    return None


def _applies(rule: Rule, cand: Candidate) -> bool:
    if rule.trigger not in (cand.source, "BOTH"):
        return False
    return rule.media_id is None or rule.media_id == cand.media_id


def _hits(rule: Rule, text: str) -> bool:
    """EXACT — весь текст равен слову; CONTAINS — слово встречается внутри.

    CONTAINS намеренно подстрочный, а не по границам слова: русская морфология даёт
    «гайд», «гайда», «гайдом» на одно ключевое слово, и терять их дороже, чем
    поймать лишнее. Цена ошибки в другую сторону — короткие слова вроде «да» сработают
    внутри «давай», поэтому такие слова в правило не кладут.
    """
    for keyword in rule.keywords:
        word = normalize(keyword)
        if not word:
            continue
        if rule.match_mode == "EXACT":
            if text == word:
                return True
        elif word in text:
            return True
    return False


# ---------- Разбор события ----------


def parse_event(
    field_name: str,
    event_key: str,
    payload: dict,
    own_ids: set[str],
    received_at: datetime,
) -> Candidate | None:
    """Строка ig_event → кандидат. None — событие не про ответ человеку.

    own_ids дополняется entry_id самого события: entry вебхука — это аккаунт-получатель,
    то есть мы. Без этого сервис отвечает на собственный публичный ответ и уходит в петлю —
    главный самострел такой механики.
    """
    value = payload.get("value")
    value = value if isinstance(value, dict) else {}
    mine = {i for i in own_ids if i} | {str(payload.get("entry_id") or "")}

    if field_name == "comments":
        return _comment(value, event_key, payload, mine, received_at)
    if field_name == "messages":
        return _message(value, event_key, mine, received_at)
    return None


def _comment(value, event_key, payload, mine, received_at) -> Candidate | None:
    author = value.get("from")
    author = author if isinstance(author, dict) else {}
    igsid = str(author.get("id") or "")
    if not igsid:
        # Без автора отвечать некому и писать в директ некому: событие не наше.
        return None
    media = value.get("media")
    media = media if isinstance(media, dict) else {}
    occurred = _moment(payload.get("entry_time"), received_at)
    return Candidate(
        source=COMMENT,
        source_id=str(value.get("id") or event_key),
        igsid=igsid,
        username=author.get("username") or None,
        media_id=str(media.get("id")) if media.get("id") else None,
        text=str(value.get("text") or ""),
        occurred_at=occurred,
        expires_at=occurred + PRIVATE_REPLY_WINDOW,
        self_authored=igsid in mine,
    )


def _message(item, event_key, mine, received_at) -> Candidate | None:
    message = item.get("message")
    message = message if isinstance(message, dict) else {}
    if not message or message.get("is_echo"):
        # Квитанции о прочтении, реакции и эхо наших же сообщений — не повод отвечать.
        return None
    sender = item.get("sender")
    sender = sender if isinstance(sender, dict) else {}
    igsid = str(sender.get("id") or "")
    if not igsid:
        return None
    # У Direct timestamp приходит в миллисекундах, у comments — в секундах в entry.time.
    occurred = _moment(item.get("timestamp"), received_at, millis=True)
    return Candidate(
        source=DM,
        source_id=str(message.get("mid") or event_key),
        igsid=igsid,
        username=None,  # в payload сообщения username нет, только IGSID
        media_id=None,
        text=str(message.get("text") or ""),
        occurred_at=occurred,
        expires_at=occurred + DM_REPLY_WINDOW,
        self_authored=igsid in mine,
    )


def _moment(raw, fallback: datetime, millis: bool = False) -> datetime:
    """Время события от Meta, а не время приёма: окна платформы считаются от него."""
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0:
        seconds = raw / 1000 if millis else raw
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return fallback
    return fallback


# ---------- Движок текстов: {вариант1|вариант2} ----------
#
# Раскрывается В МОМЕНТ ОТПРАВКИ: в базе лежит один шаблон, два человека получают
# разные строки. Формат выбран потому, что его правит человек в админке, а не только код.
#
# Синтаксис:
#   {а|б|в}        — один из вариантов, вложенность допускается: {Привет{, дорогая|}|Хей}
#   {|!}           — пустой вариант законен, он и делает текст живым
#   \{ \} \| \\    — экранирование: фигурные скобки и черту можно написать буквально
#   незакрытая {   — не ошибка: остаётся обычным символом, отправку не роняет


def check_template(text: str | None) -> str | None:
    """Почему шаблон нельзя принимать. None — можно. Линейный проход, без разбора.

    Зовётся из unconfigured для КАЖДОЙ строки правила и для формы правила в панели.
    Гарантирует сбалансированность до входа в парсер: ветка «скобка не закрылась»
    там самая дорогая, и лучше не доводить до неё вовсе.
    """
    text = text or ""
    if len(text.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        return f"шаблон длиннее {MAX_TEMPLATE_BYTES} байт"
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2  # экранированный символ синтаксисом не является
            continue
        if ch == "{":
            depth += 1
            if depth > MAX_GROUP_DEPTH:
                return f"вложенность вариантов больше {MAX_GROUP_DEPTH}"
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return "лишняя закрывающая скобка"
        i += 1
    return "незакрытая фигурная скобка" if depth else None


def check_groups(text: str | None) -> str | None:
    """Блок вариантов, в котором вариантов нет: `{}` и `{|}`. None — таких блоков нет.

    Отдельно от check_template и НЕ из unconfigured: у живого правила такой блок безвреден
    (раскрывается в пустую строку), и превращать его в отказ доставки задним числом нельзя.
    А вот при сохранении из формы это опечатка — человек открыл скобку и не дописал варианты,
    и молча принять её значит выдать ему текст, отличающийся от задуманного.

    Пустой вариант РЯДОМ с непустым («{Привет, дорогая|}») законен и остаётся законным:
    он и делает текст живым — пусто ровно в половине случаев.
    """
    if _empty_group(_parse(text or "")):
        return "пустой блок вариантов — скобки есть, вариантов внутри нет"
    return None


def _empty_group(nodes: list) -> bool:
    for node in nodes:
        if isinstance(node, str):
            continue
        if all(not option for option in node):
            return True
        if any(_empty_group(option) for option in node):
            return True
    return False


def expand(text: str | None, rng: random.Random | None = None) -> str:
    """Одно случайное раскрытие шаблона."""
    picker = rng or random
    return _render(_parse(text or ""), picker.choice)


def longest(text: str | None) -> str:
    """Самое длинное (в БАЙТАХ) раскрытие шаблона.

    По нему и только по нему проверяется лимит платформы. Проверять случайное раскрытие
    нельзя: правило пройдёт валидацию и через неделю выпадет отказом Meta на неудачном
    сочетании вариантов — плавающий отказ, который почти невозможно поймать.
    """
    return _render(_parse(text or ""), _widest)


def _widest(options: list[str]) -> str:
    return max(options, key=lambda s: len(s.encode("utf-8")))


def _parse(text: str) -> list:
    """Дерево: строка — литерал, список списков — группа вариантов.

    Слишком длинный шаблон не разбираем вовсе — отдаём литералом. Это не потеря данных:
    check_template такой текст в правило не пускает, а здесь стоит последний предохранитель.
    """
    if len(text.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        return [text]
    # Позиции, на которых группа заведомо не закрывается. Без этой памяти неудачная
    # попытка разбирала весь суффикс заново, и стоимость удваивалась с каждой лишней «{»:
    # 26 байт скобок — 31 секунда CPU в том же цикле, где принимаются вебхуки.
    nodes, _ = _parse_seq(text, 0, stop="", failed=set(), depth=0)
    return nodes


def _parse_seq(text: str, i: int, stop: str, failed: set, depth: int) -> tuple[list, int]:
    nodes: list = []
    buf: list[str] = []
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            buf.append(text[i + 1])
            i += 2
            continue
        if stop and ch in stop:
            break
        if ch == "{":
            group, j = (None, i) if i in failed else _parse_group(text, i, failed, depth)
            if group is None:
                # Скобка не закрыта — это обычный символ, а не повод уронить отправку.
                failed.add(i)
                buf.append(ch)
                i += 1
                continue
            if buf:
                nodes.append("".join(buf))
                buf = []
            nodes.append(group)
            i = j
            continue
        buf.append(ch)
        i += 1
    if buf:
        nodes.append("".join(buf))
    return nodes, i


def _parse_group(text: str, i: int, failed: set, depth: int) -> tuple[list | None, int]:
    if depth >= MAX_GROUP_DEPTH:
        return None, i  # глубже не идём: рекурсия тоже стоит денег
    options: list = []
    j = i + 1
    while True:
        nodes, j = _parse_seq(text, j, stop="|}", failed=failed, depth=depth + 1)
        options.append(nodes)
        if j >= len(text):
            return None, i
        if text[j] == "}":
            return options, j + 1
        j += 1  # разделитель |


def _render(nodes: list, pick) -> str:
    out: list[str] = []
    for node in nodes:
        if isinstance(node, str):
            out.append(node)
        else:
            out.append(pick([_render(option, pick) for option in node]))
    return "".join(out)


def clip(text: str | None, limit: int = MAX_MESSAGE_BYTES) -> str:
    """Обрезка по БАЙТАМ UTF-8 с сохранением целого символа.

    Последний рубеж на СОБРАННОЙ строке: подставленная ссылка с utm добавляет под сотню
    байт, и шаблон, помещавшийся в лимит, может в него не влезть.
    """
    raw = (text or "").encode("utf-8")
    if len(raw) <= limit:
        return text or ""
    return raw[:limit].decode("utf-8", "ignore")


def unconfigured(rule: Rule) -> str | None:
    """Почему правило нельзя пускать в дело. None — можно.

    Проверяется ДО первого обращения к Meta: иначе человек получил бы публичное
    «отправила в директ» и пустоту в директе — худший исход, он выглядит как обман.
    Публичные ответы проверяются наравне с текстом DM: они уходят в ленту, где их видят
    посторонние, и неразбираемый шаблон там стоит дороже.
    """
    if PLACEHOLDER in rule.dm_text:
        # Формулировка называет ОБЕ причины намеренно: «{{» — это и незаполненный
        # плейсхолдер вроде {{ССЫЛКА}}, и законная вложенность вида {{а|б} в|г}.
        # Различать их сервис пока не умеет (открытая находка ревью 2-го круга, №10),
        # а видит этот текст теперь человек в форме, а не только лог: утверждать
        # «остался плейсхолдер» про корректный шаблон — значит отправить его искать
        # то, чего нет.
        return (
            "в тексте DM есть «{{» — либо остался незаполненный плейсхолдер, либо два"
            " блока вариантов начинаются подряд; второе законно, но отличить одно от"
            " другого сервис пока не умеет"
        )
    for label, text in _texts(rule):
        broken = check_template(text)
        if broken:
            return f"{label}: {broken}"
    for button in rule.dm_buttons:
        url = str(button.get("url") or "") if isinstance(button, dict) else ""
        if not url.startswith("https://") or not url.isascii():
            return "в кнопке не подставлена ссылка"
    worst = len(longest(rule.dm_text).encode("utf-8"))
    if worst > MAX_MESSAGE_BYTES:
        return f"самое длинное раскрытие текста DM — {worst} байт при лимите {MAX_MESSAGE_BYTES}"
    return None


def _texts(rule: Rule):
    """Все строки правила, которые уходят в движок вариантов."""
    yield "текст DM", rule.dm_text
    for variant in rule.public_replies:
        yield "публичный ответ", variant
    for variant in rule.duplicate_replies:
        yield "ответ на повтор", variant
    for button in rule.dm_buttons:
        if isinstance(button, dict):
            yield "заголовок кнопки", str(button.get("title") or "")
