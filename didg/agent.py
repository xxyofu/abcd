import json
import re
from datetime import UTC, datetime, timedelta

import httpx
import numpy as np
import yaml

from didg.collect import EPOCH, discover, fetch, site_links
from didg.models import SOURCES, config
from didg.rank import embed, query, semantic, vectors

TASK = (
    "Проведи плановое обслуживание: оцени источники по статистике и отметкам читателя, "
    "понизь или отключи бесполезные, повысь полезные."
)

SYSTEM = (
    "Ты агент сопровождения ИТ/ИБ-дайджеста. Профиль читателя «{title}»: {audience}.\n"
    "Ты отвечаешь за качество источников: проверяешь и подключаешь их, настраиваешь вес по "
    "статистике и отметкам читателя.\n"
    "Правила:\n"
    "- решения принимай только по данным инструментов, ничего не додумывай;\n"
    "- подключённые источники проверяй через probe_source по их id, не подбирай им другие "
    "адреса;\n"
    "- новый источник подключай, только если probe_source показал свежие, регулярные "
    "публикации по ИБ,\n"
    "  релевантные профилю и редко дублирующие базу; id Telegram-канала — tg_<канал>, "
    "сайта — по домену;\n"
    "- если у сайта нет RSS, probe_source вернёт ссылки страницы: составь по ним pattern "
    "ссылок на статьи\n"
    "  и проверь сайт ещё раз с этим pattern;\n"
    "- вес источника от 0 до 2: снижай при большом объёме и низкой доле попаданий в "
    "дайджест или при отрицательных\n"
    "  отметках, повышай при высокой доле попаданий или положительных отметках, 0 "
    "отключает источник;\n"
    "  вес подключённого источника меняй, только если у него от 3 отметок или от 20 "
    "публикаций за 30 дней;\n"
    "- в конце кратко на русском перечисли, что проверил, что изменил и почему."
)


def spec(name, description, **params):
    props = {k: {"type": t.rstrip("?"), "description": d} for k, (t, d) in params.items()}
    required = [k for k, (t, _) in params.items() if not t.endswith("?")]
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


TOOLS = [
    spec(
        "overview",
        "Профиль читателя и статистика источников: вес, публикации, последняя дата, "
        "попадания в дайджест, отметки «полезно» и «бесполезно»",
        days=("integer?", "окно статистики в днях, по умолчанию 30"),
    ),
    spec(
        "probe_source",
        "Проверить источник: свежесть, частоту, долю ИБ, релевантность профилю, дубли с базой",
        url=(
            "string",
            "id подключённого источника или адрес кандидата: RSS, сайт, https://t.me/канал",
        ),
        pattern=("string?", "регулярное выражение ссылок на статьи, если у сайта нет RSS"),
    ),
    spec(
        "set_source",
        "Подключить новый источник или изменить вес подключённого",
        id=("string", "id источника: латиница, цифры и подчёркивания"),
        weight=("number?", "вес в ранжировании от 0 до 2, 0 отключает сбор, по умолчанию 1"),
        type=("string?", "для нового: rss, html или tg"),
        url=("string?", "для нового: адрес ленты или страницы"),
        channel=("string?", "для нового: имя Telegram-канала"),
        pattern=("string?", "для нового html: шаблон ссылок"),
        match=("string?", "для нового: регулярное выражение фильтра по теме ИБ"),
    ),
]
NAMES = {t["function"]["name"] for t in TOOLS}
CHECKED = {"tg": ("channel",), "rss": ("url",), "html": ("url", "pattern")}


def signature(src):
    values = [src.get(k, "") for k in CHECKED.get(src["type"], ())]
    return src["type"], *(v.lower() if src["type"] == "tg" else v for v in values)


class Agent:
    def __init__(self, profile, storage, llm, confirm, log):
        self.profile, self.storage, self.llm, self.confirm, self.log = (
            profile,
            storage,
            llm,
            confirm,
            log,
        )
        self.applied, self.probed = [], set()

    def run(self, task, steps=40):
        messages = [
            {
                "role": "system",
                "content": SYSTEM.format(title=self.profile.title, audience=self.profile.audience),
            },
            {"role": "user", "content": task},
        ]
        for _ in range(steps):
            message = (
                self.llm.client.chat.completions.create(
                    model=self.llm.model,
                    messages=messages,
                    tools=TOOLS,
                    temperature=0,
                    **self.llm.options,
                )
                .choices[0]
                .message
            )
            messages.append(message.model_dump(exclude_none=True))
            if not message.tool_calls:
                return message.content
            for call in message.tool_calls:
                name = call.function.name
                try:
                    args = json.loads(call.function.arguments or "{}")
                    self.log(f"→ {name}({json.dumps(args, ensure_ascii=False)})")
                    result = (
                        getattr(self, name)(**args)
                        if name in NAMES
                        else {"ошибка": "нет такого инструмента"}
                    )
                except Exception as e:
                    result = {"ошибка": str(e)}
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    }
                )
        return "Достигнут лимит шагов"

    def overview(self, days=30):
        return {
            "профиль": {
                k: getattr(self.profile, k)
                for k in ("days", "interests", "stack", "include_keywords")
            },
            "источники": self.storage.source_stats(
                self.profile.name, datetime.now(UTC) - timedelta(days=days)
            ),
        }

    def probe_source(self, url, pattern=""):
        conf = config()
        sources = {s["id"]: s for s in conf["sources"]}
        if url in sources:
            src = sources[url]
        elif "t.me/" in url:
            src = {"id": "probe", "type": "tg", "channel": url.rstrip("/").split("/")[-1]}
        elif pattern:
            src = {"id": "probe", "type": "html", "url": url, "pattern": pattern, "limit": 8}
        else:
            src = {"id": "probe", "type": "rss", "url": discover(url), "full_text": False}
        items, error = fetch(src, EPOCH)
        if error or not items:
            result = {"ошибка": str(error or "публикации не найдены"), "источник": src}
            if src["type"] == "rss" and not error:
                try:
                    result["ссылки на странице"] = site_links(url)
                except httpx.HTTPError:
                    pass
            return result
        items = sorted(items, key=lambda a: a.published)[-30:]
        dates, vecs = [a.published for a in items], embed(items)
        now = datetime.now(UTC)
        base = [
            a
            for a in self.storage.articles(now - timedelta(days=30), now)
            if a.source != src["id"]
        ]
        dup = (
            (vecs @ vectors(base, self.storage).T).max(1) > 0.92
            if base
            else np.zeros(len(items), bool)
        )
        topic = re.compile(conf["security_topics"], re.I)
        self.probed.add(signature(src))
        return {
            "источник": src,
            "публикаций": len(items),
            "последняя": dates[-1].date(),
            "в день": round(len(items) / max((dates[-1] - dates[0]).days, 1), 1),
            "доля ИБ": round(
                float(np.mean([bool(topic.search(f"{a.title} {a.text}")) for a in items])), 2
            ),
            "релевантность профилю": round(float(semantic(vecs @ query(self.profile)).mean()), 2),
            "доля дублей с базой": round(float(dup.mean()), 2),
            "примеры": [a.title for a in items[:5]],
        }

    def set_source(self, id, weight=1.0, type="", url="", channel="", pattern="", match=""):
        text, weight = (
            SOURCES.read_text(encoding="utf-8"),
            round(min(2.0, max(0.0, float(weight))), 2),
        )
        row = re.compile(rf'^(  - \{{id: "?{re.escape(id)}"?,.*?)(, weight: [\d.]+)?\}}$', re.M)
        if row.search(text):
            since = datetime.now(UTC) - timedelta(days=30)
            stat = next(
                s for s in self.storage.source_stats(self.profile.name, since) if s["id"] == id
            )
            marks, volume = stat.get("полезно", 0) + stat.get("бесполезно", 0), stat["публикаций"]
            if marks < 3 and volume < 20 and not (weight == 0 and volume == 0):
                return {
                    "ошибка": "мало данных: нужно от 3 отметок или от 20 публикаций за 30 дней"
                }
            if not self.confirm(f"Установить источнику {id} вес {weight}?"):
                return {"ошибка": "пользователь отклонил"}
            SOURCES.write_text(row.sub(rf"\1, weight: {weight}}}", text), encoding="utf-8")
            self.applied.append(f"{id}: вес {weight}")
            return {"источник": id, "вес": weight}
        if type not in CHECKED or not (url or channel):
            return {"ошибка": "для нового источника нужны type и url или channel"}
        if weight == 0:
            return {
                "ошибка": (
                    "новый источник подключается с весом больше 0, "
                    "отклонённый кандидат не добавляется"
                )
            }
        fields = dict(id=id, type=type, url=url, channel=channel, pattern=pattern, match=match)
        if signature(fields) not in self.probed:
            return {
                "ошибка": (
                    "источник с этими type, url, channel и pattern не проверен: "
                    "сначала вызови probe_source с ними"
                )
            }
        entry = {k: v for k, v in fields.items() if v} | (
            {"weight": weight} if weight != 1.0 else {}
        )
        if not self.confirm(f"Подключить источник {entry}?"):
            return {"ошибка": "пользователь отклонил"}
        line = yaml.safe_dump(
            entry, default_flow_style=True, sort_keys=False, allow_unicode=True, width=1000
        )
        SOURCES.write_text(text.rstrip("\n") + "\n  - " + line, encoding="utf-8")
        self.applied.append(f"{id}: подключён" + (f", вес {weight}" if weight != 1.0 else ""))
        return {"подключено": entry}
