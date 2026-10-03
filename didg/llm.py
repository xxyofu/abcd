import hashlib
import json
import os
from collections import Counter
from difflib import get_close_matches

from openai import OpenAI

GROUPS = ["Атака", "Уязвимость", "Инфо"]
MIN_SIM = 0.15
TAGS = [
    "В РФ",
    "Вне РФ",
    "Крупные финансовые потери",
    "Нарушение работы критической инфраструктуры",
    "Энергетика",
    "Промышленность",
    "Имиджевые потери",
    "Утечки чувствительной информации (ПДн, коммерческая и государственная тайна)",
    "Госсектор и правовое поле",
    "Уязвимый сервис массового использования (для обывателей и топ-менеджеров)",
    "Кадры, громкие мероприятия и конференции ИБ",
    "Может быть интересно (нестандартные и курьёзные события ИБ)",
]
FIELDS = {
    "Атака": [
        "Страна жертвы",
        "Наименование группировки",
        "Предполагаемая дата атаки",
        "Затронутые отрасли/компании",
        "Метод первоначального доступа",
        "Используемые инструменты злоумышленником",
        "Идентификатор используемых уязвимостей",
        "Наличие индикаторов компрометации",
    ],
    "Уязвимость": [
        "Наименование уязвимости",
        "Наименование релевантного уязвимого сервиса",
        "Краткое описание уязвимости",
        "Наличие обновления",
        "Временные решения",
        "Наличие эксплойта",
        "Идентификатор уязвимости CVE",
        "Оценка CVE",
        "Метрики CVSS",
        "Последствия компрометации сервиса",
    ],
}
STYLE = {
    "tech": (
        "- group: строго одно из: Атака — кибератака, инцидент, кампания или активность "
        "группировки, в том числе отчёты о них; Уязвимость — конкретная уязвимость или "
        "эксплойт; Инфо — статистика, рынок, законы и прочее;",
        "2–3 предложения",
        '"group": "Атака", ',
    ),
    "brief": (
        "- tags: номера всех подходящих тегов, сначала 1 или 2, "
        "затем тематические по убыванию важности: "
        + "; ".join(f"{i}. {t}" for i, t in enumerate(TAGS, 1))
        + ";",
        "3–4 предложения",
        '"tags": [1, 8], ',
    ),
}

RERANK = (
    "Ты аналитик информационной безопасности и отбираешь новости для читателя с таким "
    "профилем.\n"
    "Интересы: {interests}\n"
    "Используемое ПО: {stack}\n"
    "Аудитория: {audience}\n"
    "{feedback}\n"
    "Для каждой новости верни:\n"
    "- relevance: целое число от 0 до 10 — насколько новость важна именно этому читателю: "
    "оценивай по его интересам\n"
    "  и ПО; критичная уязвимость в продукте вне его ПО и интересов — не выше 5;\n"
    "{classify}\n"
    "- title: заголовок на русском до 100 символов;\n"
    "- reason: одно предложение на русском — почему это важно читателю;\n"
    "- summary: {summary} на русском — суть новости языком, понятным этой аудитории.\n"
    "\n"
    "Используй только факты из переданного текста, ничего не додумывай. Новости не про ИТ "
    "и ИБ и обзоры,\n"
    "где собраны несколько несвязанных новостей, оценивай от 0 до 2.\n"
    "Ответ строго в формате JSON:\n"
    '{{"items": [{{"id": "s1", "relevance": 7, {example}"title": "...", "reason": "...", '
    '"summary": "..."}}]}}'
)

FINAL = (
    "Ты готовишь дайджест по ИТ и ИБ. Аудитория: {audience}. Тебе дан пронумерованный "
    "список отобранных новостей.\n"
    "1. Найди дубликаты — разные публикации об одном и том же событии — и верни их "
    "группами номеров.\n"
    "2. Сформулируй 3–5 главных выводов на русском, по одному предложению, только по "
    "фактам из списка, без общих слов,\n"
    "   и для каждого укажи номера новостей, на которых он основан.\n"
    'Ответ строго в формате JSON: {{"duplicates": [[1, 4]], "points": [{{"text": "...", '
    '"news": [2]}}]}}'
)

CARD = (
    "Ты аналитик SOC. Заполни карточку новости на русском строго по её тексту, без "
    "домыслов.\n"
    "Английский текст переводи, названия ПО, группировок, файлов, CVE и векторы CVSS "
    "оставляй как есть.\n"
    "Если сведений нет, пиши «нет данных».\n"
    "Поля карточки атаки: {attack}.\n"
    "Поля карточки уязвимости: {vuln}.\n"
    "Для атаки также верни russia: true, если жертвы находятся в России,\n"
    "и sector: true, если затронуты энергетика или промышленность.\n"
    "Для уязвимости также верни exploit: true, если есть публичный эксплойт, PoC или "
    "эксплуатация в атаках.\n"
    "Ответ строго в формате JSON:\n"
    '{{"items": [{{"id": "s1", "fields": {{"Поле": "значение"}}, "russia": false, '
    '"sector": false, "exploit": false}}]}}'
)


class LLM:
    def __init__(self, storage):
        self.storage, self.model, self.stats = storage, os.getenv("LLM_MODEL"), Counter()
        self.options = (
            {"reasoning_effort": effort} if (effort := os.getenv("LLM_REASONING")) else {}
        )
        self.strict = True
        self.client = OpenAI(
            api_key=os.getenv("LLM_API_KEY"),
            base_url=os.getenv("LLM_BASE_URL", "https://ai.api.cloud.yandex.net/v1"),
            timeout=120,
            max_retries=1,
        )

    def ask(self, system, user, field="items"):
        key = (
            "llm:"
            + hashlib.sha1(f"{self.model}\n{self.options}\n{system}\n{user}".encode()).hexdigest()
        )
        if (cached := self.storage.get(key)) is not None:
            self.stats["ответов LLM из кэша"] += 1
            return json.loads(cached)
        for strict in (self.strict, False):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    temperature=0,
                    **self.options,
                    **({"response_format": {"type": "json_object"}} if strict else {}),
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                data = parse(resp.choices[0].message.content, field)
            except Exception as e:
                print(f"LLM: {e}")
                continue
            self.strict = strict
            self.stats["запросов к LLM"] += 1
            self.stats["токенов"] += resp.usage.total_tokens if resp.usage else 0
            self.storage.put(key, json.dumps(data, ensure_ascii=False))
            return data
        self.stats["ошибок LLM"] += 1


def parse(text, field):
    data = json.loads(text[text.find("{") : text.rfind("}") + 1])
    if not isinstance(data, dict) or not isinstance(data.get(field), list):
        raise ValueError(f"в ответе нет списка {field}")
    return data


def listed(value):
    return value if isinstance(value, list) else []


def answers(data):
    return {str(x.get("id")): x for x in listed((data or {}).get("items")) if isinstance(x, dict)}


def numbers(refs, size):
    return [i - 1 for i in listed(refs) if isinstance(i, int) and 0 < i <= size]


def number(value):
    try:
        return min(10.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return None


def field(fields, name):
    key = (
        name if name in fields else next(iter(get_close_matches(name, list(fields), 1, 0.8)), None)
    )
    return str(fields.get(key) or "нет данных")


def card(i, s, size=600):
    meta = [
        s.category and f"тип: {s.category}",
        ", ".join(s.cves[:5]),
        s.cvss and f"CVSS {s.cvss} {s.vector or ''}".strip(),
        s.kev and "в каталоге CISA KEV: " + ", ".join(s.kev[:3]),
    ]
    return f"[s{i}] {s.main.title}\n{'; '.join(filter(None, meta))}\n{s.main.text[:size]}"


def hint(feedback):
    good = [t for t, label in feedback.values() if label > 0][-5:]
    bad = [t for t, label in feedback.values() if label < 0][-5:]
    return "".join(
        [
            f"Читатель отметил как полезные: {'; '.join(good)}\n" if good else "",
            f"Читатель отметил как бесполезные: {'; '.join(bad)}\n" if bad else "",
        ]
    )


def priority(s, russia=False, sector=False, exploit=False):
    if s.category == "Атака":
        return "Высокий" if russia and sector else "Средний" if russia else "Низкий"
    if s.category == "Уязвимость":
        return "Высокий" if exploit or s.kev else "Средний"
    return "Новости ТГ" if s.from_tg else "Новости"


def judge(batch, system, llm):
    data = llm.ask(
        system, "Новости:\n\n" + "\n\n".join(card(i, s) for i, s in enumerate(batch, 1))
    )
    if data is None and len(batch) > 1:
        half = len(batch) // 2
        return judge(batch[:half], system, llm) + judge(batch[half:], system, llm)
    items = answers(data)
    return [items.get(f"s{i}", {}) for i in range(1, len(batch) + 1)]


def rerank(stories, profile, llm, feedback, top=40, size=8, floor=3):
    head, (classify, summary, example) = stories[:top], STYLE[profile.format]
    system = RERANK.format(
        interests=" ".join(profile.interests.split()),
        audience=profile.audience,
        stack=", ".join(profile.stack) or "не указано",
        feedback=hint(feedback),
        classify=classify,
        summary=summary,
        example=example,
    )
    for start in range(0, len(head), size):
        batch = head[start : start + size]
        for s, item in zip(batch, judge(batch, system, llm)):
            if (relevance := number(item.get("relevance"))) is not None:
                s.relevance, s.score = relevance, 0.5 * s.score + 0.05 * relevance
            s.category = item.get("group") if item.get("group") in GROUPS else None
            s.tags = [
                TAGS[t - 1]
                for t in listed(item.get("tags"))
                if isinstance(t, int) and 0 < t <= len(TAGS)
            ]
            s.title, s.reason, s.summary = (
                item.get("title"),
                item.get("reason"),
                item.get("summary"),
            )
    return sorted(
        (s for s in head if s.relevance is None or s.relevance >= floor), key=lambda s: -s.score
    )


def finalize(stories, profile, llm, close):
    judged = [s for s in stories if s.relevance is not None]
    if not judged:
        return stories, []
    news = "\n".join(
        f"{i}. {s.title}: {s.summary}" + (f" В CISA KEV: {', '.join(s.kev)}." if s.kev else "")
        for i, s in enumerate(judged, 1)
    )
    answer = llm.ask(FINAL.format(audience=profile.audience), news, "points") or {}
    owner = list(range(len(judged)))
    for group in listed(answer.get("duplicates")):
        ids = sorted({owner[i] for i in numbers(group, len(judged))})
        for i in ids[1:]:
            main, other = judged[ids[0]], judged[i]
            if not set(main.cves) & set(other.cves) and (
                main.cves and other.cves or close(main, other) < MIN_SIM
            ):
                continue
            main.articles += other.articles
            other.articles = []
            owner = [ids[0] if o == i else o for o in owner]
    points = [
        (
            p["text"],
            [
                judged[i]
                for i in dict.fromkeys(owner[i] for i in numbers(p.get("news"), len(judged)))
            ],
        )
        for p in listed(answer.get("points"))
        if isinstance(p, dict) and isinstance(p.get("text"), str)
    ]
    return [s for s in stories if s.articles], [(text, refs) for text, refs in points if refs]


def cards(stories, llm):
    system = CARD.format(attack="; ".join(FIELDS["Атака"]), vuln="; ".join(FIELDS["Уязвимость"]))
    for s in (s for s in stories if s.category in FIELDS):
        if not (item := answers(llm.ask(system, card(1, s, 4000))).get("s1")):
            continue
        fields = item.get("fields") if isinstance(item.get("fields"), dict) else {}
        s.card = {f: field(fields, f) for f in FIELDS[s.category]}
        s.priority = priority(
            s, item.get("russia") is True, item.get("sector") is True, item.get("exploit") is True
        )
