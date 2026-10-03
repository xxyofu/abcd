from datetime import UTC, datetime, time

from didg.llm import LLM, TAGS
from didg.models import Article, Profile
from didg.rank import select
from didg.storage import Storage


def evaluate(cases, kev, trust, use_llm):
    for name in dict.fromkeys(c["profile"] for c in cases):
        own = [c for c in cases if c["profile"] == name]
        articles = [Article(**c["article"]) for c in own if c["article"]]
        for a in articles:
            a.published = datetime.fromisoformat(a.published)
        storage, profile = Storage(":memory:"), Profile.load(name)
        storage.add_articles(articles)
        now = datetime.combine(
            max(a.published for a in articles).astimezone(UTC).date(), time.max, UTC
        )
        profile.days = (now - min(a.published for a in articles)).days + 1
        stories, info, _ = select(
            profile, storage, now, kev, LLM(storage) if use_llm else None, True, trust
        )
        found = {a.id: s for s in stories for a in s.articles}
        yield name, [(c, c["article"] and found.get(c["article"]["id"])) for c in own], info


def tags(story):
    return {TAGS.index(t) + 1 for t in story.tags}


def summary(pairs):
    shown = [(c, s) for c, s in pairs if s]
    known = sum(1 for c, _ in pairs if c["article"])
    line = f"в выпуске {len(shown)} из {known}, источник недоступен у {len(pairs) - known}"
    if all("tags" in c for c, _ in pairs):
        tp = sum(len(tags(s) & set(c["tags"])) for c, s in shown)
        fp = sum(len(tags(s) - set(c["tags"])) for c, s in shown)
        fn = sum(len(set(c["tags"]) - tags(s)) for c, s in shown)
        region = sum(tags(s) & {1, 2} == set(c["tags"]) & {1, 2} for c, s in shown)
        p, r = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
        f1 = 2 * p * r / max(p + r, 1e-9)
        return (
            f"{line}; теги: precision {p:.2f}, recall {r:.2f}, F1 {f1:.2f}; "
            f"регион верен у {region} из {len(shown)}"
        )
    group = sum(s.category == c["group"] for c, s in shown)
    priority = sum(s.priority == c["priority"] for c, s in shown)
    return (
        f"{line}; группа верна у {group} из {len(shown)}, приоритет — у {priority} из {len(shown)}"
    )


def result(case, story):
    if not case["article"]:
        return "источник недоступен"
    if not story:
        return "не в выпуске"
    if "tags" in case:
        got, expected = f"теги {sorted(tags(story))}", f"{sorted(case['tags'])}"
    else:
        got, expected = (
            f"{story.category} · {story.priority}",
            f"{case['group']} · {case['priority']}",
        )
    return got if got.removeprefix("теги ") == expected else f"{got}, ожидалось {expected}"
