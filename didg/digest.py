import re
from datetime import timedelta
from urllib.parse import urlparse

from didg.llm import GROUPS, TAGS

ORDER = {"Высокий": 0, "Средний": 1, "Низкий": 2}
REFS = 5


def esc(text):
    return re.sub(r"([\[\]])", r"\\\1", text)


def defang(url):
    host = urlparse(url).netloc
    return url.replace(host, re.sub(r"\.(?=[^.]*$)", "[.]", host), 1)


def short(tag):
    return tag.split(" (")[0]


def meta(s, profile):
    if profile.format == "brief":
        parts = [f"{s.first:%d.%m.%Y}", *map(short, s.tags)]
    else:
        parts = [
            f"**Приоритет: {s.priority}**",
            f"{s.first:%d.%m.%Y}",
            ", ".join(f"`{c}`" for c in s.cves[:3]),
            not s.card and s.cvss and f"CVSS {s.cvss}",
            s.kev and "в CISA KEV: " + ", ".join(s.kev[:3]),
            s.relevance is not None and f"релевантность {s.relevance:g}/10",
        ]
    return " · ".join(filter(None, parts + [f"id `{s.id}`"]))


def body(s, profile):
    if profile.format == "brief":
        return [s.summary]
    if s.card:
        lines = [f"{i}. {k}: {v}" for i, (k, v) in enumerate(s.card.items(), 1)]
    else:
        lines = [f"1. Краткое содержание: {s.summary}"]
        if s.refs:
            lines += [
                "2. Ссылки, на которые ссылается пост:",
                *[f"   - `{defang(r)}`" for r in s.refs[:REFS]],
            ]
            lines += [f"   - и ещё {len(s.refs) - REFS}"] if len(s.refs) > REFS else []
    return lines + ["", f"**Почему важно:** {s.reason}"]


def render(profile, stories, stats, points, now):
    start = now - timedelta(days=profile.days)
    lines = [
        f"# {profile.title}: дайджест ИТ/ИБ",
        "",
        f"**Период:** {start:%d.%m.%Y %H:%M} – {now:%d.%m.%Y %H:%M} UTC  ",
        f"**Аудитория:** {profile.audience}  ",
        f"**Интересы:** {' '.join(profile.interests.split())}  ",
        f"**Стек:** {', '.join(profile.stack)}",
    ]
    if points:
        lines += ["", "## Главное", ""]
        lines += [
            f"- {text} " + " · ".join(f"[{s.main.source}]({s.main.url})" for s in refs)
            for text, refs in points
        ]
    n = 0
    for section in GROUPS if profile.format == "tech" else TAGS:
        group = sorted(
            (s for s in stories if s.category == section),
            key=lambda s: (ORDER.get(s.priority, 3), -s.score),
        )
        lines += ["", f"## {short(section)}"] if group else []
        for s in group:
            n += 1
            links = " · ".join(f"[{source}]({url})" for url, source in s.links.items())
            lines += [
                "",
                f"### {n}. [{esc(s.title)}]({s.main.url})",
                "",
                meta(s, profile),
                "",
                *body(s, profile),
                "",
                f"**Источники:** {links}",
            ]
    lines += ["", "---", "", "**Отбор:** " + " · ".join(f"{k}: {v}" for k, v in stats.items()), ""]
    return "\n".join(lines)
