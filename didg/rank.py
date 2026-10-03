import math
import os
import re
import textwrap
import time
from collections import defaultdict
from datetime import timedelta
from functools import cache
from itertools import combinations

import numpy as np

from didg.enrich import enrich
from didg.llm import TAGS, cards, finalize, priority, rerank
from didg.models import Story

WEIGHTS = {
    "semantic": 0.3,
    "stack": 0.2,
    "keywords": 0.1,
    "severity": 0.2,
    "freshness": 0.1,
    "coverage": 0.1,
    "feedback": 0.15,
}
RUSSIA, SECTOR, EXPLOIT = (
    r"росси|\bрф\b|russia",
    r"энерг|промышлен|energy|industr",
    r"эксплойт|exploit|\bpoc\b|в атаках",
)
GUESS = {
    "Уязвимость": r"уязвимост|vulnerab|0-day|zero-day|эксплойт|exploit|\brce\b|\bpoc\b",
    "Атака": r"атак|attack|взлом|hack|\bapt|группировк|ransomware|шифровальщ|вымогател"
    r"|фишинг|phishing|кампани|campaign",
}
HINTS = {
    TAGS[2]: r"млн|млрд|ущерб|убыт|million|billion",
    TAGS[3]: r"\bкии\b|критическ\w* инфраструктур|аэропорт|авиа|железнодорож|больниц",
    TAGS[4]: r"энерг|электросет|нефт|energy",
    TAGS[5]: r"промышлен|завод|машиностро|scada|асу тп|industrial",
    TAGS[7]: r"утечк|слив|персональн|leak|breach",
    TAGS[8]: r"закон|минцифр|госдум|фстэк|регулятор|штраф|\bсуд",
    TAGS[9]: r"android|iphone|whatsapp|telegram|госуслуг|мессендж|смартфон|банковск",
    TAGS[10]: r"конференц|форум|кадр|ваканс|обучени",
}


@cache
def model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer("intfloat/multilingual-e5-small")


def encode(texts):
    return model().encode(texts, batch_size=32, normalize_embeddings=True).astype(np.float32)


def query(profile):
    return encode([f"query: {profile.interests} {', '.join(profile.stack)}"])[0]


def embed(articles):
    return encode([f"passage: {a.title}. {a.text[:500]}" for a in articles])


def semantic(sims):
    return np.clip((sims - 0.7) / 0.2, 0, 1)


def vectors(articles, storage):
    vecs = storage.embeddings([a.id for a in articles])
    if missing := [a for a in articles if a.id not in vecs]:
        vecs |= storage.save_embeddings(dict(zip([a.id for a in missing], embed(missing))))
    return np.vstack([vecs[a.id] for a in articles])


def linked(a, b, sim):
    if a.cves and b.cves:
        return 2 * len(set(a.cves) & set(b.cves)) > len(set(a.cves) | set(b.cves))
    close = abs(a.published - b.published) <= timedelta(hours=72)
    return close and (sim >= 0.6 or a.title.lower() == b.title.lower())


def centered(vecs):
    shifted = vecs - vecs.mean(0)
    return shifted / (np.linalg.norm(shifted, axis=1, keepdims=True) + 1e-9)


def group(articles, vecs):
    parent, sims = list(range(len(articles))), vecs @ vecs.T

    def root(i):
        while parent[i] != i:
            i = parent[i]
        return i

    for i, j in combinations(range(len(articles)), 2):
        if linked(articles[i], articles[j], sims[i, j]):
            parent[root(i)] = root(j)
    groups = defaultdict(list)
    for i, a in enumerate(articles):
        groups[root(i)].append(a)
    return [Story(g) for g in groups.values()]


@cache
def term(t):
    stem = re.escape(re.sub(r"(?<=\w{4})[а-яё]$", "", t.lower()))
    return re.compile(rf"(?<!\w){stem}" + (r"(?![a-zа-яё])" if len(t) <= 4 else ""))


def found(text, terms):
    return [t for t in terms if term(t).search(text)]


def affinity(sims):
    return float(np.clip((sims.max(initial=0) - 0.85) / 0.1, 0, 1))


def score(s, profile, vec, q, marked, labels, now):
    severity = max((s.cvss or 0) / 10, 0.9 * bool(s.kev))
    if not s.kev and (s.cvss or 0) < profile.min_cvss:
        severity /= 2
    parts = {
        "semantic": semantic(q @ vec),
        "stack": min(1, len(found(s.text, profile.stack)) / 2),
        "keywords": min(1, len(found(s.text, profile.include_keywords)) / 2),
        "severity": severity,
        "freshness": math.exp(-(now - s.published) / timedelta(days=max(2, profile.days / 2))),
        "coverage": min(1, math.log(1 + len(s.sources)) / math.log(4)),
        "feedback": affinity(marked[labels > 0] @ vec) - affinity(marked[labels < 0] @ vec),
    }
    weights = WEIGHTS | profile.weights
    return float(sum(weights[k] * v for k, v in parts.items()))


def allowed(s, profile, skip):
    if skip & {a.id for a in s.articles}:
        return False
    return (
        s.kev
        or found(s.text, profile.stack + profile.include_keywords)
        or not found(s.text, profile.exclude_keywords)
    )


def fill(s, profile):
    titles = " ".join(a.title for a in s.articles).lower()
    if profile.format == "tech":
        s.category = s.category or next(
            (g for g, p in GUESS.items() if re.search(p, titles)),
            "Уязвимость" if s.cves else "Инфо",
        )
    else:
        s.tags = s.tags or [t for t, p in HINTS.items() if re.search(p, titles)]
        if not set(s.tags) & set(TAGS[:2]):
            s.tags = [TAGS[0] if re.search(RUSSIA, s.text) else TAGS[1], *s.tags]
        s.category = next((t for t in s.tags if t not in TAGS[:2]), TAGS[-1])
    s.title = s.title or s.main.title
    s.reason = s.reason or explain(s, profile)
    s.summary = s.summary or textwrap.shorten(s.main.text, 300, placeholder="…")


def explain(s, profile):
    stack, keywords = found(s.text, profile.stack), found(s.text, profile.include_keywords)
    reasons = [
        stack and "затрагивает " + ", ".join(stack),
        s.kev and "эксплуатируется (CISA KEV)" or (s.cvss or 0) >= 7 and f"CVSS {s.cvss}",
        keywords and "темы: " + ", ".join(keywords),
        len(s.sources) > 1 and f"источников: {len(s.sources)}",
    ]
    return "; ".join(r for r in reasons if r) or "близко к интересам профиля"


def select(profile, storage, now, kev_url, llm=None, nvd=True, trust=None):
    started = time.time()
    articles = storage.articles(now - timedelta(days=profile.days), now)
    stats = {"публикаций": len(articles), "источников": len({a.source for a in articles})}
    if not articles:
        return [], stats, []
    enrich(articles, storage, kev_url, os.getenv("NVD_API_KEY"), 40 if nvd else 0)
    vecs = vectors(articles, storage)
    centered_vecs, row = centered(vecs), {a.id: i for i, a in enumerate(articles)}
    stories = group(articles, centered_vecs)
    feedback = storage.feedback(profile.name)
    skip = storage.shown(profile.name, f"{now:%Y-%m-%d}") | {
        k for k, (_, label) in feedback.items() if label < 0
    }
    kept = [s for s in stories if allowed(s, profile, skip)]
    marked = storage.embeddings(list(feedback))
    marked_vecs = np.array(list(marked.values())).reshape(-1, vecs.shape[1])
    labels = np.array([feedback[k][1] for k in marked])
    q, trust = query(profile), trust or {}
    for s in kept:
        weight = max(trust.get(a.source, 1.0) for a in s.articles)
        s.score = weight * score(s, profile, vecs[row[s.main.id]], q, marked_vecs, labels, now)
    kept.sort(key=lambda s: -s.score)
    selected = (rerank(kept, profile, llm, feedback) if llm else kept)[: profile.max_items]
    for s in selected:
        fill(s, profile)

    def close(a, b):
        return float(centered_vecs[row[a.main.id]] @ centered_vecs[row[b.main.id]])

    final, points = finalize(selected, profile, llm, close) if llm and selected else (selected, [])
    for s in final:
        s.category = "Инфо" if profile.format == "tech" and s.from_tg else s.category
    if llm and profile.format == "tech":
        cards(final, llm)
    for s in final:
        s.priority = s.priority or priority(
            s, *(bool(re.search(p, s.text)) for p in (RUSSIA, SECTOR, EXPLOIT))
        )
    merged = len(articles) - len(stories) + len(selected) - len(final)
    stats |= {
        "сюжетов": len(stories),
        "дублей объединено": merged,
        "отсеяно": len(stories) - len(kept),
        "в дайджесте": len(final),
        **(llm.stats if llm else {}),
        "секунд": round(time.time() - started, 1),
    }
    return final, stats, points
