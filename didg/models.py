from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

SOURCES, PROFILES = Path("config/sources.yaml"), Path("config/profiles")


def config():
    return yaml.safe_load(SOURCES.read_text(encoding="utf-8"))


@dataclass
class Article:
    id: str
    url: str
    title: str
    text: str
    source: str
    published: datetime
    cves: list = field(default_factory=list)
    refs: list = field(default_factory=list)
    cvss: float = None
    vector: str = None
    kev: list = field(default_factory=list)


@dataclass
class Story:
    articles: list
    score: float = 0.0
    relevance: float = None
    category: str = None
    tags: list = field(default_factory=list)
    priority: str = None
    card: dict = field(default_factory=dict)
    title: str = None
    summary: str = None
    reason: str = None

    @property
    def main(self):
        return max(self.articles, key=lambda a: len(a.text))

    @property
    def id(self):
        return self.main.id[:8]

    @property
    def links(self):
        return {a.url: a.source for a in sorted(self.articles, key=lambda a: a.published)}

    @property
    def sources(self):
        return sorted({a.source for a in self.articles})

    @property
    def cves(self):
        return list(dict.fromkeys(c for a in self.articles for c in a.cves))

    @property
    def refs(self):
        return list(dict.fromkeys(r for a in self.articles for r in a.refs))

    @property
    def cvss(self):
        return max((a.cvss for a in self.articles if a.cvss is not None), default=None)

    @property
    def vector(self):
        return max(self.articles, key=lambda a: a.cvss or 0).vector

    @property
    def kev(self):
        return list(dict.fromkeys(c for a in self.articles for c in a.kev))

    @property
    def from_tg(self):
        return all("//t.me/" in a.url for a in self.articles)

    @property
    def first(self):
        return min(a.published for a in self.articles)

    @property
    def published(self):
        return max(a.published for a in self.articles)

    @property
    def text(self):
        return f"{' '.join(a.title for a in self.articles)} {self.main.text}".lower()


@dataclass
class Profile:
    name: str
    title: str
    audience: str
    days: int
    interests: str
    format: str = "tech"
    stack: list = field(default_factory=list)
    include_keywords: list = field(default_factory=list)
    exclude_keywords: list = field(default_factory=list)
    min_cvss: float = 0.0
    max_items: int = 20
    weights: dict = field(default_factory=dict)

    @classmethod
    def load(cls, name):
        return cls(name, **yaml.safe_load((PROFILES / f"{name}.yaml").read_text(encoding="utf-8")))
