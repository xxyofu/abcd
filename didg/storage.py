import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from didg.models import Article, config

FMT = "%Y-%m-%d %H:%M:%S.%f"
SCHEMA = """
create table if not exists articles (id text primary key, url text, title text, text text,
                                     source text, published text, cves text, refs text);
create table if not exists embeddings (article_id text primary key, vec blob);
create table if not exists feedback (profile text, article_id text, ts text, label integer,
                                     primary key (profile, article_id, ts));
create table if not exists cache (key text primary key, response text);
create table if not exists picks (profile text, article_id text, day text,
                                  primary key (profile, article_id));
"""


def stamp(dt):
    return dt.astimezone(UTC).strftime(FMT)


class Storage:
    def __init__(self, path="data/digest.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def write(self, sql, rows):
        with self.db:
            return self.db.executemany(sql, rows).rowcount

    def add_articles(self, articles):
        rows = [
            (
                a.id,
                a.url,
                a.title,
                a.text,
                a.source,
                stamp(a.published),
                json.dumps(a.cves),
                json.dumps(a.refs),
            )
            for a in articles
        ]
        return self.write("insert or ignore into articles values (?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def articles(self, since, until):
        rows = self.db.execute(
            "select id, url, title, text, source, published, cves, refs from articles "
            "where published > ? and published <= ? order by published",
            (stamp(since), stamp(until)),
        )
        return [
            Article(
                *r[:5], datetime.strptime(r[5], FMT).replace(tzinfo=UTC), *map(json.loads, r[6:])
            )
            for r in rows
        ]

    def embeddings(self, ids):
        marks = ", ".join("?" * len(ids))
        rows = self.db.execute(
            f"select article_id, vec from embeddings where article_id in ({marks})", ids
        )
        return {k: np.frombuffer(v, dtype=np.float32) for k, v in rows}

    def save_embeddings(self, vecs):
        self.write(
            "insert or replace into embeddings values (?, ?)",
            [(k, v.tobytes()) for k, v in vecs.items()],
        )
        return vecs

    def add_feedback(self, profile, prefix, label):
        ids = [
            r[0]
            for r in self.db.execute("select id from articles where id like ?", (prefix + "%",))
        ]
        if len(ids) == 1:
            self.write(
                "insert into feedback values (?, ?, ?, ?)",
                [(profile, ids[0], stamp(datetime.now(UTC)), label)],
            )
        return ids

    def feedback(self, profile):
        rows = self.db.execute(
            "select f.article_id, a.title, f.label from feedback f join articles a "
            "on a.id = f.article_id where f.profile = ? order by f.ts",
            (profile,),
        )
        return {i: (title, label) for i, title, label in rows}

    def add_picks(self, profile, ids, day):
        self.write(
            "insert into picks values (?, ?, ?) "
            "on conflict do update set day = min(day, excluded.day)",
            [(profile, i, day) for i in ids],
        )

    def shown(self, profile, day):
        return {
            r[0]
            for r in self.db.execute(
                "select article_id from picks where profile = ? and day < ?", (profile, day)
            )
        }

    def source_stats(self, profile, since):
        rows = self.db.execute(
            "select a.source, count(distinct a.id), substr(max(a.published), 1, 10), "
            "count(distinct p.article_id), count(case when f.label > 0 then 1 end), "
            "count(case when f.label < 0 then 1 end) from articles a "
            "left join picks p on p.article_id = a.id and p.profile = ?1 "
            "left join feedback f on f.article_id = a.id and f.profile = ?1 "
            "where a.published > ?2 group by a.source",
            (profile, stamp(since)),
        )
        keys = ("публикаций", "последняя", "в дайджесте", "полезно", "бесполезно")
        stats = {r[0]: dict(zip(keys, r[1:])) for r in rows}
        return [
            {
                "id": s["id"],
                "тип": s["type"],
                "вес": s.get("weight", 1.0),
                **stats.get(s["id"], {"публикаций": 0}),
            }
            for s in config()["sources"]
        ]

    def get(self, key):
        row = self.db.execute("select response from cache where key = ?", (key,)).fetchone()
        return row and row[0]

    def put(self, key, value):
        self.write("insert or replace into cache values (?, ?)", [(key, value)])
