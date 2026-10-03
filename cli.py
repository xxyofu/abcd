import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

import typer
from dotenv import load_dotenv

from didg.agent import TASK, Agent
from didg.collect import fetch, fetch_url
from didg.digest import render
from didg.evaluate import evaluate, result, summary
from didg.llm import LLM
from didg.models import Article, Profile, config
from didg.rank import select
from didg.storage import Storage

load_dotenv()
app = typer.Typer()
SOURCES = config()["sources"]
KEV = next((s["url"] for s in SOURCES if s["type"] == "kev"), None)
TRUST = {s["id"]: s.get("weight", 1.0) for s in SOURCES}
STORED = ("id", "url", "title", "text", "source", "published", "cves", "refs")


@app.command()
def collect(days: int = 3, only: str = None):
    db, since, total = Storage(), datetime.now(UTC) - timedelta(days=days), 0
    sources = [s for s in SOURCES if s.get("weight", 1) > 0 and (not only or s["id"] == only)]
    with ThreadPoolExecutor(8) as pool:
        for src, (articles, error) in zip(sources, pool.map(lambda s: fetch(s, since), sources)):
            if error:
                typer.echo(f"{src['id']:<22} ошибка: {str(error)[:80]}")
                continue
            total += len(articles)
            typer.echo(
                f"{src['id']:<22}{len(articles):>5} получено{db.add_articles(articles):>5} новых"
            )
    typer.echo(f"Всего получено: {total}")


@app.command()
def urls(path: Path):
    links = [u.strip() for u in path.read_text(encoding="utf-8").splitlines() if u.strip()]
    with ThreadPoolExecutor(8) as pool:
        articles = list(pool.map(fetch_url, links))
    for link in (u for u, a in zip(links, articles) if not a):
        typer.echo(f"не удалось загрузить: {link}")
    found = [a for a in articles if a]
    typer.echo(f"Загружено: {len(found)} из {len(links)}, новых: {Storage().add_articles(found)}")


@app.command()
def stats(profile: str = "soc", days: int = 30):
    for row in Storage().source_stats(profile, datetime.now(UTC) - timedelta(days=days)):
        typer.echo(" · ".join(f"{k}: {v}" for k, v in row.items()))


@app.command()
def export(path: Path, days: int = 30):
    now = datetime.now(UTC)
    articles = Storage().articles(now - timedelta(days=days), now)
    rows = [
        json.dumps({k: getattr(a, k) for k in STORED}, ensure_ascii=False, default=str)
        for a in articles
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    typer.echo(f"Выгружено: {len(rows)}")


@app.command("import")
def load(path: Path):
    articles = [
        Article(**json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    for a in articles:
        a.published = datetime.fromisoformat(a.published)
    typer.echo(f"Прочитано: {len(articles)}, новых: {Storage().add_articles(articles)}")


@app.command()
def digest(
    profile: str = "soc",
    date: str = None,
    days: int = None,
    interests: str = None,
    stack: str = None,
    no_llm: bool = False,
    no_nvd: bool = False,
    out: Path = None,
):
    p, db = Profile.load(profile), Storage()
    p.interests, p.days = interests or p.interests, days or p.days
    p.stack = [t.strip() for t in stack.split(",")] if stack else p.stack
    now = (
        datetime.combine(datetime.fromisoformat(date), time.max, UTC)
        if date
        else datetime.now(UTC)
    )
    llm = LLM(db) if os.getenv("LLM_API_KEY") and not no_llm else None
    stories, info, points = select(p, db, now, KEV, llm, not no_nvd, TRUST)
    db.add_picks(p.name, [a.id for s in stories for a in s.articles], f"{now:%Y-%m-%d}")
    for i, s in enumerate(stories, 1):
        typer.echo(f"{i:>2}. [{s.score:.2f}] {s.id} {s.category} · {s.priority} | {s.title}")
    out = out or Path(f"output/{p.name}_{now:%Y-%m-%d}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(p, stories, info, points, now), encoding="utf-8")
    typer.echo(" · ".join(f"{k}: {v}" for k, v in info.items()) + f"\nДайджест: {out}")


@app.command("eval")
def check(path: Path, no_llm: bool = False):
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    for name, pairs, info in evaluate(
        cases, KEV, TRUST, bool(os.getenv("LLM_API_KEY")) and not no_llm
    ):
        typer.echo(f"{name}: {summary(pairs)}")
        for case, story in pairs:
            typer.echo(f"  {case['name']}: {result(case, story)}")
        typer.echo("  " + " · ".join(f"{k}: {v}" for k, v in info.items()))


@app.command()
def feedback(profile: str, story_id: str, mark: str):
    if mark not in ("+", "-"):
        raise typer.BadParameter("ожидается + или -")
    ids = Storage().add_feedback(profile, story_id, 1 if mark == "+" else -1)
    typer.echo("Учтено" if len(ids) == 1 else f"Совпадений с id: {len(ids)}")


@app.command()
def agent(task: str = typer.Argument(TASK), profile: str = "soc", yes: bool = False):
    if not os.getenv("LLM_API_KEY"):
        raise typer.BadParameter("нужен LLM_API_KEY")
    db = Storage()
    worker = Agent(
        Profile.load(profile), db, LLM(db), lambda text: yes or typer.confirm(text), typer.echo
    )
    typer.echo(worker.run(task))
    typer.echo("\nПрименено: " + ("; ".join(worker.applied) or "ничего"))


if __name__ == "__main__":
    app()
