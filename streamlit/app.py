import json
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st
from dotenv import load_dotenv

from didg.agent import CHECKED, Agent, signature
from didg.digest import render
from didg.evaluate import evaluate, result, summary
from didg.llm import LLM
from didg.models import PROFILES, SOURCES, Article, Profile, config
from didg.rank import select, vectors
from didg.storage import Storage

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
load_dotenv(ROOT / ".env")
CANDIDATES = [
    "https://t.me/alukatsky",
    "https://t.me/knowyouradversary",
    "https://t.me/ThreatHuntingFather",
    "https://www.comnews.ru/information_security",
    "https://securenews.ru/news/",
    "https://cybernews.com/security/",
]


class Probe(Agent):
    def __init__(self, *args, box, **kwargs):
        super().__init__(*args, **kwargs)
        self.box, self.probes, self.changes, self.steps = box, [], [], []

    def step(self, line):
        self.steps.append(line)
        self.box.markdown(line)

    def overview(self, days=30):
        found = super().overview(days)
        self.step(f"📊 Статистика подключённых источников: {len(found['источники'])}")
        return found

    def probe_source(self, url, pattern=""):
        self.box.update(label=f"Проверка {url}")
        try:
            found = super().probe_source(url, pattern)
        except Exception as e:
            found = {"ошибка": str(e)}
        self.probes.append((url, found))
        head = f"🔎 **{url}**" + (f" по шаблону `{pattern}`" if pattern else "")
        if "ссылки на странице" in found:
            self.step(f"{head}: RSS нет, {len(found['ссылки на странице'])} ссылок для шаблона")
        elif "ошибка" in found:
            self.step(f"{head}: {short(found)}")
        else:
            how = "" if pattern else f" ({way(found['источник'])})"
            self.step(
                f"{head}{how}: последняя {found['последняя']}, "
                f"{found['в день']} в день, ИБ {found['доля ИБ']:.0%}, "
                f"релевантность {found['релевантность профилю']}, "
                f"дубли {found['доля дублей с базой']:.0%}"
            )
        return found

    def set_source(self, **kwargs):
        try:
            done = super().set_source(**kwargs)
        except Exception as e:
            done = {"ошибка": str(e)}
        self.changes.append((kwargs, done))
        if "ошибка" in done:
            self.step(f"⛔ `{kwargs.get('id')}`: отклонено — {done['ошибка']}")
        elif "подключено" in done:
            self.step(f"✅ `{kwargs['id']}` подключён, вес {float(kwargs.get('weight', 1)):g}")
        else:
            self.step(f"⚖️ `{kwargs['id']}`: вес {done['вес']:g}")
        return done


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@st.cache_resource(show_spinner="Подготовка данных…")
def prepare():
    articles = [Article(**row) for row in read_jsonl(ROOT / "examples/articles.jsonl")]
    for a in articles:
        a.published = datetime.fromisoformat(a.published)
    db = Storage()
    db.add_articles(articles)
    vectors(articles, db)
    return max(a.published for a in articles).astimezone(UTC).date()


def context():
    sources = config()["sources"]
    kev = next((s["url"] for s in sources if s["type"] == "kev"), None)
    return kev, {s["id"]: s.get("weight", 1.0) for s in sources}


def login():
    password = os.getenv("APP_PASSWORD")
    if not password or st.session_state.get("signed_in"):
        return
    st.title("ИТ/ИБ-дайджест")
    with st.form("login"):
        user = st.text_input("Логин")
        secret = st.text_input("Пароль", type="password")
        if st.form_submit_button("Войти"):
            if (user, secret) == (os.getenv("APP_USER", "demo"), password):
                st.session_state.signed_in = True
                st.rerun()
            st.error("Неверный логин или пароль")
    st.stop()


def build(name, day, interests, stack, use_llm):
    profile, db = Profile.load(name), Storage()
    profile.interests = interests
    profile.stack = [t.strip() for t in stack.split(",") if t.strip()]
    now = datetime.combine(day, time.max, UTC)
    kev, trust = context()
    llm, nvd = LLM(db) if use_llm else None, bool(os.getenv("NVD_API_KEY"))
    stories, info, points = select(profile, db, now, kev, llm, nvd, trust)
    db.add_picks(name, [a.id for s in stories for a in s.articles], f"{now:%Y-%m-%d}")
    return {
        "profile": name,
        "file": f"{name}_{now:%Y-%m-%d}.md",
        "markdown": render(profile, stories, info, points, now),
        "stories": {f"{s.id} — {s.title}": s.id for s in stories},
    }


def digest_tab(name, day, interests, stack, use_llm):
    if st.button("Сформировать", type="primary"):
        with st.spinner("Формирование выпуска…"):
            st.session_state.digest = build(name, day, interests, stack, use_llm)
    if not (digest := st.session_state.get("digest")):
        return
    choice, good, bad, save = st.columns([5, 2, 2, 2], vertical_alignment="bottom")
    story = choice.selectbox("Отметить сюжет", list(digest["stories"]))
    for column, label, mark in ((good, "👍 Полезно", 1), (bad, "👎 Бесполезно", -1)):
        if column.button(label) and story:
            Storage().add_feedback(digest["profile"], digest["stories"][story], mark)
            st.toast("Отметка учтена")
    save.download_button("Скачать .md", digest["markdown"], digest["file"], "text/markdown")
    st.markdown(digest["markdown"])


def eval_tab(use_llm):
    if st.button("Запустить сверку", type="primary"):
        kev, trust = context()
        tables = []
        with st.spinner("Сверка…"):
            cases = read_jsonl(ROOT / "examples/dataset.jsonl")
            for name, pairs, info in evaluate(cases, kev, trust, use_llm):
                rows = [
                    {"Пример": case["name"], "Результат": result(case, s)} for case, s in pairs
                ]
                tables.append((Profile.load(name).title, summary(pairs), rows))
        st.session_state.eval = tables
    for title, line, rows in st.session_state.get("eval", []):
        st.subheader(title)
        st.write(line)
        st.dataframe(rows, hide_index=True)


def same(a, b):
    return a.rstrip("/").lower().split("://")[-1] == b.rstrip("/").lower().split("://")[-1]


def short(found):
    if "ссылки на странице" in found:
        return "RSS не найден"
    return "сайт закрыт (403)" if "403" in found["ошибка"] else found["ошибка"][:100]


def way(src):
    return {
        "tg": "Telegram",
        "rss": f"RSS {src.get('url')}",
        "html": f"шаблон {src.get('pattern')}",
    }.get(src["type"], src["type"])


def verdict(url, agent):
    tried = [found for probed, found in agent.probes if same(probed, url)]
    found = next((f for f in reversed(tried) if "ошибка" not in f), tried[-1] if tried else None)
    if not found or "ошибка" in found:
        return {"Источник": url, "Решение": short(found) if found else "не проверен"}
    src, decision = found["источник"], "не подключать"
    for args, done in agent.changes:
        if args.get("type") in CHECKED and signature(args) == signature(src):
            weight = float(args.get("weight", 1))
            decision = f"подключить, вес {weight:g}" if "подключено" in done else done["ошибка"]
    return {
        "Источник": url,
        "Сбор": way(src),
        "Последняя": str(found["последняя"]),
        "В день": found["в день"],
        "Доля ИБ": f"{found['доля ИБ']:.0%}",
        "Релевантность": found["релевантность профилю"],
        "Дубли": f"{found['доля дублей с базой']:.0%}",
        "Решение": decision,
    }


def review(name, urls):
    links = [u.strip() for u in urls.splitlines() if u.strip()]
    task = f"Проверь источники-кандидаты: {', '.join(links)}. Подключи только полезные."
    db, answer = Storage(), ""
    with (
        st.status("Агент проверяет источники…", expanded=True) as box,
        tempfile.TemporaryDirectory() as tmp,
    ):
        sandbox = Path(tmp) / "sources.yaml"
        shutil.copy(SOURCES, sandbox)
        agent = Probe(
            Profile.load(name),
            db,
            LLM(db),
            lambda text: True,
            lambda line: None,
            sources=sandbox,
            box=box,
        )
        try:
            answer = agent.run(task)
            box.update(label="Ход работы агента", state="complete")
        except Exception as e:
            box.update(label=f"Ошибка: {e}", state="error")
        before = set(SOURCES.read_text(encoding="utf-8").splitlines())
        added = [s for s in sandbox.read_text(encoding="utf-8").splitlines() if s not in before]
    rows = [verdict(url, agent) for url in links]
    return {"steps": agent.steps, "rows": rows, "answer": answer, "added": added}


def agent_tab(name):
    st.caption(
        "Агент — модель с инструментами: сама проверяет кандидатов, решает, какие подключить, "
        "и задаёт им вес. Код не даёт подключить непроверенный источник; изменения пишутся "
        "в копию config/sources.yaml."
    )
    urls = st.text_area("Источники-кандидаты", "\n".join(CANDIDATES), height=170)
    if st.button("Проверить источники", type="primary"):
        st.session_state.agent = review(name, urls)
    elif report := st.session_state.get("agent"):
        with st.status("Ход работы агента", state="complete", expanded=True):
            for line in report["steps"]:
                st.markdown(line)
    if not (report := st.session_state.get("agent")):
        return
    st.subheader("Решения", anchor=False)
    st.dataframe(report["rows"], hide_index=True)
    if report["answer"]:
        st.subheader("Вывод агента", anchor=False)
        st.markdown(report["answer"])
    if report["added"]:
        st.subheader("Записано в sources.yaml", anchor=False)
        st.code("\n".join(report["added"]), "yaml")


st.set_page_config(page_title="ИТ/ИБ-дайджест", layout="wide")
st.html("<style>[data-testid='InputInstructions'] {display: none}</style>")
last_day = prepare()
login()
use_llm = bool(os.getenv("LLM_API_KEY"))
with st.sidebar:
    names = sorted(p.stem for p in PROFILES.glob("*.yaml"))
    name = st.selectbox(
        "Профиль", names, names.index("soc"), format_func=lambda n: Profile.load(n).title
    )
    profile = Profile.load(name)
    day = st.date_input("Дата выпуска", last_day)
    interests = st.text_area(
        "Интересы", " ".join(profile.interests.split()), height=200, key=f"interests-{name}"
    )
    stack = st.text_input("Стек", ", ".join(profile.stack), key=f"stack-{name}")
digest, check, sources = st.tabs(["Дайджест", "Сверка с датасетом", "Источники"])
with digest:
    digest_tab(name, day, interests, stack, use_llm)
with check:
    eval_tab(use_llm)
with sources:
    if use_llm:
        agent_tab(name)
    else:
        st.info("Для агента нужен LLM_API_KEY")
