import json
import os
import subprocess
import sys
from datetime import UTC, datetime, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st
from dotenv import load_dotenv

from didg.agent import TASK, Agent
from didg.digest import render
from didg.evaluate import evaluate, result, summary
from didg.llm import LLM
from didg.models import PROFILES, Article, Profile, config
from didg.rank import select, vectors
from didg.storage import Storage

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
load_dotenv(ROOT / ".env")


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def commit():
    try:
        git = ["git", "rev-parse", "--short", "HEAD"]
        return subprocess.run(git, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return os.getenv("APP_VERSION", "нет данных")


@st.cache_resource(show_spinner="Подготовка: загрузка снимка публикаций и модели эмбеддингов…")
def prepare():
    articles = [Article(**row) for row in read_jsonl(ROOT / "examples/articles.jsonl")]
    for a in articles:
        a.published = datetime.fromisoformat(a.published)
    db = Storage()
    db.add_articles(articles)
    vectors(articles, db)
    return max(a.published for a in articles).astimezone(UTC).date(), commit()


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
    st.caption(
        "Выпуск с LLM занимает 2–5 минут, без LLM — до минуты. "
        "Пока он формируется, не меняйте параметры."
    )
    if st.button("Сформировать", type="primary"):
        with st.spinner("Отбор публикаций, склейка дублей, оценка и карточки…"):
            st.session_state.digest = build(name, day, interests, stack, use_llm)
    if not (digest := st.session_state.get("digest")):
        return
    st.download_button("Скачать Markdown", digest["markdown"], digest["file"], "text/markdown")
    choice = st.selectbox("Отметить сюжет для следующего выпуска", list(digest["stories"]))
    good, bad = st.columns(2)
    for column, label, mark in ((good, "👍 Полезно", 1), (bad, "👎 Бесполезно", -1)):
        if column.button(label) and choice:
            Storage().add_feedback(digest["profile"], digest["stories"][choice], mark)
            st.success("Отметка учтена: сформируйте выпуск заново")
    st.divider()
    st.markdown(digest["markdown"])


def eval_tab(use_llm):
    st.caption(
        "Выпуск каждой аудитории собирается только из примеров датасета организаторов "
        "и сравнивается с их разметкой: попадание в выпуск, группа, приоритет, теги."
    )
    if st.button("Запустить сверку"):
        kev, trust = context()
        lines = []
        with st.spinner("Сверка с датасетом…"):
            cases = read_jsonl(ROOT / "examples/dataset.jsonl")
            for name, pairs, info in evaluate(cases, kev, trust, use_llm):
                lines += [f"{name}: {summary(pairs)}"]
                lines += [f"  {case['name']}: {result(case, story)}" for case, story in pairs]
        st.session_state.eval = "\n".join(lines)
    if text := st.session_state.get("eval"):
        st.code(text, language=None, wrap_lines=True)


def agent_tab(name, has_llm):
    task = st.text_area("Задача агенту", TASK, height=100)
    apply = st.checkbox("Применять изменения к источникам")
    st.caption(
        "Без флажка агент проверяет источники и предлагает изменения, конфигурация не меняется."
    )
    if st.button("Запустить агента", disabled=not has_llm):
        db = Storage()
        with st.status("Агент работает…", expanded=True) as status:
            agent = Agent(Profile.load(name), db, LLM(db), lambda text: apply, status.text)
            try:
                report = agent.run(task)
                status.update(label="Агент закончил", state="complete")
            except Exception as e:
                report = f"Ошибка: {e}"
                status.update(label="Агент остановлен", state="error")
        st.session_state.agent = report, agent.applied
    if run := st.session_state.get("agent"):
        st.markdown(run[0])
        st.info("Применено: " + ("; ".join(run[1]) or "ничего"))


st.set_page_config(page_title="ИТ/ИБ-дайджест", layout="wide")
last_day, version = prepare()
login()
has_llm = bool(os.getenv("LLM_API_KEY"))
with st.sidebar:
    names = sorted(p.stem for p in PROFILES.glob("*.yaml"))
    name = st.selectbox(
        "Профиль", names, names.index("soc"), format_func=lambda n: Profile.load(n).title
    )
    profile = Profile.load(name)
    day = st.date_input("Выпуск на конец дня", last_day)
    interests = st.text_area(
        "Интересы", " ".join(profile.interests.split()), height=200, key=f"interests-{name}"
    )
    stack = st.text_input("Стек через запятую", ", ".join(profile.stack), key=f"stack-{name}")
    use_llm = st.toggle("Использовать LLM", has_llm, disabled=not has_llm)
    st.caption(f"Окно профиля: {profile.days} дн. · версия {version}")
digest, check, agent = st.tabs(["Дайджест", "Сверка с датасетом", "Агент"])
with digest:
    digest_tab(name, day, interests, stack, use_llm)
with check:
    eval_tab(use_llm)
with agent:
    agent_tab(name, has_llm)
