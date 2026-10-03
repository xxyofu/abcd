import hashlib
import re
import ssl
import textwrap
import warnings
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import certifi
import feedparser
import httpx
import trafilatura
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from didg.enrich import load_kev
from didg.models import Article, config

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
EPOCH, LIMIT = datetime(2000, 1, 1, tzinfo=UTC), 20000
TLS = ssl.create_default_context(cafile=certifi.where())
TLS.load_verify_locations(Path(__file__).parents[1] / "config/russian_trusted_root_ca.pem")
http = httpx.Client(
    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    timeout=30,
    follow_redirects=True,
    verify=TLS,
)


def get(url):
    return http.get(url).raise_for_status()


def canonical_url(url):
    p = urlparse(url)
    query = urlencode(
        [(k, v) for k, v in parse_qsl(p.query) if not k.startswith("utm_") and k != "fbclid"]
    )
    return urlunparse(
        (p.scheme, p.netloc.lower(), p.path.rstrip("/") or p.path, p.params, query, "")
    )


def clean(html):
    return re.sub(
        r"\s+", " ", BeautifulSoup(html or "", "html.parser").get_text(" ", strip=True)
    ).strip()


def make_article(url, title, text, source, published, **extra):
    url = canonical_url(url)
    return Article(
        hashlib.sha1(url.encode()).hexdigest(),
        url,
        clean(title),
        clean(text),
        source,
        published,
        **extra,
    )


def full_text(url):
    try:
        return trafilatura.extract(get(url).text)
    except Exception:
        return None


def page(url, source, title=""):
    doc = trafilatura.bare_extraction(get(url).text, url=url, with_metadata=True)
    if doc and doc.date and doc.text:
        published = datetime.fromisoformat(doc.date).replace(tzinfo=UTC)
        title = (
            doc.title
            if doc.title and (len(title) < 20 or doc.title.lower() in title.lower())
            else title
        )
        return make_article(url, title, doc.text[:LIMIT], source, published)


def posts(html, source, since):
    result = []
    for post in BeautifulSoup(html, "html.parser").select(".tgme_widget_message"):
        body, link = (
            post.select_one(".js-message_text"),
            post.select_one("a.tgme_widget_message_date"),
        )
        if not body or not link or not link.time:
            continue
        refs = list(
            dict.fromkeys(
                a["href"] for a in body.select("a[href^=http]") if "//t.me/" not in a["href"]
            )
        )
        for br in body.find_all("br"):
            br.replace_with("\n")
        text, published = body.get_text().strip(), datetime.fromisoformat(link.time["datetime"])
        if text and published > since:
            title = textwrap.shorten(text, 120, placeholder="…")
            result.append(
                make_article(
                    link["href"].split("?")[0], title, text[:LIMIT], source, published, refs=refs
                )
            )
    return result


def discover(url):
    resp = get(url)
    if feedparser.parse(resp.content).entries:
        return url
    link = BeautifulSoup(resp.text, "html.parser").select_one(
        "link[type$='rss+xml'], link[type$='atom+xml']"
    )
    return urljoin(url, link["href"]) if link else url


def site_links(url, limit=20):
    page = urlparse(url)
    found = {
        urljoin(url, a["href"]).split("#")[0]
        for a in BeautifulSoup(get(url).text, "html.parser").select("a[href]")
    }
    links = [
        urlparse(u) for u in found if urlparse(u).netloc == page.netloc and not urlparse(u).query
    ]
    inside = [
        u
        for u in links
        if u.path.startswith(page.path) and u.path.rstrip("/") != page.path.rstrip("/")
    ]
    return [u.geturl() for u in (inside or sorted(links, key=lambda u: -len(u.path)))[:limit]]


def fetch_rss(src, since):
    match, result = re.compile(src.get("match", ""), re.I), []
    for e in feedparser.parse(get(src["url"]).content).entries:
        parsed = e.get("published_parsed") or e.get("updated_parsed")
        published, text = parsed and datetime(*parsed[:6], tzinfo=UTC), e.get("summary", "")
        if (
            not e.get("link")
            or not published
            or published <= since
            or not match.search(f"{e.get('title', '')} {text}")
        ):
            continue
        if len(text) < 500 and src.get("full_text", True):
            text = full_text(e.link) or text
        result.append(make_article(e.link, e.get("title", ""), text[:LIMIT], src["id"], published))
    return result


def fetch_tg(src, since):
    return posts(get(f"https://t.me/s/{src['channel']}").text, src["id"], since)


def fetch_html(src, since):
    links = {}
    for a in BeautifulSoup(get(src["url"]).text, "html.parser").select("a[href]"):
        url = urljoin(src["url"], a["href"]).split("#")[0]
        if re.search(src["pattern"], url):
            links[url] = links.get(url) or a.get_text(" ", strip=True)
    result = []
    for url, title in list(links.items())[: src.get("limit", 10)]:
        try:
            article = page(url, src["id"], title)
        except httpx.HTTPError:
            continue
        if article and article.published > since:
            result.append(article)
    return result


def fetch_kev(src, since):
    result = []
    for v in load_kev(src["url"], max_age=3600):
        added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=UTC)
        if added > since:
            title = f"{v['cveID']}: {v['vendorProject']} {v['product']} — {v['vulnerabilityName']}"
            text = f"{v['shortDescription']} {v['requiredAction']}"
            url = f"https://nvd.nist.gov/vuln/detail/{v['cveID']}"
            result.append(make_article(url, title, text, src["id"], added, cves=[v["cveID"]]))
    return result


FETCHERS = {"rss": fetch_rss, "tg": fetch_tg, "html": fetch_html, "kev": fetch_kev}


def fetch(src, since):
    try:
        return FETCHERS[src["type"]](src, since), None
    except Exception as e:
        return [], e


def source_id(url):
    p = urlparse(url)
    tg = p.netloc == "t.me"
    key = p.path.split("/")[1].lower() if tg else p.netloc.removeprefix("www.")
    for s in config()["sources"]:
        if key in (
            s.get("channel", "").lower(),
            urlparse(s.get("url", "")).netloc.removeprefix("www."),
        ):
            return s["id"]
    return "tg_" + key if tg else key


def fetch_url(url):
    try:
        if "//t.me/" in url:
            found = posts(get(f"{url}?embed=1").text, source_id(url), EPOCH)
            return found[0] if found else None
        return page(url, source_id(url))
    except Exception:
        return None
