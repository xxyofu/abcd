import json
import re
import time
from pathlib import Path

import httpx

KEV_CACHE = Path("data/kev.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}|BDU:\d{4}-\d{5}", re.I)
GENERIC = {
    "and",
    "for",
    "the",
    "multiple",
    "products",
    "windows",
    "server",
    "manager",
    "gateway",
    "driver",
    "suite",
}
MAIN_CVES = 3


def load_kev(url, max_age=86400):
    if url and (not KEV_CACHE.exists() or time.time() - KEV_CACHE.stat().st_mtime > max_age):
        try:
            KEV_CACHE.write_bytes(
                httpx.get(url, timeout=30, follow_redirects=True).raise_for_status().content
            )
        except httpx.HTTPError as e:
            print(f"KEV: {e}")
    return (
        json.loads(KEV_CACHE.read_text(encoding="utf-8"))["vulnerabilities"]
        if KEV_CACHE.exists()
        else []
    )


def nvd(cve, api_key):
    resp = httpx.get(
        NVD_URL, params={"cveId": cve}, headers={"apiKey": api_key} if api_key else {}, timeout=20
    )
    metrics = (
        (resp.raise_for_status().json().get("vulnerabilities") or [{}])[0]
        .get("cve", {})
        .get("metrics", {})
    )
    keys = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    data = next((metrics[k][0]["cvssData"] for k in keys if metrics.get(k)), {})
    return data.get("baseScore"), data.get("vectorString")


def about(v, head):
    words = [w for w in re.findall(r"\w{3,}", v["product"].lower()) if w not in GENERIC] or [
        v["vendorProject"].lower()
    ]
    return v["cveID"].lower() in head or any(w in head for w in words)


def enrich(articles, storage, kev_url, nvd_key, budget):
    kev, scores = {v["cveID"]: v for v in load_kev(kev_url)}, {}
    for a in articles:
        a.cves = list(
            dict.fromkeys(a.cves + [c.upper() for c in ID_RE.findall(f"{a.title} {a.text}")])
        )
        head = f"{a.title} {a.text[:400]}".lower()
        a.kev = [c for c in a.cves if c in kev and about(kev[c], head)]
    for cve in dict.fromkeys(
        c for a in reversed(articles) for c in a.cves[:MAIN_CVES] if c.startswith("CVE")
    ):
        cached = storage.get(f"cvss:{cve}")
        if cached is None and budget > 0:
            try:
                cached = json.dumps(nvd(cve, nvd_key))
            except httpx.HTTPError as e:
                print(f"NVD: {e}")
                budget = 0
                continue
            storage.put(f"cvss:{cve}", cached)
            budget -= 1
            time.sleep(0.7 if nvd_key else 6)
        scores[cve] = json.loads(cached) if cached else (None, None)
    for a in articles:
        known = [scores[c] for c in a.cves[:MAIN_CVES] if scores.get(c, (None,))[0]]
        a.cvss, a.vector = max(known, key=lambda x: x[0], default=(None, None))
