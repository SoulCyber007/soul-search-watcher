#!/usr/bin/env python3
"""Soul Search fast-lane watcher. Pure Python stdlib, zero LLM tokens.

Polls non-federal public feeds, matches them against inventory.json (what CSI-ISAC
member orgs actually run), and writes queue.json (hits only) for the daily
Claude exposure-match agent to triage. Sources: GitHub Advisory Database (GitHub),
EPSS (FIRST.org), OpenPhish community feed, and CISA KEV (U.S. federal). Every hit carries an
"origin" and "origin_type" so the community can see where it came from; federal feeds are
labelled origin_type "federal".

Usage:  python watcher.py            # live run
        python watcher.py --selftest # offline test with fixtures
"""
import json, os, re, sys, urllib.request, urllib.parse
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
UA = {"User-Agent": "SoulSearch-Watcher/1.0 (soulcyber.org)"}

def get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def load(name, default):
    p = os.path.join(HERE, name)
    return json.load(open(p)) if os.path.exists(p) else default

def terms(inv):
    """product alias -> display name; aliases of 3+ chars matched on word boundaries."""
    out = []
    for p in inv.get("products", []):
        for a in [p["name"]] + p.get("aliases", []):
            if len(a) >= 3:
                out.append((re.compile(r"(?<![a-z0-9])" + re.escape(a.lower()) + r"(?![a-z0-9])"), p["name"]))
    return out

def match_advisories(advs, inv, since):
    pats, hits = terms(inv), []
    for a in advs:
        if (a.get("updated_at") or a.get("published_at") or "") < since:
            continue
        pkgs = " ".join((v.get("package") or {}).get("name", "") for v in a.get("vulnerabilities", []))
        hay = f"{a.get('summary','')} {pkgs}".lower()
        found = sorted({n for rx, n in pats if rx.search(hay)})
        if found:
            hits.append({"kind": "advisory", "id": a.get("ghsa_id"), "cve": a.get("cve_id"),
                         "severity": a.get("severity"), "title": a.get("summary"),
                         "matched": found, "url": a.get("html_url"), "published": a.get("published_at"),
                         "origin": "GitHub Advisory Database", "origin_type": "private-sector"})
    return hits

def match_kev(doc, inv, since):
    """CISA Known Exploited Vulnerabilities catalog. U.S. federal source: labelled as such."""
    pats, hits = terms(inv), []
    for v in doc.get("vulnerabilities", []):
        if (v.get("dateAdded") or "") < since[:10]:
            continue
        hay = f"{v.get('vendorProject','')} {v.get('product','')} {v.get('vulnerabilityName','')}".lower()
        found = sorted({n for rx, n in pats if rx.search(hay)})
        if found:
            hits.append({"kind": "advisory", "id": "kev-" + v["cveID"].lower(), "cve": v["cveID"],
                         "severity": "exploited-in-the-wild", "title": f"{v.get('vendorProject','')} {v.get('product','')}: {v.get('vulnerabilityName','')}",
                         "matched": found, "url": "https://nvd.nist.gov/vuln/detail/" + v["cveID"],
                         "published": v.get("dateAdded"), "origin": "CISA Known Exploited Vulnerabilities catalog",
                         "origin_type": "federal"})
    return hits

def enrich_epss(hits):
    cves = [h["cve"] for h in hits if h.get("cve")]
    if not cves:
        return
    try:
        d = json.loads(get("https://api.first.org/data/v1/epss?cve=" + ",".join(cves)))
        sc = {r["cve"]: float(r["epss"]) for r in d.get("data", [])}
        for h in hits:
            if h.get("cve") in sc:
                h["epss"] = round(sc[h["cve"]], 4)
    except Exception as e:
        print("epss failed:", e, file=sys.stderr)

def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def match_phish(urls, inv):
    brands = [b.lower().replace(" ", "") for b in inv.get("brands", []) if len(b) >= 5]
    doms = [d.lower() for d in inv.get("domains", [])]
    hits = []
    for u in urls:
        host = (urllib.parse.urlparse(u).hostname or "").lower()
        if not host:
            continue
        why = None
        for d in doms:
            if host == d or host.endswith("." + d):
                why = f"impersonates/abuses member domain {d}"; break
            label = d.split(".")[0]
            hl = host.split(".")[-2] if host.count(".") else host
            if len(label) >= 5 and (label in host or lev(label, hl) <= 2) and not host.endswith("." + d):
                why = f"lookalike of {d}"; break
        if not why:
            for b in brands:
                if b in host:
                    why = f"brand lure: {b}"; break
        if why:
            hits.append({"kind": "phish", "url": u, "host": host, "why": why,
                         "origin": "OpenPhish community feed", "origin_type": "private-sector"})
    return hits

def run():
    inv = load("inventory.json", {})
    st = load("state.json", {"seen": [], "last_run": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()})
    hits, errors = [], []
    try:
        h = {"Accept": "application/vnd.github+json"}
        if os.environ.get("GITHUB_TOKEN"):
            h["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
        advs = json.loads(get("https://api.github.com/advisories?per_page=100&type=reviewed&sort=updated&direction=desc", h))
        hits += match_advisories(advs, inv, st["last_run"])
    except Exception as e:
        errors.append("ghsa: " + str(e))
    try:
        kev = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
        hits += match_kev(kev, inv, st["last_run"])
    except Exception as e:
        errors.append("kev: " + str(e))
    try:
        urls = [l.strip() for l in get("https://openphish.com/feed.txt").splitlines() if l.strip()]
        hits += match_phish(urls, inv)[:50]
    except Exception as e:
        errors.append("openphish: " + str(e))
    key = lambda x: x.get("id") or x.get("url")
    hits = [x for x in hits if key(x) not in set(st["seen"])]
    enrich_epss(hits)
    now = datetime.now(timezone.utc).isoformat()
    json.dump({"generated_at": now, "count": len(hits), "errors": errors, "hits": hits},
              open(os.path.join(HERE, "queue.json"), "w"), indent=2)
    json.dump({"seen": (st["seen"] + [key(x) for x in hits])[-2000:], "last_run": now},
              open(os.path.join(HERE, "state.json"), "w"))
    print(f"{len(hits)} hits, {len(errors)} errors", errors)

def selftest():
    inv = {"products": [{"name": "WordPress", "aliases": ["wordpress", "wp-"]}, {"name": "Zoom", "aliases": []}],
           "brands": ["Planning Center"], "domains": ["gracechurchdc.org"]}
    advs = [{"ghsa_id": "GHSA-x", "cve_id": "CVE-2026-0001", "severity": "high", "summary": "XSS in WordPress plugin",
             "updated_at": "2026-10-03T00:00:00Z", "html_url": "u", "vulnerabilities": []},
            {"ghsa_id": "GHSA-y", "summary": "Bug in unrelated lib", "updated_at": "2026-10-03T00:00:00Z", "vulnerabilities": []},
            {"ghsa_id": "GHSA-z", "summary": "WordPress old", "updated_at": "2020-01-01T00:00:00Z", "vulnerabilities": []}]
    a = match_advisories(advs, inv, "2026-10-01")
    assert [x["id"] for x in a] == ["GHSA-x"], a
    k = match_kev({"vulnerabilities": [
        {"cveID": "CVE-2026-1111", "vendorProject": "Zoom", "product": "Client", "vulnerabilityName": "Zoom RCE", "dateAdded": "2026-10-03"},
        {"cveID": "CVE-2026-2222", "vendorProject": "Other", "product": "Thing", "vulnerabilityName": "x", "dateAdded": "2026-10-03"}]}, inv, "2026-10-01")
    assert len(k) == 1 and k[0]["origin_type"] == "federal", k
    p = match_phish(["http://gracechurchdc-login.com/x", "http://graceehurchdc.org/y", "http://planningcenter-secure.xyz/z",
                     "http://example.com/"], inv)
    assert len(p) == 3, p
    print("selftest ok:", len(a), "advisory,", len(p), "phish")

if __name__ == "__main__":
    selftest() if "--selftest" in sys.argv else run()
