#!/usr/bin/env python3
"""Personal threat feed: news + CISA KEV + Arch tracker digest, and a merged IP blocklist.

Run on a timer. Every new item goes to out/digest/YYYY-MM-DD.md, merged into
stories and ranked by risk. Only stories matching your watchlist notify you, and
so do sources that keep failing. out/blocklist.txt is rebuilt each run.

Watchlist = installed pacman packages + Flatpak apps + watch.txt. In watch.txt, put one term per
line for anything pacman doesn't know about ("fortios"), or "!term" to stop a
noisy term matching. A headline match means it names the term, not that your version
is affected. Arch tracker entries are version-checked: they all appear in the digest,
and notify when High/Critical or in KEV, and again when a fix ships. Versions are
compared against Arch's numbers, so CachyOS rebuilds may be slightly off.
"""
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
WATCH = HERE / "watch.txt"

NEWS = {
    "CISA": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
}
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ARCH = "https://security.archlinux.org/issues/all.json"
EPSS = "https://api.first.org/data/v1/epss?cve="
BLOCKLISTS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://www.spamhaus.org/drop/drop_v4.json",
]

FAIL_ALERT = 3  # consecutive failed runs before a notification; rides out brief outages
BLOCKLIST_MAX_AGE = timedelta(hours=48)
STORY_WINDOW = timedelta(days=7)
ROUNDUP_CVES = 3  # articles naming more CVEs than this are roundups, not one story

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
OFF_TOPIC = ("bleepingcomputer.com/news/artificial-intelligence/",)  # product news, not security
# Installed packages named like everyday words, which would match unrelated headlines.
# ponytail: hand-picked from this machine's packages; "!term" in watch.txt covers the rest.
COMMON_WORDS = set()
TITLE_NOISE = set("""
    the and for with from that this via new after over into its are was has have can
    now how why who what says said attack attacks attackers hackers flaw flaws
    vulnerability vulnerabilities critical security exploited exploit malware
""".split())


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "threatfeed/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def rss(data):
    for item in ET.fromstring(data).iter("item"):
        link = (item.findtext("link") or item.findtext("guid") or "").strip()
        title, text = (item.findtext("title") or link).strip(), item.findtext("description") or ""
        if link and (not any(p in link for p in OFF_TOPIC) or CVE.search(f"{title} {text}")):
            yield link, title, link, text


def kev(catalog):
    for v in catalog.values():
        title = f"{v['cveID']} {v['vendorProject']} {v['product']}: {v['vulnerabilityName']}"
        yield v["cveID"], title, f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", ""


def vercmp(a, b):
    return int(subprocess.run(["vercmp", a, b], capture_output=True, text=True, check=True).stdout)


def arch_items(groups, installed):
    """Tracker groups covering an installed version. The id includes the fix, so a fix
    arriving later counts as a new item."""
    for g in groups:
        if g["status"] == "Not affected":
            continue
        fixed = g["fixed"]
        pkgs = [p for p in g["packages"] if p in installed and vercmp(installed[p], g["affected"]) >= 0
                and not (fixed and vercmp(installed[p], fixed) >= 0)]
        if pkgs:
            state = f"fixed in {fixed}, update" if fixed else "no fix yet"
            title = f"{g['name']} {', '.join(pkgs)}: {g['type']} ({g['severity']}), {state}"
            yield (f"{g['name']}:{fixed or 'open'}", title, f"https://security.archlinux.org/{g['name']}",
                   " ".join(g["issues"]),
                   {"installed": pkgs, "urgent": g["severity"] in ("High", "Critical"), "has_fix": bool(fixed)})


def ips(text):
    """Parse plain-IP / CIDR / Spamhaus JSON-lines lists. Drops private and reserved ranges
    so a poisoned feed can't get your LAN blocked."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("{"):
            line = json.loads(line).get("cidr", "")
        try:
            net = ipaddress.ip_network(line.split()[0], strict=False)
        except (ValueError, IndexError):
            continue
        if net.is_global:
            yield net


def record_health(db, name, error=None):
    """Track a source's consecutive failures. Returns a message when it crosses the
    alert threshold or recovers from it, so each outage notifies once each way."""
    row = db.execute("select failures, last_ok from health where source=?", (name,)).fetchone()
    failures, last_ok = row or (0, None)
    now = datetime.now().isoformat(timespec="seconds")
    if error is None:
        db.execute("insert or replace into health values (?, 0, ?)", (name, now))
        return f"{name}: recovered" if failures >= FAIL_ALERT else None
    failures += 1
    db.execute("insert or replace into health values (?, ?, ?)", (name, failures, last_ok))
    if failures == FAIL_ALERT:
        return f"{name}: failed {failures} runs in a row, last worked {last_ok or 'never'} ({error})"
    return None


def check(db, alerts, name, fetch):
    """Run fetch and record the outcome in health. Returns None if it failed."""
    try:
        result = fetch()
        error = None
    except Exception as e:
        result, error = None, str(e) or type(e).__name__
        print(f"{name}: {error}", file=sys.stderr)
    alert = record_health(db, name, error)
    if alert:
        alerts.append(alert)
    return result


def write_blocklist(db, alerts):
    nets, complete = [], True
    for url in BLOCKLISTS:
        # Checks every source, so each one's health stays current during a partial outage.
        got = check(db, alerts, f"blocklist {urlparse(url).hostname}", lambda: list(ips(get(url).decode())))
        if got is None:
            complete = False
        else:
            nets += got
    count = None
    # Keep the previous file rather than shrink the blocklist during an outage.
    if complete:
        merged = [n for v in (4, 6) for n in ipaddress.collapse_addresses(x for x in nets if x.version == v)]
        tmp = OUT / "blocklist.txt.tmp"
        tmp.write_text("".join(f"{n}\n" for n in merged))
        tmp.replace(OUT / "blocklist.txt")
        count = len(merged)

    def fresh():
        age = datetime.now() - datetime.fromtimestamp((OUT / "blocklist.txt").stat().st_mtime)
        if age > BLOCKLIST_MAX_AGE:
            raise ValueError(f"not updated for {age.days}d {age.seconds // 3600}h")
    check(db, alerts, "blocklist age", fresh)
    return count


def watch_terms(watch_text, packages):
    """Terms to look for: usable package names + watch.txt, minus "!term" lines."""
    lines = [w.strip().lower() for w in watch_text.splitlines() if w.strip()]
    ignored = {w[1:].strip() for w in lines if w.startswith("!")}
    names = {re.sub(r"-(git|bin)$", "", p.lower()) for p in packages if not p.startswith("lib32-")}
    usable = {n for n in names if len(n) >= 3} - COMMON_WORDS
    return (usable | {w for w in lines if not w.startswith("!")}) - ignored


def watch_pattern(terms):
    if not terms:
        return None
    # Longest first, and hyphens count as part of a word: "python" shouldn't fire on "python-foo".
    names = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    return re.compile(rf"(?<![\w-])({names})(?![\w-])", re.I)


def title_words(title):
    return set(re.findall(r"[a-z0-9]{3,}", title.lower())) - TITLE_NOISE


def same_story(a, b):
    """Shared CVE, or overlapping headline words from different outlets (one outlet doesn't
    run a story twice, and its own titles share boilerplate like dates)."""
    if len(a["cves"]) <= ROUNDUP_CVES and len(b["cves"]) <= ROUNDUP_CVES:
        if a["cves"] & b["cves"]:
            return True
        if a["cves"] and b["cves"]:
            return False
    if a["source"] == b["source"]:
        return False
    wa, wb = title_words(a["title"]), title_words(b["title"])
    shared = wa & wb
    # ponytail: word overlap, tuned on 58 real headlines; misses reworded stories like
    # the two Chainalysis ones. Lower the 0.3 if too many duplicates get through.
    return len(shared) >= 3 and len(shared) / len(wa | wb) >= 0.3


def assign_stories(items, recent):
    """Give each item a story id, joining an earlier story when one matches."""
    pool = list(recent)
    for item in items:
        hit = next((p for p in pool if same_story(item, p)), None)
        item["story"] = hit["story"] if hit else item["id"]
        item["earlier"] = hit["earlier"] if hit else None
        pool.append(item)


def build_stories(items, catalog, scores, pattern):
    """Group items by story, attach risk signals, and sort the riskiest first."""
    groups = {}
    for item in items:
        groups.setdefault(item["story"], []).append(item)
    stories = []
    for story_id, members in groups.items():
        cves = set().union(*(m["cves"] for m in members))
        known = [catalog[c] for c in sorted(cves) if c in catalog]
        # Tracker titles are excluded: they already name the package, whatever the severity.
        text = " ".join(m["title"] for m in members if not m.get("installed"))
        text += " " + " ".join(f"{v['vendorProject']} {v['product']}" for v in known)
        installed = {p for m in members for p in m.get("installed", ())}
        matches = sorted({m.lower() for m in pattern.findall(text)} | installed if pattern else installed)
        urgent = any(m.get("urgent") for m in members)
        stories.append({
            "id": story_id,
            "members": members,
            "earlier": next((m["earlier"] for m in members if m["earlier"]), None),
            "matches": matches,
            "kev": bool(known),
            "ransomware": any(v.get("knownRansomwareCampaignUse") == "Known" for v in known),
            "due": min((v["dueDate"] for v in known if v.get("dueDate")), default=None),
            "epss": max((scores.get(c, 0) for c in cves), default=0),
            # No watchlist at all means a broken inventory, so fail open rather than go silent.
            "urgent": urgent,
            "fix": any(m.get("has_fix") for m in members),
            "relevant": bool(set(matches) - installed) or pattern is None or urgent or bool(installed and known),
        })
    stories.sort(key=lambda s: (bool(s["matches"]), s["ransomware"], s["kev"], s["urgent"], s["epss"]), reverse=True)
    return stories


def render(story):
    tags = []
    if story["matches"]:
        tags.append(f"YOU: {', '.join(story['matches'])}")
    if story["kev"]:
        tags.append("KEV")
    if story["ransomware"]:
        tags.append("RANSOMWARE")
    if story["due"]:
        tags.append(f"due {story['due']}")
    if story["epss"] >= 0.01:
        tags.append(f"EPSS {story['epss']:.0%}")
    lead, *others = story["members"]
    line = "- " + "".join(f"`{t}` " for t in tags)
    line += f"**{lead['source']}** [{lead['title']}]({lead['link']})"
    if others:
        line += " · also: " + ", ".join(f"[{m['source']}]({m['link']})" for m in others)
    if story["earlier"]:
        line += f" · follows: {story['earlier']}"
    return line + "\n"


def fetch_epss(cves):
    scores = {}
    ordered = sorted(cves)
    for i in range(0, len(ordered), 100):  # API returns at most 100 per request
        for row in json.loads(get(EPSS + ",".join(ordered[i:i + 100])))["data"]:
            scores[row["cve"]] = float(row["epss"])
    return scores


def require_items(items):
    # A feed that parses to nothing has usually changed format or returned an error page.
    if not items:
        raise ValueError("no items parsed")
    return items


def to_notify(db, stories):
    """Relevant stories not notified yet, or with a fix just arrived. Marks them notified."""
    fresh = [s for s in stories if s["relevant"] and (s["fix"] or not db.execute(
        "select 1 from items where story=? and notified=1", (s["id"],)).fetchone())]
    db.executemany("update items set notified=1 where story=?", [(s["id"],) for s in fresh])
    return fresh


def pacman_versions():
    out = subprocess.run(["pacman", "-Q"], capture_output=True, text=True, check=True).stdout
    return dict(line.split() for line in out.splitlines())


def flatpak_apps():
    return subprocess.run(["flatpak", "list", "--app", "--columns=name"],
                          capture_output=True, text=True, check=True).stdout.splitlines()


def notify(title, body):
    # -t 0: stay on screen until clicked, so it can't expire unread
    subprocess.run(["notify-send", "-a", "threatfeed", "-t", "0", title, body], check=False)


def main():
    (OUT / "digest").mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(OUT / "seen.db")
    first_run = not db.execute("select name from sqlite_master where name='seen'").fetchone()
    db.execute("create table if not exists seen (id text primary key, first_seen text)")
    db.execute("""create table if not exists items
        (id text primary key, source text, title text, cves text, story text, first_seen text, notified integer default 0)""")
    db.execute("create table if not exists health (source text primary key, failures integer, last_ok text)")
    alerts = []

    catalog = check(db, alerts, "CISA KEV", lambda: require_items(
        {v["cveID"]: v for v in json.loads(get(KEV))["vulnerabilities"]})) or {}
    installed = check(db, alerts, "pacman inventory", pacman_versions) or {}
    sources = [(name, lambda u=url: require_items(list(rss(get(u))))) for name, url in NEWS.items()]
    sources.append(("Arch", lambda: list(arch_items(require_items(json.loads(get(ARCH))), installed))))

    new, now = [], datetime.now().isoformat(timespec="seconds")
    for name, entries in [(n, check(db, alerts, n, fetch)) for n, fetch in sources] + [("CISA KEV", kev(catalog))]:
        for id_, title, link, text, *extra in entries or ():
            if db.execute("insert or ignore into seen values (?, ?)", (id_, now)).rowcount:
                cves = {c.upper() for c in CVE.findall(f"{title} {text}")}
                new.append({"id": id_, "source": name, "title": title, "link": link, "cves": cves, **(extra[0] if extra else {})})

    count = write_blocklist(db, alerts)
    print(f"{len(new)} new items; blocklist: {count if count is not None else 'unchanged'}")
    if first_run:
        print("first run: seeded the seen-database, nothing reported")
        db.commit()
        return

    if new:
        watch_text = WATCH.read_text() if WATCH.exists() else ""
        packages = list(installed) + (check(db, alerts, "flatpak inventory", flatpak_apps) or [])
        pattern = watch_pattern(watch_terms(watch_text, packages))
        cves = set().union(*(i["cves"] for i in new))
        scores = (check(db, alerts, "EPSS", lambda: fetch_epss(cves)) or {}) if cves else {}

        cutoff = (datetime.now() - STORY_WINDOW).isoformat(timespec="seconds")
        recent = [{"source": src, "title": t, "cves": set(c.split()), "story": s, "earlier": t} for src, t, c, s in
                  db.execute("select source, title, cves, story from items where first_seen > ?", (cutoff,))]
        assign_stories(new, recent)
        db.executemany("insert or ignore into items (id, source, title, cves, story, first_seen) values (?, ?, ?, ?, ?, ?)",
                       [(i["id"], i["source"], i["title"], " ".join(sorted(i["cves"])), i["story"], now) for i in new])

        stories = build_stories(new, catalog, scores, pattern)
        digest = OUT / "digest" / f"{date.today()}.md"
        with open(digest, "a") as f:
            f.write(f"\n## {now}\n\n")
            f.writelines(render(s) for s in stories)

        # Each story notifies once, even if more outlets pick it up later; a new fix is the exception.
        fresh = to_notify(db, stories)
        if fresh:
            summary = "\n".join(f"{s['members'][0]['source']}: {s['members'][0]['title']}" for s in fresh[:5])
            notify(f"Threat feed: {len(fresh)} for you", f"{summary}\n\nFull list: {digest}")
    db.commit()  # After the digest is written, so a crash re-reports rather than loses items

    if alerts:
        print("\n".join(alerts), file=sys.stderr)
        notify("Threat feed: source status", "\n".join(alerts))


if __name__ == "__main__":
    main()
