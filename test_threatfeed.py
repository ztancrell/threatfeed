import sqlite3

from threatfeed import (FAIL_ALERT, arch_items, assign_stories, build_stories, ips, kev, record_health, render, rss,
                        to_notify, watch_pattern, watch_terms)

nets = [str(n) for n in ips('# c\n1.2.3.4\n10.0.0.1\n{"cidr":"5.6.0.0/16"}\njunk\n8.8.8.0/24 ; note\n')]
assert nets == ["1.2.3.4/32", "5.6.0.0/16", "8.8.8.0/24"], nets

items = list(rss(b"<rss><channel><item><title>T</title><link>https://x/1</link><description>D</description></item>"
                 b"<item><title>no link</title></item></channel></rss>"))
assert items == [("https://x/1", "T", "https://x/1", "D")], items

catalog = {"CVE-1": {"cveID": "CVE-1", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "x",
                     "knownRansomwareCampaignUse": "Known", "dueDate": "2026-12-01"}}
assert [i[0] for i in kev(catalog)] == ["CVE-1"]

# Watchlist: packages + watch.txt, minus common words, lib32 and "!term" lines.
terms = watch_terms("FortiOS\n\n!curl\n", ["curl", "openssl", "file", "lib32-glibc", "go"])
assert terms == {"fortios", "openssl"}, terms
pattern = watch_pattern(terms)
assert pattern.findall("OpenSSL bug") == ["OpenSSL"]
assert not pattern.findall("openssl-foo and notopenssl")
assert watch_pattern(set()) is None


def item(id_, title, cves=(), source="S"):
    return {"id": id_, "source": source, "title": title, "link": f"https://x/{id_}", "cves": set(cves)}


# Stories: shared CVE and near-identical headlines merge; different CVEs and roundups don't.
same_cve = [item("a", "Fortinet bug", ["CVE-1"]), item("b", "Totally different words", ["CVE-1"])]
assign_stories(same_cve, [])
assert same_cve[1]["story"] == "a"

same_title = [item("a", "Trezor Warns of Suspected Hardware Implant in One of Its Wallets Sold by CryptoBilis", source="A"),
              item("b", "Trezor warns of suspected crypto-theft implant in hardware wallet", source="B")]
assign_stories(same_title, [])
assert same_title[1]["story"] == "a"

one_outlet = [item("a", "Wireshark 5.0.0rc1 Release, (Sat, Oct 31st)"), item("b", "Stormcast Release, (Sat, Oct 31st)")]
assign_stories(one_outlet, [])
assert one_outlet[1]["story"] == "b"

diff_cve = [item("a", "Microsoft patches Windows kernel bug", ["CVE-1"]),
            item("b", "Microsoft patches Windows kernel bug", ["CVE-2"])]
assign_stories(diff_cve, [])
assert diff_cve[1]["story"] == "b"

roundup = [item("a", "Fortinet bug", ["CVE-1"]), item("b", "Weekly recap", ["CVE-1", "CVE-2", "CVE-3", "CVE-4"])]
assign_stories(roundup, [])
assert roundup[1]["story"] == "b"

unrelated = [item("a", "Alpine Linux rebuilds GitLab"), item("b", "OpenAI doubles Pro usage limits")]
assign_stories(unrelated, [])
assert unrelated[1]["story"] == "b"

# A follow-up joins a story from an earlier run and can see its title.
followup = [item("b", "Other headline", ["CVE-1"])]
assign_stories(followup, [{"source": "T", "title": "First report", "cves": {"CVE-1"}, "story": "a", "earlier": "First report"}])
assert followup[0]["story"] == "a" and followup[0]["earlier"] == "First report"

# Ranking: watchlist matches first, then KEV among them; EPSS only breaks later ties.
ranked = [item("plain", "Nothing here"), item("epss", "Some bug", ["CVE-9"]),
          item("kev", "Fortinet bug", ["CVE-1"]), item("mine", "OpenSSL bug")]
assign_stories(ranked, [])
stories = build_stories(ranked, catalog, {"CVE-9": 0.9}, pattern)
assert [s["id"] for s in stories] == ["kev", "mine", "epss", "plain"], [s["id"] for s in stories]
assert [s["relevant"] for s in stories] == [True, True, False, False]  # "kev" matches via catalog's FortiOS
line = render(stories[0])
assert all(t in line for t in ("`YOU: fortios`", "`KEV`", "`RANSOMWARE`", "`due 2026-12-01`")), line

# With no watchlist at all, everything notifies rather than nothing.
assert all(s["relevant"] for s in build_stories(ranked, catalog, {}, None))

# Health: alerts once on reaching the threshold, stays quiet after, and once on recovery.
db = sqlite3.connect(":memory:")
db.execute("create table health (source text primary key, failures integer, last_ok text)")
assert record_health(db, "src") is None
results = [record_health(db, "src", "boom") for _ in range(FAIL_ALERT + 2)]
assert [bool(r) for r in results] == [False, False, True, False, False], results
assert "boom" in results[2] and "last worked" in results[2]
assert "recovered" in record_health(db, "src")
assert record_health(db, "src") is None
assert record_health(db, "new", "boom") is None  # one blip stays silent
assert record_health(db, "new") is None

# Off-topic: BleepingComputer's AI section is dropped unless the article names a CVE.
AI = "https://www.bleepingcomputer.com/news/artificial-intelligence"
feed = (f"<rss><channel><item><title>Pro limits doubled</title><link>{AI}/limits/</link></item>"
        f"<item><title>Chat bug</title><link>{AI}/bug/</link><description>CVE-2026-1234</description></item>"
        "<item><title>Keep</title><link>https://www.bleepingcomputer.com/news/security/x/</link></item>"
        "</channel></rss>").encode()
assert [i[1] for i in rss(feed)] == ["Chat bug", "Keep"]

# Inventory: packaging suffixes don't hide a name from headlines.
assert watch_terms("", ["electron-cash-git", "foo-bin"]) == {"electron-cash", "foo"}


def group(name, pkg, severity="Medium", affected="1.0-1", fixed=None, status="Vulnerable"):
    return {"name": name, "packages": [pkg], "status": status, "severity": severity, "type": "code execution",
            "affected": affected, "fixed": fixed, "issues": ["CVE-2026-0001"]}


# Arch tracker: only groups covering the installed version count.
installed = {"open": "1.0-1", "fixable": "1.5-1", "patched": "3.0-1", "older": "0.5-1", "notaff": "1.0-1"}
got = list(arch_items([group("AVG-1", "open", "High"), group("AVG-2", "fixable", fixed="2.0-1"),
                       group("AVG-3", "patched", fixed="2.0-1"), group("AVG-4", "older"),
                       group("AVG-5", "notaff", status="Not affected"), group("AVG-6", "absent")], installed))
assert [g[0] for g in got] == ["AVG-1:open", "AVG-2:2.0-1"], got
assert got[0][2] == "https://security.archlinux.org/AVG-1" and "CVE-2026-0001" in got[0][3]
assert "no fix yet" in got[0][1] and "fixed in 2.0-1" in got[1][1]
assert got[0][4] == {"installed": ["open"], "urgent": True, "has_fix": False}
assert got[1][4] == {"installed": ["fixable"], "urgent": False, "has_fix": True}


def arch(id_, pkg, urgent=False, has_fix=False, cves=()):
    return {**item(id_, f"{id_} {pkg}: code execution", cves, "Arch"), "story": id_, "earlier": None,
            "installed": [pkg], "urgent": urgent, "has_fix": has_fix}


# Installed issues always show as yours, but only High/Critical or KEV ones notify.
exploited = {"CVE-5": {"vendorProject": "Zzz", "product": "Zzz"}}
stories = {s["id"]: s for s in build_stories(
    [arch("hi", "pam", urgent=True), arch("med", "perl"), arch("kev", "nasm", cves=["CVE-5"])],
    exploited, {}, watch_pattern({"perl", "pam", "nasm"}))}
assert stories["hi"]["matches"] == ["pam"] and "`YOU: pam`" in render(stories["hi"])
assert stories["hi"]["relevant"] and stories["kev"]["relevant"]
assert stories["med"]["matches"] == ["perl"] and not stories["med"]["relevant"]

# Notifications: one per story, except that a fix arriving notifies again.
db = sqlite3.connect(":memory:")
db.execute("create table items (story text, notified integer default 0)")
db.executemany("insert into items values (?, 0)", [("old",), ("fixed",), ("brandnew",)])
db.execute("update items set notified=1 where story in ('old', 'fixed')")
base = {"relevant": True, "fix": False}
batch = [{**base, "id": "old"}, {**base, "id": "fixed", "fix": True}, {**base, "id": "brandnew"},
         {**base, "id": "quiet", "relevant": False}]
assert [s["id"] for s in to_notify(db, batch)] == ["fixed", "brandnew"]
assert db.execute("select notified from items where story='brandnew'").fetchone() == (1,)
print("ok")
