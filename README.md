# threatfeed

A personal threat feed for one Arch/CachyOS desktop. Once an hour it gathers security news,
CISA's Known Exploited Vulnerabilities (KEV) list and the Arch security tracker. It merges
related items into stories, ranks them by risk, and writes them to a daily digest. You get a
desktop notification only when a story names something installed on this machine. It also
builds a merged IP blocklist. Pure stdlib Python; see [DESIGN.md](DESIGN.md) for the idea
and open decisions.

## What it reads

- News RSS: CISA advisories, BleepingComputer, The Hacker News, SANS ISC
- CISA KEV catalog, plus EPSS scores from FIRST
- Arch security tracker (version-checked against installed packages)
- IP blocklists: Feodo Tracker, Emerging Threats compromised IPs, Spamhaus DROP

## What it writes (`out/`, not committed)

- `out/digest/YYYY-MM-DD.md`: every new story that day, ranked by risk
- `out/blocklist.txt`: merged IP/CIDR blocklist, rebuilt each run (not enforced anywhere yet)
- `out/seen.db`: SQLite state (seen items, stories, source health)

## Notifications

`notify-send` fires when:
- a story matches your watchlist
- an Arch tracker entry for an installed package is High/Critical or in KEV, and again when
  a fix ships
- a source fails 3 runs in a row

## Watchlist

Installed pacman packages + Flatpak apps + `watch.txt`. In `watch.txt`, one term per line for
things pacman doesn't know about (`fortios`), or `!term` to silence a noisy term. A headline
match means the term is named, not that your version is affected.

## Install

Needs Python 3, pacman (`vercmp`), and `notify-send`.

```sh
ln -s ~/projects/threatfeed/threatfeed.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now threatfeed.timer
```

Run once by hand: `python3 threatfeed.py`. Check the timer: `systemctl --user list-timers threatfeed.timer`.

## Tests

`python3 test_threatfeed.py` prints `ok`. GitHub Actions runs the same file on every push and
pull request, inside an Arch Linux container (`.github/workflows/test.yml`).
