# threatfeed design

## Idea

A personal threat feed for this one Arch/CachyOS desktop. An hourly systemd timer runs
`threatfeed.py`, which pulls security news, CISA KEV and the Arch security tracker, merges
items into stories ranked by risk, and writes a daily digest to `out/digest/`. It sends a
desktop notification only when a story touches something installed here (pacman packages,
Flatpak apps, `watch.txt`). It also rebuilds a merged IP blocklist at `out/blocklist.txt`.
Stdlib Python only, all state local (`out/seen.db`).

## Open questions

- Blocklist enforcement: load it into an nftables set, add URLhaus/ThreatFox domains for
  DNS blocking, with an allowlist and sanity check. On hold since 2026-11-01.
- More sources: Arch advisories, GitHub advisories/OSV, vendor PSIRT feeds. Needs Atom
  support in `rss()` first. On hold since 2026-11-01.
- Should the feed itself ever run off this machine (e.g. scheduled in GitHub Actions)? It
  depends on local pacman/Flatpak state and `notify-send`, so that would be a change of
  direction.

## Decided

- Runs locally on a systemd timer; watchlist comes from what's installed on this machine.
- Only watchlist matches and failing sources notify; everything else stays in the digest.
- Code lives in a private GitHub repo (`ztancrell/threatfeed`); generated `out/` is not committed.
- GitHub Actions runs the tests only, in an Arch container (tests need pacman's `vercmp`).
