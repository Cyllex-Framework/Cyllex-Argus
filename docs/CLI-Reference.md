# CLI Reference

_[Back to the docs index](README.md)_

## CLI reference

| Command | What it does |
|---|---|
| `argus init` | Create `~/.cyllex-argus/` (or `$ARGUS_HOME`), `argus.toml` and the database |
| `argus attack update` | Download MITRE ATT&CK Enterprise and load groups, software and techniques |
| `argus investigate "<threat>" [--max-docs N] [--concurrency N]` | Collect, analyse and consolidate sources; re-run to resume after a usage limit |
| `argus ingest <files>... [--target "<threat>"]` | Analyse local PDF/HTML/TXT documents |
| `argus show "<entity>" [--citations]` | Consolidated profile with status, confidence and Admiralty codes |
| `argus export "<entity>" --format markdown\|stix [-o file] [--no-summary] [--tlp-cap <tlp>]` | Export the profile |
| `argus generate-detections "<entity>" [--out DIR] [--author NAME]` | Generate Sigma detection rules |
| `argus entity-merge <source-id> <target-id>` | Fuse one entity into another; useful when the pipeline split a single actor into dupes |
| `argus identity-set "<identity>" [--sector <s>] [--country <ISO2>]` | Tag an identity with sector / country |
| `argus query-targets [--sector <s>] [--country <ISO2>]` | List actors with observed `targets` claims against identities in that sector / country |
| `argus enrich <indicator> --type <stix-type> --with <enricher>` / `--list` | Enrich an IOC or CVE with a configured enricher |
| `argus import-stix <bundle.json>` | Merge a STIX 2.1 bundle (MISP, OpenCTI, any STIX-aware tool) into the store |
| `argus status` | Documents per stage and failures of the latest investigation |
| `argus sources list` / `set-reliability <pub> <A-F>` / `set-tlp <pub> <clear\|green\|amber\|amber-strict\|red\|none>` | Manage publisher reliability and TLP 2.0 label |
| `argus sources rate-known [--dry-run] [--yes] [--include-rated]` | Apply the shipped Admiralty grade to every recognised publisher and rescore. F is the floor of the confidence scale, not a neutral middle |
| `argus sources merge-duplicates [--dry-run] [--yes]` | Fold publisher rows that are the same organisation into one source, so corroboration stops counting a source twice. Confidence drops where it was overstated |
| `argus sources merge "<keep>" "<drop>"... [--yes]` | The same by hand, for the cases the automatic rules refuse |
| `argus trace purge [--before YYYY-MM-DD] [--investigation N] [--raw]` | Delete pipeline events or just LLM payload bytes |
| `argus serve [--host 127.0.0.1\|0.0.0.0] [--port N] [--no-browser] [--session-ttl SECONDS]` | Local web interface |
| `argus resume [N]` | Continue a paused / interrupted investigation (latest, or #N) |
| `argus backup [--out PATH]` | Snapshot the SQLite store (online `VACUUM INTO`) to a portable `.db` |
| `argus set-admin-password <pass>` / `reset-admin-password <pass>` | Set / break-glass reset the web admin password |
| `argus entity-merge-ghosts [--yes]` | Fuse document-origin ghost entities into their MITRE-catalog counterpart |
| `argus entity-retype <id> <stix-type>` | Change an entity's STIX type in place |
| `argus schedule add\|list\|remove\|enable\|disable` | Recurring investigations fired by the scheduler inside `argus serve` (the storage behind Watchers) |
| `argus user add\|list\|disable\|enable\|delete\|passwd` | Manage web users and roles (see [Users and roles](Users-Roles-and-Security.md)) |

Exit codes: `0` ok, `1` error, `2` investigation paused by a usage limit.


---
_[Back to the docs index](README.md)_
