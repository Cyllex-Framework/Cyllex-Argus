# Detections

_[Back to the docs index](README.md)_

## Sigma detections

Argus produces two things for every threat profile:

- **One Sigma rule per `indicator` entity**, the detections Argus genuinely owns, because the IOCs
  come from the investigation. The log source is routed by IOC shape: IPv4/IPv6 to `firewall`, URL
  to `proxy`, SHA256/SHA1/MD5 to `file_event`, domain to `dns_query`. Refanged IOCs (`185[.]220...`,
  `hxxp://`) are normalised first. Ids are deterministic (UUID v5 over the IOC value), so re-running
  on the same data produces the same `id:`.

- **A SigmaHQ coverage map for the observed MITRE techniques.** For every technique the actor uses,
  Argus reports how many community-maintained [SigmaHQ](https://github.com/SigmaHQ/sigma) rules
  already detect it and links a sample of them directly (login-free, pinned to a SigmaHQ commit), so
  a technique with 79 rules and one with none are both obvious at a glance. Argus does not invent a
  detection from a technique id: a wrong field would silently never fire (a false sense of coverage),
  and SigmaHQ already maintains vetted rules. The map comes from a bundled index
  (`detections/sigmahq_index.json`); regenerate it against the latest SigmaHQ with
  `python scripts/build_sigmahq_index.py`.

## Access

- **CLI**: `argus generate-detections "<entity>" --out dir/` writes one `.yml` per IOC rule and a
  `SIGMAHQ-REFERENCES.md` that links every observed technique to its SigmaHQ rules.
- **API**: `GET /api/threats/{entity_id}/detections/sigma` returns the rules and references as
  JSON; `GET /api/threats/{entity_id}/detections/sigma.zip` bundles the `.yml` files plus the
  references markdown in one download.
- **Web**: the Sigma section of the Threat profile, with a **Download all (.zip)** button and the
  technique references as links.

---
_[Back to the docs index](README.md)_
