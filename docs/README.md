# Cyllex Argus documentation

The complete reference for [Cyllex Argus](../README.md). Start with Installation, pick a model in
LLM Providers, then run your first investigation.

## Getting started
- [Installation](Installation.md) — install paths, prerequisites, first login, LAN mode
- [CLI Reference](CLI-Reference.md) — every `argus` command
- [Configuration](Configuration.md) — the `argus.toml` reference, exports, where things are stored

## How it works
- [How a Run Works](How-a-Run-Works.md) — the pipeline, the audit trace, incremental re-runs, the fetch rescue chain
- [Source Reliability](Source-Reliability.md) — Admiralty grades and ICD 203 analytic confidence

## Sources and outputs
- [CTI Sources](CTI-Sources.md) — TAXII and MISP subscriptions, RSS, opt-in IOC enrichment, webhooks
- [Detections](Detections.md) — Sigma rules and SigmaHQ references
- [TAXII 2.1 Server](TAXII-Server.md) — the read-write TAXII node other tools subscribe to

## Using Argus
- [Web Interface](Web-Interface.md) — the dashboard, threat profiles and watchers, with screenshots
- [Users, Roles and Security](Users-Roles-and-Security.md) — accounts, roles, sessions, and exactly what leaves the machine

## Contributing
- [Development and Deployment](Development.md) — the dev harness, test suite, project layout and systemd
