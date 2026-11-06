# CTI Sources

_[Back to the docs index](README.md)_

## External CTI sources (TAXII 2.1)

Argus can subscribe to external TAXII 2.1 servers alongside RSS and web search. Each
configured server adds its matching STIX `report` objects to the Collector queue — same path
as RSS entries — so an investigation picks up vendor write-ups the server has published.

```toml
# ~/.cyllex-argus/argus.toml — one block per server. Append more freely.

# Example: a hypothetical vendor TAXII server with a Bearer token in the env.
[[taxii]]
name = "ESET APT Reports"
url = "https://taxii.eset.example/taxii2/api1"
collection = "apt-reports"
env_api_key = "ESET_TAXII_TOKEN"      # export ESET_TAXII_TOKEN=xxx before `argus serve`
added_after_days = 180                # pull only the recent window (default)

# Example: a public server that accepts anonymous reads.
[[taxii]]
name = "URLhaus"
url = "https://taxii.abuse.ch/taxii2"
collection = "ip-reputation"
# no credentials: anonymous GET

# Example: HTTP Basic.
[[taxii]]
name = "Internal CTI"
url = "https://taxii.corp.internal/taxii2/api1"
collection = "incidents-2026"
username = "argus-reader"
password = "..."
enabled = false                       # keep the entry but do not pull
```

The connector:
- Queries `GET {url}/collections/{collection}/objects/?match[type]=report&added_after=…`
- Filters client-side: a report must mention the target's name or an alias in `name` or
  `description` to count as a candidate
- Extracts the URL from `external_references[].url`, title from `name`, published date from
  `published` or `created`, and labels the publisher as `TAXII:<server-name>` so the
  `publishers` admiralty table can score it (`publishers."TAXII:ESET APT Reports" = "A"`)
- Caps the pull at 50 objects per server to prevent one chatty server from drowning the queue
- On error (401, 404, 5xx, network, malformed envelope) logs and skips the server — the rest
  of the Collector line-up (RSS + web search) keeps running

What this does NOT do:
- **No MITRE loader**. `argus attack update` already pulls MITRE ATT&CK from GitHub — subscribing
  to MITRE via TAXII would duplicate work.
- **No IOC importer**. Indicator / observable-data STIX objects are ignored on purpose; adding
  them would require a new storage shape and a new enrichment pass (planned, not shipped).

## External CTI sources (MISP)

Argus can subscribe to external MISP instances alongside RSS, TAXII and web search. Each
`[[misp]]` block queries `/events/restSearch` for events whose `info` mentions a target
alias, then emits every link-shaped Attribute (`type` in {link, url, uri}) as a candidate
URL — same path as RSS and TAXII.

```toml
# ~/.cyllex-argus/argus.toml

# CIRCL public OSINT MISP (anonymous read).
[[misp]]
name = "CIRCL OSINT"
url = "https://misppriv.circl.lu"

# Internal MISP with an env-sourced key.
[[misp]]
name = "Internal MISP"
url = "https://misp.corp.example"
env_api_key = "CORP_MISP_TOKEN"       # export before `argus serve`
timestamp_days = 365                   # pull-window hint (MISP accepts "<N>d")

# Vendor MISP with the key in toml (plaintext — env preferred).
[[misp]]
name = "Vendor Feed"
url = "https://misp.vendor.example"
api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
enabled = false                        # keep the entry; do not pull
```

**Auth precedence**: env var (name via `env_api_key`) → `api_key` on toml → anonymous.
MISP uses `Authorization: <key>` (NOT `Bearer <key>`); the connector keeps that shape
verbatim since several MISP deployments 401 on a `Bearer` prefix.

**IOCs are not imported here.** Only link-shaped Attributes become candidates; `ip-src`,
`domain`, `md5` and friends are useless for the Collector (which needs a document URL to
fetch) and belong in the enrichment pass (VirusTotal, URLhaus, GreyNoise).

## IOC enrichment (opt-in, default off)

Argus's receive-only default is a hard stance: nothing crosses the machine's boundary
unless the operator explicitly opts in. Each enricher is listed under
`[enrichment.enrichers.<name>]` with `enabled = false` by default; flipping one on
authorises the exact outbound described on the enricher's config block.

```toml
# Public, no key — anonymous reads.
[enrichment.enrichers.urlhaus]
enabled = true

# Public Community API, anonymous (rate-limited).
[enrichment.enrichers.greynoise]
enabled = true

# BYO key — env preferred, toml fallback.
[enrichment.enrichers.virustotal]
enabled = true
env_api_key = "VIRUSTOTAL_API_KEY"   # preferred: `export VIRUSTOTAL_API_KEY=...`
# api_key = "paste-key-here"          # fallback if the env var is absent

# CISA KEV catalog pull-and-match (no outbound per lookup).
[enrichment.enrichers.cisa-kev]
enabled = true
```

**Providing a key (VirusTotal, and any key-gated enricher).** You supply the key **one of two
ways — you do not fill both**:

- **Environment variable (preferred — the key never touches disk).** Set `env_api_key` to the
  *name* of the variable (default `VIRUSTOTAL_API_KEY`) and export it before `argus serve`
  (`export VIRUSTOTAL_API_KEY=...`). In the web UI (Settings → Enrichers) this is the **"Env var
  for key"** field — it holds the variable's *name*, not the key itself.
- **`api_key` in `argus.toml`**, or the **"API key"** field in the web UI. Stored on disk and
  shown masked (`••••••••`) on reload.

**Precedence:** the env var (the name in `env_api_key`, or `VIRUSTOTAL_API_KEY` when it is blank)
wins; then the toml `api_key`; otherwise the enricher reports *"API key not configured"* and makes
no outbound call. Same rule as the TAXII/MISP servers above. Leaving the `api_key` field empty and
the enricher disabled is the receive-only default — nothing is sent until you opt a key-gated
enricher in.

**VirusTotal** supports hashes (MD5/SHA1/SHA256), URLs, domains and IPs. 404 from VT is a
finding (`known=false`), not an error. A `verdict` roll-up (`clean`/`suspicious`/`malicious`)
summarises `last_analysis_stats` so operators get a one-line answer plus the full stats.

## Outbound notifications (webhooks)

Argus POSTs a signed JSON payload to each configured webhook when an investigation reaches
a terminal state (FINISHED or PAUSED). Useful for Slack / Discord / Teams / an internal
router that pages an on-call analyst.

```toml
# Slack / Discord / Teams-compatible webhook. Secret enables HMAC signing.
[[webhook]]
url = "https://hooks.slack.com/services/.../..."
env_secret = "ARGUS_HOOK_SECRET"
on_states = ["finished"]              # only on success; "paused" fires on rate-limits too

# Internal router — unsigned (trusted LAN) and fires on every terminal state.
[[webhook]]
url = "https://notifier.corp.internal/argus-events"
on_states = []
```

**Payload shape** (stable public contract — bind your subscriber to the key names):

```json
{
  "event": "investigation.finished",
  "investigation_id": 42,
  "target": "APT29 Microsoft January 2024 OAuth",
  "state": "finished",
  "stage_counts": {"collected": 10, "triaged": 8, "validated": 6, "irrelevant": 2},
  "claims_accepted": 23,
  "claims_rejected": 5,
  "message": null,
  "timestamp": "2026-10-22T14:17:03.422Z"
}
```

**Signature** (when `secret` or `env_secret` is set, otherwise unsigned):

```
X-Argus-Signature: sha256=<hex digest>
X-Argus-Timestamp:  2026-10-22T14:17:03.422Z
```

Subscriber verifies with `HMAC-SHA256(secret, timestamp + "." + raw_body)`. Stripe /
GitHub pattern.

A dead subscriber **never** fails the investigation — the dispatcher catches every
failure (connection, timeout, non-2xx) with a log line, retries once with linear backoff,
and moves on. The work is already stored on disk.


## Enrichment (opt-in, OPSEC-aware)

The pipeline default is receive-only: nothing except the Collector's search queries and the
documents it downloads leaves the machine. Enrichment is the escape hatch for operators who
deliberately accept that a specific indicator will be sent to a specific third party in exchange
for extra context.

**Every enricher is disabled by default**. The runner refuses to call a disabled enricher and
raises an error that includes the enricher's own `outbound` statement, so the operator sees
exactly what would leave the machine before opting in.

| Enricher | Accepts | Outbound | Returns |
|---|---|---|---|
| `crt.sh` | `domain-name` | The exact domain goes to crt.sh over HTTP. CT logs are a public cryptographic ledger. | Historical certificates (common names, issuer, not-before date) |
| `nvd` | `vulnerability` (CVE id) | The CVE id goes to services.nvd.nist.gov. | CVSS v3.1/v3.0/v2, English description, CWE, dates, references |
| `urlhaus` | `url`, `file-hash` (MD5/SHA256) | HTTP POST to urlhaus-api.abuse.ch. | URL status, threat label, tags, date added, malware family |
| `cisa-kev` | `vulnerability` (CVE id) | One HTTP GET to cisa.gov downloads the KEV catalog (~1 MB), cached 24h. | Known-exploited status, dateAdded, dueDate, required action |
| `greynoise` | `ip-address` | The exact IP goes to api.greynoise.io as a path parameter (Community API, anonymous). | Noise / RIOT classification, scanner name, last-seen, a link |
| `virustotal` | `file-hash` (MD5/SHA1/SHA256), `url`, `domain-name`, `ip-address` | GET to www.virustotal.com/api/v3 (files / urls / domains / ip_addresses) with your API key. | Detection stats, vendor labels, reputation, first / last-seen dates |

The runner records a `stage='enrichment'` event in `pipeline_events` for each call. Automatic
firing during a run: when the Validator accepts an `indicates` claim or an `exploits` claim with
a `vulnerability` object, every enabled enricher that supports the observable type is called.


---
_[Back to the docs index](README.md)_
