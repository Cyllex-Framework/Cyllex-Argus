# Development and Deployment

_[Back to the docs index](README.md)_

## Dev harness

How to iterate on Argus end-to-end on a laptop. Everything runs locally; the suite can run
fully offline when the LLM is faked (`FakeLLMProvider`, and the `ScriptedLLM` built on it, are
used across the test suite — directly in ~15 modules and indirectly in many more).

### Setup

```bash
uv sync                                 # installs deps + the project in editable mode under .venv
uv run argus init                       # ~/.cyllex-argus/ with argus.toml and the SQLite store
uv run argus attack update              # one-time MITRE ATT&CK Enterprise download (~1 MB)
```

> On Windows the venv binary is `.venv/Scripts/argus.exe`; on macOS/Linux it is
> `.venv/bin/argus`. `uv run argus …` works from either.

### Test suites

| Suite | Count | How to run |
|---|---:|---|
| Python unit + integration | **1621** | `uv run pytest tests/ --ignore=tests/e2e` |
| Web (Vitest + React Testing Library) | **415** (44 files) | `cd web && npm test` or `npx vitest run` |
| End-to-end in a real browser (Edge, offline) | n/a | `ARGUS_E2E=1 uv run pytest tests/e2e -v` (set `ARGUS_E2E_SHOTS=/some/dir` to keep per-tab screenshots) |

### CI

`.github/workflows/ci.yml` runs on every push and pull request to `main` and `dev`. Four things
have to pass, and each one exists because its absence cost something:

| Job | What it guards |
|---|---|
| `tests` | `ruff check src tests` and the pytest suite |
| `concurrency-stress` | Repeats the concurrency suites **15 times**. The races they cover produced *wrong intelligence* rather than crashes, and the test that caught them failed 2 runs in 12 — one green pass proves nothing |
| `frontend` | Vitest, then `npm run build`, which also type-checks |
| (same job) The committed bundle matches the source | `argus serve` ships the bundle committed under `src/cyllex_argus/web/static`, so a frontend commit without a rebuild silently serves the old UI. Checked with `git status`, not `git diff`: content-hashed filenames make a stale bundle show up as files added *and* deleted, and `git diff` cannot see the untracked half |

So **a frontend change is not finished until `npm run build` has run and the bundle is
committed**. The ruff version is pinned so a new release's new rules cannot redden a branch
nobody touched.

Narrow runs:

```bash
# One module
uv run pytest tests/pipeline -q
# One test file
uv run pytest tests/web/test_jobs_api.py -q
# One test, verbose
uv run pytest tests/pipeline/test_investigation.py -v
# Web: watch mode
cd web && npx vitest
# Web: one file
cd web && npx vitest run src/features/auth/LoginPage.test.tsx
```

### Dev loop (frontend + backend together)

Open two terminals; the Vite dev server proxies `/api` to the backend so the SPA you edit
hits a live Argus:

```bash
# Terminal 1 — backend
uv run argus serve --no-browser

# Terminal 2 — frontend; HMR at http://localhost:5173
cd web && npm run dev
```

Open `http://localhost:5173` and log in. Save a `.tsx` file and the SPA
hot-reloads against the running backend. When you're done, `cd web && npm run build` rebuilds
the static bundle under `src/cyllex_argus/web/static/`; commit the result so `argus serve`
ships the latest UI.

### Running Argus without Claude Code (offline / unit mode)

Every test that would otherwise call Claude Code uses `FakeLLMProvider`
(`src/cyllex_argus/llm/fake.py`): a deterministic provider the test seeds with a handler
that maps each `LLMRequest` to a response. The pipeline, generator and web APIs are built
around `LLMProvider` as an interface, so a run that never touches the network is one
import away. Minimum example:

```python
from cyllex_argus.llm.fake import FakeLLMProvider

llm = FakeLLMProvider(lambda req: {"filename": "T1087.002-01.yaml", "body": "id: T1087.002-01\n…"})
```

For local-model runs that DO fire real LLM calls but keep document text off Anthropic's
servers, swap `[llm] provider = "ollama"` (see **Local models** below) and set
`[llm.search] provider = "disabled"` for strict mode.

### Fixtures (`tests/conftest.py`)

| Fixture | Builds | When to use |
|---|---|---|
| `tmp_path` | a fresh scratch dir (pytest built-in) | always, to isolate SQLite files and config |
| `store` | an empty `SQLiteStore` under `tmp_path/argus.db` | low-level store tests |
| `attack_store` | `store` + the mini MITRE catalog loaded (`tests/fixtures/attack_mini.json`) | tests that need technique IDs resolved |
| `new_doc` | a factory producing valid `NewDocument` objects | pipeline / validator / scoring tests |
| `world` | a `World` wrapping a fresh home dir, DB, attack catalog, services factory | API, CLI, and anything that needs the whole stack |
| `seeded_world` | `world` plus one `investigate("Scattered Spider")` run | threat profile / dashboard / UI test setup |

Web-side helpers live in `web/src/test/utils.tsx`: `renderWithProviders` (QueryClient + Router)
and `mockApi` (route table → `vi.fn()` fetch stub).

### Linting

The project is Ruff-only; no mypy. **CI fails on a lint error**, so extending the rule set in
`pyproject.toml` means fixing every existing violation of the new rule in the same commit. Fast
on save:

```bash
uv run ruff check src tests        # style + bugs
uv run ruff format src tests       # formatter (idempotent)
```

The web side uses TypeScript's own checker:

```bash
cd web && npx tsc --noEmit         # types only, no build
```

### Troubleshooting

- **Can't log in / forgot the admin password**: with no `ARGUS_ADMIN_PASSWORD` set, the shipped
  default is `admin` / `Argus123` — change it with `argus set-admin-password <pass>` (or
  `reset-admin-password <pass>` for break-glass). `ARGUS_ADMIN_PASSWORD`, if set before
  `argus serve`, always wins and is re-applied on each start.
- **Vite dev proxy returns 404**: the backend has to be on port 8765. If you passed
  `--port`, set `VITE_API_PROXY_TARGET` or edit `web/vite.config.ts`.
- **`npx tsc --noEmit` complains about a `.test.tsx`**: Vitest tests still go through the
  typechecker on `npm run build`. Fix the type or add a scoped `// @ts-expect-error` with a
  reason.
- **E2E `pytest tests/e2e` fails to launch Edge**: the suite uses the installed Microsoft
  Edge via its DevTools Protocol driver; it needs `msedgewebview2`/`msedgedriver` on PATH.
  Install Edge first; `ARGUS_E2E=1` is a hard gate so the suite does not run unexpectedly in
  CI.


## Operational harness

For long-running or team-shared deployments, Argus ships three keep-alive paths. All of
them run the same `argus serve` process — the one that hosts the web UI, the TAXII server,
AND the scheduler thread for recurring investigations. Pick the one that matches how you
want the box managed; env configuration + the SQLite store are the same across both.

### Deployment matrix

| Path | Best for | LLM backend | Keep-alive | TLS |
| --- | --- | --- | --- | --- |
| **Foreground CLI** (`argus serve`) | Dev loop, solo laptop | Claude Code CLI or Ollama | Terminal must stay open | None (loopback) |
| **systemd** (`deploy/argus.service`) | Linux server, 24/7 solo | Claude Code CLI (SSH login) or Ollama | `systemctl` + Restart=on-failure | Put nginx/caddy in front |

### systemd (Linux)

```bash
# From an Argus checkout at /opt/argus with the venv already synced:
sudo deploy/install-service.sh
sudoedit /etc/argus/env    # set a real ARGUS_ADMIN_PASSWORD
sudo systemctl start argus
journalctl -u argus -f     # tail the live log
```

The unit runs as a dedicated `argus` system user, binds to `127.0.0.1:8765`, and persists
`argus.toml` + `argus.db` + the attack catalog + backups under `/var/lib/argus`. The
installer is idempotent (re-run to repair ownership or re-link the unit file). To stop:
`sudo systemctl disable --now argus`.

### Environment reference

These three environment variables configure the service; everything else is set in `argus.toml`
(or the Settings UI). The admin credentials also live in `argus.toml` under `[auth]`, and the env
var takes precedence there — so the service can set them without writing a hash to disk.

| Variable | Purpose | Default |
| --- | --- | --- |
| `ARGUS_HOME` | Directory for `argus.toml`, `argus.db`, backups, raw doc copies | `~/.cyllex-argus` |
| `ARGUS_ADMIN_USERNAME` | Admin login name | `admin` |
| `ARGUS_ADMIN_PASSWORD` | Admin password (bcrypt-hashed at first start) | `Argus123` (shipped default — change it) |

Host, port and session lifetime are `argus serve` flags (`--host`, `--port`, `--session-ttl`),
not env vars; the LLM provider is set in `argus.toml` / Settings. Provider and enricher API keys
have their own env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `VIRUSTOTAL_API_KEY`, …), covered
in their sections.

### Liveness vs. health

Two endpoints with different jobs:

- **`GET /api/live`** — no auth, no DB, just confirms the HTTP server loop is up. Used by
  the systemd watchdog. Cheap enough to poll every 30 s.
- **`GET /api/health`** — authenticated, returns the operator-facing data-quality shortlist
  (failed docs, untagged identities, stuck investigations, name collisions, …). Powered by
  real SQL queries — do NOT poll it from an orchestrator; it is a UI card, not a probe.

### Scheduler + backup under keep-alive

The scheduler thread lives inside `argus serve`, so recurring investigations
(`argus schedule add ...`, or a Watcher created in the UI) fire naturally as long as the
service / container stays up. Pair it with `argus backup` on a host cron:

```cron
# Daily backup of the live store at 03:00, keep the last 14 days.
0 3 * * * /opt/argus/.venv/bin/argus backup --dest /var/lib/argus/backups
0 4 * * * find /var/lib/argus/backups -name 'argus-*.db' -mtime +14 -delete
```

The backup is a `VACUUM INTO` snapshot: the live store stays writable during the copy, and
the resulting file is a self-contained SQLite DB that can be dropped into another Argus
install directly.


## Database schema (high level)

Key tables (full schema in `src/cyllex_argus/knowledge/schema.py`):

| Table | What it holds |
|---|---|
| `publishers` | Known publishers with their Admiralty reliability (A..F), TLP cap and `org_key` — the registrable domain this publisher IS, which is what independence is counted by |
| `publisher_names` | Every byline ever seen for a publisher. Makes a merge non-destructive: the old name still resolves the row |
| `documents` | Every downloaded or ingested doc: URL, title, publisher, date, SHA-256 hash, stage |
| `entities` | STIX-typed entities: intrusion-set, malware, tool, attack-pattern, identity, indicator, vulnerability, location |
| `aliases` | Alternative names for an entity, with their origin (`attack` / `document` / `user`) |
| `claims` | One row per extracted claim: triple + verbatim quote + character span + polarity + quote_status + investigation id |
| `assessments` | One row per unique (subject, predicate, object): status, confidence, Admiralty, first_seen / last_seen |
| `investigations` | A target name, resolved entity id, state, started/finished, document counts |
| `investigation_documents` | Join table (an investigation and the documents it saw) |
| `pipeline_events` | Every decision each agent made per document: stage, decision, reason, duration_ms, tokens, cost. Carries raw LLM prompt/response when `retain_raw_llm` is on |


## Project layout

```
src/cyllex_argus/
├── cli/              Typer CLI (`argus …`)
├── config/           ArgusConfig and TOML parsing
├── documents/        Chunking of long text into Analyst-sized parts (with overlap)
├── sources/          Source connectors: Claude-WebSearch, RSS, TAXII, MISP, local files
├── attack/           ATT&CK catalog loader (STIX bundle → techniques, groups, software)
├── pipeline/         The four agents + shared retry helper with exponential backoff
├── knowledge/        Store (SQLite), schema, profile builder, read model, indicators & freshness
│                     publisher_identity / _merge / _ratings: who counts as one source, and how reliable
├── llm/              LLMProvider interface, Claude Code CLI provider, fake for tests, price table
├── scoring/          Confidence computation (reliability-weighted contested threshold)
├── exporters/        Markdown, STIX, AI summary
├── detections/       Sigma rule generator + SigmaHQ references
├── watchers/         Standing monitors: scheduler, deterministic change diff, snapshots & events
├── notify/           HMAC-signed webhook dispatch for watcher change alerts
├── evaluation/       Offline eval harness for the pipeline
├── enrichment/       Opt-in external enrichers (crt.sh, nvd, urlhaus, cisa-kev, greynoise, virustotal)
├── importers/        STIX 2.1 bundle ingest (pairs with the STIX exporter)
└── web/              FastAPI backend: routes, security middleware, jobs, SSE, trace endpoints
    └── static/       Committed Vite build of the React interface

web/                  React 19 + TypeScript + Vite source
tests/                pytest (unit + web + e2e)
```


## Known limits

- The Collector's web search is as good as Claude Code's `WebSearch` tool and your RSS feeds.
- Publishers behind a TLS-fingerprinting WAF are reached through curl_cffi, and permanent
  refusals through the Wayback Machine or a file you supply (see *When a publisher refuses*).
  What stays unreachable: hosts that time out rather than refuse, pages that need a login, and
  publishers whose access policy Argus complies with instead of evading. Measured on a
  46-document corpus, 43 are reachable; the remaining 3 are two timeouts and one policy refusal.
- Argus does not render JavaScript. A page whose text only exists after client-side rendering
  comes back shallow, and the Wayback fallback is the only rescue for it.
- The Triage considers each document in isolation. It learns aliases incrementally within one
  investigation and runs a second triage pass with the final alias set, but it does not plan
  across unrelated investigations.
- The Validator's quote match uses normalised rapidfuzz; a quote that was heavily reformatted by
  the publisher may be rejected even though the sentence is present.
- Indicator freshness is computed only from the local documents' publication dates. Argus never
  resolves domains or looks up IPs externally — unless the operator opts into a specific
  enricher.
- Publisher identity is resolved by registrable domain, which is deliberately conservative: a
  publisher whose domain cannot be derived — one that only ever appears as a republished primary
  source, with no document of its own — keeps its own row and stays ungraded until you rate it.
  `argus sources rate-known` lists exactly those.
- The shipped reliability table covers established track records and nothing else. It is not a
  directory of the industry, and an outlet's absence from it is not a judgement about that
  outlet — it means Argus has no basis for one.
- Aliases learned from an ingested document are never used as a web-search query, in line with
  the receive-only OPSEC principle; they do steer the Validator, scoped to the investigation
  that learned them so a bad alias in one case cannot pollute another.


---
_[Back to the docs index](README.md)_
