# Users, Roles and Security

_[Back to the docs index](README.md)_

## Users and roles

Argus runs as one server with one database that several people log into, each with their own
account and a role. The admin account is seeded on first boot from the credentials above; the
admin then creates the rest.

**Roles** are strictly ordered `reader < operator < admin`:

| Role | Can |
|---|---|
| **reader** | read everything (dashboards, threat profiles, dossiers, investigations, logs) — but launch nothing and change nothing |
| **operator** | everything a reader can, plus all operational work: run/resume/cancel investigations, ingest documents, edit settings and source credentials. **Cannot** manage users |
| **admin** | everything, including creating/disabling/deleting users and the destructive database admin actions |

Any signed-in user can change their own password from the account page (their name in the header).

Authorization is enforced on the server for every request, so the UI only hides controls a role
cannot use — it never relies on hiding alone. Reads are reader+, writes are operator+, and user
and database management are admin-only.

**Sessions** are per user and stored server-side: logging out revokes your session immediately,
and disabling or deleting a user drops all of theirs. The served TAXII endpoint (`/taxii2/…`)
authenticates with the machine token printed at `argus serve` startup, independent of user logins.

### Managing users from the CLI

```bash
uv run argus user add alice --role operator      # prompts for a password
uv run argus user list
uv run argus user disable alice                   # blocks login, kills their sessions
uv run argus user enable alice
uv run argus user passwd alice                    # set a new password
uv run argus user delete alice                    # tombstoned, so "started by alice" survives
```

Every destructive action refuses to remove the last remaining admin, and
`argus reset-admin-password` remains the break-glass path if you are locked out of the UI.


## What leaves the machine, exactly

- **Web search** (Collector, through Claude Code's `WebSearch`): the target name and ATT&CK /
  user-level aliases only — never aliases learned from an ingested document.
- **Document downloads** from the sources the Collector returns.
- **MITRE ATT&CK bundle** downloads (one per `argus attack update`).
- **Claude API calls** that Claude Code makes under the hood for triage / analyst / validator.
- **Enricher calls** (opt-in, per-connector; see Enrichment).

No telemetry, no external enrichment of IOCs by default. Freshness of indicators is computed from
the documents' own publication dates.


---
_[Back to the docs index](README.md)_
