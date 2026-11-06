# Installation

_[Back to the docs index](README.md)_

## Install

Cyllex Argus ships its web UI **pre-built**, so installing needs only Python 3.12+ — no Node and
no build step. It is not on PyPI yet, so install from the repository, a Git URL, or a release
wheel. It runs on Windows and Linux.

### With pip

```bash
# From a clone of the repository:
python3 -m venv .venv
. .venv/bin/activate              # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install .                     # or:  pip install -e .   (editable, for development)

# …or straight from GitHub, without cloning:
pip install "git+https://github.com/Cyllex-Framework/Cyllex-Argus.git"

# …or from a wheel attached to a GitHub release:
pip install cyllex_argus-<version>-py3-none-any.whl
```

### With uv

```bash
uv sync                           # creates .venv and installs the project (editable) + dev tools
```

Either path puts the `argus` command on your PATH. `uv` folds venv-creation and install into one
step; with pip you create the venv yourself. The dev tools (pytest, playwright) live in the `dev`
dependency group and are needed only to work on Argus, not to run it.

### Then

```bash
argus init                        # creates ~/.cyllex-argus/
argus attack update               # downloads the MITRE ATT&CK Enterprise bundle
argus serve                       # web UI at the printed URL
```

### Choosing an LLM provider

Argus needs one model backend: the **Anthropic API** (set `ANTHROPIC_API_KEY`), the **Claude Code
CLI** (`claude`, logged in), or a local **Ollama** model. A pip install does **not** bundle the
Claude Code CLI, so for a plain `pip install` set `ANTHROPIC_API_KEY` (or point Argus at Ollama).
See [Choosing a model](../README.md#choosing-a-model) for the full configuration.


## Quickstart

```bash
# Prerequisites: Python 3.12+, uv, and the Claude Code CLI logged in (`claude`).

uv sync
uv run argus init                                # creates ~/.cyllex-argus/
uv run argus attack update                       # downloads the MITRE ATT&CK Enterprise bundle
uv run argus investigate "Scattered Spider" --max-docs 10
uv run argus serve                               # web UI at the printed URL (loopback-only)
```


## First login & admin password

The web UI is gated by a login screen — there is no `#token=` URL bypass. Credentials are
resolved in this order:

1. **Environment variable** (preferred for shared or containerised deployments):
   ```bash
   export ARGUS_ADMIN_PASSWORD='pick-something-long'
   # optional: export ARGUS_ADMIN_USERNAME='analyst'   # defaults to 'admin'
   uv run argus serve
   ```
   The password is bcrypt-hashed on each resolve and never lives on disk.

2. **Persisted hash** in `~/.cyllex-argus/argus.toml`:
   ```bash
   uv run argus set-admin-password 'pick-something-long'
   ```
   Writes a bcrypt hash under `[auth] admin_password_hash`. Survives restarts.

3. **Shipped default** (first-run fallback): the server accepts `admin` / `Argus123` when
   neither of the above is set. The CLI prints a yellow warning at startup and the login screen
   shows a hint. **Change it before exposing Argus on the LAN.**

### Reset a lost password

```bash
# Reset to the shipped default so you can log back in, then change it immediately:
uv run argus reset-admin-password

# Or set a specific new password in one shot:
uv run argus reset-admin-password 'the-new-one'
```

The reset writes directly to `argus.toml` and does not need the running server, so a lost
password is recoverable from the host without re-provisioning the config.

### LAN mode

```bash
uv run argus serve --host 0.0.0.0
```

Binds to every interface so another machine on your LAN can open the UI. The session token
issued by `/api/auth/login` travels in plain HTTP afterward — only use LAN mode on a trusted
network. The server prints a yellow warning when started this way.


---
_[Back to the docs index](README.md)_
