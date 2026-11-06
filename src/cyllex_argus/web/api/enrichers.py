"""Enrichment HTTP API: list the catalog, toggle one, invoke one.

Pairs with the CLI (`argus enrich --list`, `argus enrich <indicator> --with <name>`). Writes to
argus.toml via save_config so a toggle made in the web UI persists across `argus serve` restarts.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from cyllex_argus.config.settings import EnricherConfig, EnrichmentConfig, load_config, save_config
from cyllex_argus.enrichment import (
    EnrichmentDisabledError,
    EnrichmentRequest,
    EnrichmentUnavailable,
    available_enrichers,
)
from cyllex_argus.web.deps import open_services

router = APIRouter()

MASK_VALUE = "••••••••"

_VALID_TYPES: tuple[str, ...] = (
    "domain-name", "ipv4-addr", "ipv6-addr", "url", "file-hash", "vulnerability",
)

# Enrichers that take an API key through [enrichment.enrichers.<name>] api_key / env_api_key.
# Everything else ignores both fields; the UI only shows the key input for names in this set.
KEY_GATED = frozenset({"virustotal"})


class ToggleBody(BaseModel):
    """Save body for one enricher.

    `enabled` is required. `api_key` / `env_api_key` are optional; they only matter for
    key-gated enrichers (today: VirusTotal). The masked sentinel ("••••••••") on `api_key`
    means "keep the stored value" so flipping the enable toggle doesn't require re-pasting
    the key. An empty string means "clear the stored key".
    """
    enabled: bool
    api_key: str | None = None
    env_api_key: str | None = None


class InvokeBody(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048)
    indicator_type: str


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _enricher_view(name: str, enricher, stored: EnricherConfig) -> dict:
    """Serialise one enricher's row for the Settings UI.

    `requires_api_key` tells the UI whether to render the API-key input + env-var hint for
    this enricher. `api_key_configured` is the masked boolean the UI uses to show
    "key is set" without ever leaking the plaintext — the actual key never crosses the API.
    """
    key_gated = name in KEY_GATED
    return {
        "name": name,
        "description": enricher.description,
        "outbound": enricher.outbound,
        "supported_types": list(enricher.supported_types),
        "enabled": stored.enabled,
        "requires_api_key": key_gated,
        "api_key_configured": bool(stored.api_key.strip()) if key_gated else False,
        "api_key": (MASK_VALUE if stored.api_key.strip() else "") if key_gated else "",
        "env_api_key": stored.env_api_key if key_gated else "",
    }


def _write_toggle(
    services,
    name: str,
    enabled: bool,
    *,
    api_key: str | None,
    env_api_key: str | None,
) -> None:
    """Persist the enricher's enabled flag (and optional key fields) to argus.toml.

    Masked `api_key` ("••••••••") preserves the stored value; an empty string clears it;
    any other value replaces the stored plaintext. Non-key-gated enrichers ignore both
    `api_key` and `env_api_key` so the UI can safely send them without consequence.
    """
    path = services.paths.config_file
    cfg = load_config(path) if path.exists() else services.config
    enrichers = dict(cfg.enrichment.enrichers)
    prior = enrichers.get(name, EnricherConfig())
    if api_key is None or name not in KEY_GATED:
        new_api_key = prior.api_key
    elif api_key == MASK_VALUE:
        new_api_key = prior.api_key
    else:
        new_api_key = api_key
    new_env = env_api_key if (env_api_key is not None and name in KEY_GATED) else prior.env_api_key
    enrichers[name] = EnricherConfig(
        enabled=enabled, api_key=new_api_key, env_api_key=new_env,
    )
    cfg = cfg.model_copy(update={"enrichment": EnrichmentConfig(enrichers=enrichers)})
    save_config(cfg, path)
    # Reflect the change in the running Services so the next invoke respects it immediately.
    services.config = cfg


def _stored_enrichers(services) -> dict[str, EnricherConfig]:
    """Enrichers stanza as argus.toml holds it; a missing file means the live in-memory config.

    Reading from disk matches what the write path does and keeps the GET consistent with
    the preceding PUT in both the test harness (where `services.config` is a shared default)
    and production (where a request's Services may hold a stale snapshot)."""
    path = services.paths.config_file
    try:
        base = load_config(path) if path.exists() else services.config
    except Exception:  # noqa: BLE001 — a broken file falls back to the live config
        base = services.config
    return base.enrichment.enrichers


@router.get("/enrichers")
def list_enrichers(request: Request) -> dict:
    """Catalog of built-in enrichers with their current enabled state and outbound statements."""
    with open_services(request) as services:
        stored = _stored_enrichers(services)
        return {
            "enrichers": [
                _enricher_view(name, enricher, stored.get(name, EnricherConfig()))
                for name, enricher in sorted(available_enrichers().items())
            ],
        }


@router.put("/enrichers/{name}")
def toggle_enricher(name: str, body: ToggleBody, request: Request) -> dict:
    """Persist an enricher's enabled flag and optional key fields (for key-gated enrichers)."""
    if name not in available_enrichers():
        raise HTTPException(status_code=404, detail=f"unknown enricher: {name!r}")
    with open_services(request) as services:
        _write_toggle(
            services, name, body.enabled,
            api_key=body.api_key, env_api_key=body.env_api_key,
        )
        stored = _stored_enrichers(services).get(name, EnricherConfig())
        enricher = available_enrichers()[name]
        return _enricher_view(name, enricher, stored)


@router.post("/enrichers/{name}/invoke")
def invoke_enricher(name: str, body: InvokeBody, request: Request) -> dict:
    """Run one enricher against one indicator and return its findings.

    Every call still goes through EnrichmentRunner so an unknown enricher, a disabled one, or an
    unsupported indicator type is refused with the same semantics the CLI already enforces.
    """
    if body.indicator_type not in _VALID_TYPES:
        raise _bad(f"indicator_type must be one of {', '.join(_VALID_TYPES)}")
    with open_services(request) as services:
        runner = services.enrichment_runner()
        try:
            result = runner.enrich(
                EnrichmentRequest(indicator=body.indicator, indicator_type=body.indicator_type),
                name,
            )
        except EnrichmentDisabledError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except EnrichmentUnavailable as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "name": name,
        "indicator": body.indicator,
        "indicator_type": body.indicator_type,
        "duration_ms": result.duration_ms,
        "error": result.error,
        "findings": [
            {"source": f.source, "key": f.key, "value": f.value,
             "observed_at": f.observed_at, "detail": f.detail}
            for f in result.findings
        ],
    }
