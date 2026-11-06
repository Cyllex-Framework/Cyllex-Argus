"""GET /api/settings must not leak secrets through the full-config blob it returns."""

from __future__ import annotations

from cyllex_argus.web.api.settings import MASK_VALUE, _mask_config
from tests.web.conftest import make_client

_SECRET_KEYS = {"api_key", "password", "secret", "token", "admin_password_hash"}


def test_mask_config_masks_known_secret_keys_and_keeps_the_rest():
    raw = {
        "auth": {"admin_username": "admin", "admin_password_hash": "$2b$verysecret"},
        "cyllex": {"token": "push-bearer-123", "base_url": "https://cyllex.example"},
        "misp": [{"api_key": "misp-key", "env_api_key": "MISP_KEY", "url": "https://m"}],
        "notify": {"webhooks": [{"secret": "whsec", "url": "https://hook"}]},
        "taxii": [{"api_key": "", "password": "p"}],
    }
    masked = _mask_config(raw)
    assert masked["auth"]["admin_password_hash"] == MASK_VALUE
    assert masked["cyllex"]["token"] == MASK_VALUE
    assert masked["misp"][0]["api_key"] == MASK_VALUE
    assert masked["notify"]["webhooks"][0]["secret"] == MASK_VALUE
    assert masked["taxii"][0]["password"] == MASK_VALUE
    # empty secret stays empty; non-secret fields are untouched (incl. the env-var *name*)
    assert masked["taxii"][0]["api_key"] == ""
    assert masked["auth"]["admin_username"] == "admin"
    assert masked["cyllex"]["base_url"] == "https://cyllex.example"
    assert masked["misp"][0]["env_api_key"] == "MISP_KEY"


def _walk_secrets(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in _SECRET_KEYS and isinstance(value, str):
                yield key, value
            else:
                yield from _walk_secrets(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_secrets(item)


def test_settings_endpoint_config_blob_has_no_plaintext_secret(world):
    client = make_client(world)
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    config = resp.json()["config"]
    for key, value in _walk_secrets(config):
        assert value in ("", MASK_VALUE), f"{key} leaked a plaintext secret in /api/settings"
