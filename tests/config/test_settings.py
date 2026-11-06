import pytest

from cyllex_argus.config.settings import (
    ArgusConfig,
    ConfigError,
    get_paths,
    load_config,
    save_config,
)


def test_defaults_when_file_missing(tmp_path):
    cfg = load_config(tmp_path / "argus.toml")
    assert cfg.limits.max_docs == 25
    assert cfg.limits.chunk_chars == 60_000
    assert cfg.limits.max_chunks_per_document == 12
    assert cfg.scoring.base_weight == 0.6
    assert cfg.scoring.reliability_weights == {
        "A": 1.0, "B": 0.85, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.5,
    }
    assert cfg.scoring.recency_years == 3
    assert cfg.scoring.stale_factor == 0.75
    assert cfg.scoring.fuzzy_threshold == 95
    assert cfg.llm.model is None
    assert cfg.llm.claude_binary == "claude"
    assert len(cfg.feeds) >= 5


def test_roundtrip(tmp_path):
    path = tmp_path / "argus.toml"
    cfg = ArgusConfig()
    cfg.limits.max_docs = 5
    cfg.publishers["Mandiant"] = "B"
    save_config(cfg, path)
    loaded = load_config(path)
    assert loaded.limits.max_docs == 5
    assert loaded.publishers == {"Mandiant": "B"}
    assert loaded.llm.model is None


def test_invalid_reliability_is_rejected(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text('[publishers]\nMandiant = "Z"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_malformed_toml_is_rejected(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text("[limits\nmax_docs = 3", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_paths_respect_argus_home(tmp_path, monkeypatch):
    """ARGUS_HOME sets the home directory; config_file / db_file point at argus.toml / argus.db."""
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    paths = get_paths()
    assert paths.home == tmp_path
    assert paths.config_file == tmp_path / "argus.toml"
    assert paths.db_file == tmp_path / "argus.db"
    assert paths.raw_dir == tmp_path / "raw"
    assert paths.attack_file == tmp_path / "attack" / "enterprise-attack.json"
    paths.ensure()
    assert paths.raw_dir.is_dir()
    assert paths.attack_file.parent.is_dir()




def test_invalid_utf8_is_rejected(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ConfigError):
        load_config(path)


def test_partial_reliability_weights_merge_with_defaults(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text("[scoring.reliability_weights]\nA = 0.9\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg.scoring.reliability_weights["A"] == 0.9
    assert cfg.scoring.reliability_weights["B"] == 0.85
    assert cfg.scoring.reliability_weights["C"] == 0.7
    assert cfg.scoring.reliability_weights["D"] == 0.5
    assert cfg.scoring.reliability_weights["E"] == 0.3
    assert cfg.scoring.reliability_weights["F"] == 0.5


def test_invalid_reliability_weights_keys_rejected(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text("[scoring.reliability_weights]\nZ = 1.0\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_logging_defaults_to_not_retaining_raw_llm(tmp_path):
    assert ArgusConfig().logging.retain_raw_llm == "off"
    path = tmp_path / "argus.toml"
    path.write_text("[llm]\nmodel = \"x\"\n", encoding="utf-8")  # an older file without [logging]
    assert load_config(path).logging.retain_raw_llm == "off"


def test_logging_retain_raw_llm_roundtrips(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text("[logging]\nretain_raw_llm = true\n", encoding="utf-8")
    # Legacy bool shape converts to the new tri-state ("full" preserves the "store everything"
    # intent). The matching conversion runs in LoggingConfig's field_validator.
    assert load_config(path).logging.retain_raw_llm == "full"
    save_config(load_config(path), path)
    # After a round-trip through save_config the stored value is already normalised to "full".
    assert load_config(path).logging.retain_raw_llm == "full"


def test_llm_provider_blocks_default_and_load(tmp_path):
    cfg = ArgusConfig()
    assert cfg.llm.provider == "claude-code-cli" and cfg.llm.search.provider == "claude-code-cli"
    assert (cfg.llm.ollama.base_url, cfg.llm.ollama.model, cfg.llm.ollama.keep_alive) == (
        "http://127.0.0.1:11434", "qwen2.5:32b-instruct", "10m")
    path = tmp_path / "argus.toml"
    path.write_text('[llm]\nprovider = "ollama"\n[llm.ollama]\nmodel = "qwen2.5:14b-instruct"\n'
                    '[llm.search]\nprovider = "disabled"\n', encoding="utf-8")
    loaded = load_config(path)
    assert loaded.llm.provider == "ollama" and loaded.llm.ollama.model == "qwen2.5:14b-instruct"
    assert loaded.llm.search.provider == "disabled"
    save_config(loaded, path)
    assert load_config(path) == loaded


def test_search_max_results_defaults_none_and_round_trips(tmp_path):
    """max_results defaults to None (fan-out tied to the run's max_docs) and survives save/load."""
    path = tmp_path / "argus.toml"
    assert ArgusConfig().llm.search.max_results is None
    cfg = ArgusConfig()
    cfg.llm.search.max_results = 60
    save_config(cfg, path)
    assert load_config(path).llm.search.max_results == 60
