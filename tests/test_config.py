import json

import pytest

from lxmf_hub.config import HubConfig


def test_defaults_are_conservative_for_clients():
    config = HubConfig()
    assert config.egress.tokens_per_second <= 1.0
    assert config.default_acl_mode == "invite"
    assert config.at_rest.mode == "keyfile"


def test_nested_sections_are_parsed():
    config = HubConfig.from_dict(
        {
            "storage_path": "/tmp/hub",
            "egress": {"tokens_per_second": 2.5, "propagation_node": "ab" * 16},
            "federation": {"peers": ["cd" * 16], "epoch_seconds": 900},
            "at_rest": {"mode": "passphrase"},
        }
    )
    assert config.egress.tokens_per_second == 2.5
    assert config.egress.propagation_node == "ab" * 16
    assert config.federation.peers == ["cd" * 16]
    assert config.federation.epoch_seconds == 900
    assert config.at_rest.mode == "passphrase"
    assert config.database_path == "/tmp/hub/hub.db"


def test_unknown_keys_are_rejected():
    with pytest.raises(ValueError):
        HubConfig.from_dict({"storaeg_path": "/tmp/hub"})

    with pytest.raises(ValueError):
        HubConfig.from_dict({"federation": {"peer": []}})


def test_load_from_file(tmp_path):
    path = tmp_path / "hub.json"
    path.write_text(json.dumps({"hub_name": "Testbed"}))
    assert HubConfig.load(str(path)).hub_name == "Testbed"


def test_at_rest_keyfile_defaults_into_storage_path():
    config = HubConfig.from_dict({"storage_path": "/tmp/hub"})
    assert config.at_rest_keyfile == "/tmp/hub/at_rest.key"


def test_paths_are_expanded(monkeypatch):
    monkeypatch.setenv("HOME", "/home/operator")
    config = HubConfig.from_dict(
        {"storage_path": "~/hub", "reticulum_config_path": "~/.reticulum"}
    )
    assert config.resolved_storage_path == "/home/operator/hub"
    assert config.resolved_reticulum_config_path == "/home/operator/.reticulum"
    assert HubConfig().resolved_reticulum_config_path is None
