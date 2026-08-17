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


def test_operator_identity_accepts_one_hash_or_several():
    single = HubConfig.from_dict({"operator_identity": "ab" * 16})
    assert single.operator_hashes == [bytes.fromhex("ab" * 16)]

    several = HubConfig.from_dict({"operator_identity": ["ab" * 16, "cd" * 16]})
    assert several.operator_hashes == [bytes.fromhex("ab" * 16), bytes.fromhex("cd" * 16)]

    assert HubConfig().operator_hashes == []


@pytest.mark.parametrize("value", ["nothex", "ab" * 8, "ab" * 32, ""])
def test_malformed_operator_identity_is_rejected(value):
    config = HubConfig.from_dict({"operator_identity": value})
    with pytest.raises(ValueError):
        assert config.operator_hashes


def test_paths_are_expanded(monkeypatch):
    monkeypatch.setenv("HOME", "/home/operator")
    config = HubConfig.from_dict(
        {"storage_path": "~/hub", "reticulum_config_path": "~/.reticulum"}
    )
    assert config.resolved_storage_path == "/home/operator/hub"
    assert config.resolved_reticulum_config_path == "/home/operator/.reticulum"
    assert HubConfig().resolved_reticulum_config_path is None


def test_peer_hashes_are_validated_where_they_are_read():
    config = HubConfig()
    config.federation.peers = ["0b" * 16, " " + "0c" * 16 + " "]

    assert config.federation.peer_hashes == [b"\x0b" * 16, b"\x0c" * 16]


@pytest.mark.parametrize("value", ["nonsense", "0b0b", "0b" * 17])
def test_a_peer_that_is_not_a_destination_hash_is_rejected(value):
    """A truncated or misspelled peer must not become a hash nothing matches."""
    config = HubConfig()
    config.federation.peers = [value]

    with pytest.raises(ValueError):
        _ = config.federation.peer_hashes
