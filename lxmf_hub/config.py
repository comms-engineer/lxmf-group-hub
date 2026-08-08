"""Configuration handling for the LXMF group hub."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any


@dataclass
class EgressConfig:
    """Client-facing egress settings, tuned for constrained RF links."""

    tokens_per_second: float = 0.5
    burst: int = 4
    max_attempts: int = 10
    retry_backoff_sec: float = 60.0
    retry_backoff_max_sec: float = 3600.0
    batch_size: int = 8
    prefer_propagation: bool = True
    propagation_node: str | None = None
    stamp_cost: int | None = None
    path_request_grace_sec: float = 15.0


@dataclass
class FederationConfig:
    """Inter-hub federation settings, tuned for 1Mbps+ links."""

    enabled: bool = True
    peers: list[str] = field(default_factory=list)
    sync_interval_sec: float = 300.0
    epoch_seconds: int = 3600
    merkle_depth: int = 8
    retention_epochs: int = 168
    link_timeout_sec: float = 30.0
    request_timeout_sec: float = 20.0
    max_fetch_batch: int = 256


@dataclass
class AtRestConfig:
    """At-rest encryption of message payloads and group private keys."""

    mode: str = "keyfile"  # one of "none", "keyfile", "passphrase"
    keyfile: str | None = None  # defaults to <storage_path>/at_rest.key


@dataclass
class HubConfig:
    storage_path: str = "~/.lxmf_hub"
    reticulum_config_path: str | None = None
    hub_name: str = "LXMF Group Hub"
    announce_interval_sec: float = 1800.0
    announce_jitter_sec: float = 60.0
    default_acl_mode: str = "invite"
    # LXMF field index used to carry the original author hash on reflected
    # messages. 0xFD (FIELD_CUSTOM_META) is the safe default: field 0x01 is
    # FIELD_EMBEDDED_LXMS in the LXMF spec and unmodified clients may try to
    # parse its contents as embedded messages.
    author_field: int = 0xFD
    author_prefix_in_content: bool = True
    log_level: int = 4
    at_rest: AtRestConfig = field(default_factory=AtRestConfig)
    egress: EgressConfig = field(default_factory=EgressConfig)
    federation: FederationConfig = field(default_factory=FederationConfig)

    @property
    def resolved_storage_path(self) -> str:
        return os.path.abspath(os.path.expanduser(self.storage_path))

    @property
    def resolved_reticulum_config_path(self) -> str | None:
        if self.reticulum_config_path is None:
            return None
        return os.path.abspath(os.path.expanduser(self.reticulum_config_path))

    @property
    def database_path(self) -> str:
        return os.path.join(self.resolved_storage_path, "hub.db")

    @property
    def identity_path(self) -> str:
        return os.path.join(self.resolved_storage_path, "hub_identity")

    @property
    def at_rest_keyfile(self) -> str:
        if self.at_rest.keyfile:
            return os.path.abspath(os.path.expanduser(self.at_rest.keyfile))
        return os.path.join(self.resolved_storage_path, "at_rest.key")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HubConfig:
        return _build(cls, data)

    @classmethod
    def load(cls, path: str | None) -> HubConfig:
        if path is None:
            return cls()
        with open(os.path.expanduser(path)) as config_file:
            return cls.from_dict(json.load(config_file))


def _build(cls, data: dict[str, Any]):
    # Annotations are strings under PEP 563, so nested sections are resolved
    # from the defaults of the dataclass rather than from type hints.
    defaults = cls()
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ValueError(f"Unknown configuration keys for {cls.__name__}: {', '.join(unknown)}")

    kwargs: dict[str, Any] = {}
    for name in known:
        if name not in data:
            continue
        value = data[name]
        current = getattr(defaults, name)
        if is_dataclass(current) and isinstance(value, dict):
            kwargs[name] = _build(type(current), value)
        else:
            kwargs[name] = value
    return cls(**kwargs)
