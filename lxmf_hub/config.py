"""Configuration handling for the LXMF group hub."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any

# RNS truncates destination hashes to 128 bits.
DESTINATION_HASH_LENGTH = 16


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
    # How long a message handed to LXMF may be in flight before the scheduler
    # assumes neither callback is coming and offers the queue row again. LXMF
    # retries a delivery of its own accord (five attempts, ten seconds apart,
    # plus link setup), so this has to be comfortably longer than that or the
    # hub sends a second copy of a message that is still on its way.
    delivery_timeout_sec: float = 600.0


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

    @property
    def peer_hashes(self) -> list[bytes]:
        """Peer destination hashes, validated as 16-byte hex strings.

        Validated here rather than at each use site so a typo in one peer entry
        is a clear configuration error at startup instead of a ValueError from
        inside a federation or failover thread, where it would silently stop
        that thread for the lifetime of the process.
        """
        hashes = []
        for value in self.peers:
            try:
                peer_hash = bytes.fromhex(value.strip())
            except ValueError as exception:
                raise ValueError(f"federation peer '{value}' is not hex") from exception
            if len(peer_hash) != DESTINATION_HASH_LENGTH:
                raise ValueError(
                    f"federation peer '{value}' is not a"
                    f" {DESTINATION_HASH_LENGTH}-byte destination hash"
                )
            hashes.append(peer_hash)
        return hashes


@dataclass
class FailoverConfig:
    """What a hub does when a peer stops answering.

    ``peer_timeout_sec`` defaults to six federation sync intervals, so a single
    missed round, a path rebuild, or a restart on the peer does not put failover
    notices on anybody's RF link.
    """

    enabled: bool = True
    peer_timeout_sec: float = 1800.0
    check_interval_sec: float = 60.0
    notify_clients: bool = True
    notify_isolation: bool = True


@dataclass
class DirectoryConfig:
    """The endpoint directory clients can query for group addresses."""

    enabled: bool = True
    min_reply_interval_sec: float = 60.0


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
    # LXMF destination hash, or list of hashes, allowed to administer this hub
    # over LXMF. Empty means the control destination is never brought up.
    operator_identity: str | list[str] | None = None
    at_rest: AtRestConfig = field(default_factory=AtRestConfig)
    egress: EgressConfig = field(default_factory=EgressConfig)
    federation: FederationConfig = field(default_factory=FederationConfig)
    failover: FailoverConfig = field(default_factory=FailoverConfig)
    directory: DirectoryConfig = field(default_factory=DirectoryConfig)

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
    def operator_hashes(self) -> list[bytes]:
        """Operator destination hashes, validated as 16-byte hex strings."""
        raw = self.operator_identity
        if raw is None:
            return []
        values = [raw] if isinstance(raw, str) else list(raw)
        hashes = []
        for value in values:
            try:
                operator_hash = bytes.fromhex(value.strip())
            except ValueError as exception:
                raise ValueError(f"operator_identity '{value}' is not hex") from exception
            if len(operator_hash) != DESTINATION_HASH_LENGTH:
                raise ValueError(
                    f"operator_identity '{value}' is not a"
                    f" {DESTINATION_HASH_LENGTH}-byte destination hash"
                )
            hashes.append(operator_hash)
        return hashes

    @property
    def directory_identity_path(self) -> str:
        return os.path.join(self.resolved_storage_path, "directory_identity")

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
