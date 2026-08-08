"""Virtual destination manager.

Every registered group gets its own RNS identity and its own inbound LXMF
delivery destination, so unmodified clients see a group as an ordinary LXMF
contact and no slash-command parsing is needed anywhere.

``LXMRouter.register_delivery_identity`` refuses more than one identity per
router, so group destinations are constructed here the same way the router
constructs its own and then registered in ``router.delivery_destinations``. The
router's inbound pipeline (packets, links and resources) is keyed by destination
hash, so it handles every group destination without further changes.
"""

from __future__ import annotations

import os
import random
import threading
import time

import LXMF
import RNS

from .config import HubConfig
from .store import GroupRecord, Store


def identity_from_key(private_key: bytes) -> RNS.Identity:
    identity = RNS.Identity(create_keys=False)
    if not identity.load_private_key(private_key):
        raise ValueError("Stored group identity key could not be loaded")
    return identity


class VirtualDestinationManager:
    """Owns the group identities and their LXMF delivery destinations."""

    def __init__(self, router: LXMF.LXMRouter, store: Store, config: HubConfig):
        self.router = router
        self.store = store
        self.config = config
        self._lock = threading.RLock()
        self._destinations: dict[str, RNS.Destination] = {}
        self._group_by_hash: dict[bytes, str] = {}
        self._next_announce: dict[str, float] = {}

    # -- lifecycle -------------------------------------------------------

    def load_groups(self) -> list[str]:
        """Hot-load every group in the database that is not yet attached."""
        attached = []
        for group in self.store.list_groups():
            if group.group_id not in self._destinations:
                self.attach(group)
                attached.append(group.group_id)
        return attached

    def attach(self, group: GroupRecord) -> RNS.Destination:
        with self._lock:
            existing = self._destinations.get(group.group_id)
            if existing is not None:
                return existing

            identity = identity_from_key(group.identity_key)
            destination = RNS.Destination(
                identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                LXMF.APP_NAME,
                "delivery",
            )
            os.makedirs(self.router.ratchetpath, exist_ok=True)
            destination.enable_ratchets(
                os.path.join(
                    self.router.ratchetpath,
                    f"{RNS.hexrep(destination.hash, delimit=False)}.ratchets",
                )
            )
            destination.set_packet_callback(self.router.delivery_packet)
            destination.set_link_established_callback(self.router.delivery_link_established)
            destination.display_name = group.display_name
            destination.stamp_cost = self.config.egress.stamp_cost
            destination.set_default_app_data(
                lambda destination_hash=destination.hash: self.router.get_announce_app_data(
                    destination_hash
                )
            )

            self.router.delivery_destinations[destination.hash] = destination
            self._destinations[group.group_id] = destination
            self._group_by_hash[destination.hash] = group.group_id
            self._next_announce[group.group_id] = time.time()
            RNS.log(
                f"Attached group '{group.group_id}' on {RNS.prettyhexrep(destination.hash)}",
                RNS.LOG_NOTICE,
            )
            return destination

    def detach(self, group_id: str) -> None:
        with self._lock:
            destination = self._destinations.pop(group_id, None)
            if destination is None:
                return
            self.router.delivery_destinations.pop(destination.hash, None)
            self._group_by_hash.pop(destination.hash, None)
            self._next_announce.pop(group_id, None)

    # -- lookups ---------------------------------------------------------

    def destination_for(self, group_id: str) -> RNS.Destination | None:
        with self._lock:
            return self._destinations.get(group_id)

    def group_for_hash(self, destination_hash: bytes) -> str | None:
        with self._lock:
            return self._group_by_hash.get(destination_hash)

    def attached_groups(self) -> list[str]:
        with self._lock:
            return sorted(self._destinations)

    # -- announces -------------------------------------------------------

    def announce(self, group_id: str) -> bool:
        destination = self.destination_for(group_id)
        if destination is None:
            return False
        self.router.announce(destination.hash)
        with self._lock:
            self._next_announce[group_id] = time.time() + self._announce_delay()
        RNS.log(f"Announced group '{group_id}'", RNS.LOG_DEBUG)
        return True

    def announce_due(self) -> list[str]:
        """Announce every group whose interval has elapsed."""
        now = time.time()
        with self._lock:
            due = [gid for gid, when in self._next_announce.items() if when <= now]
        return [group_id for group_id in due if self.announce(group_id)]

    def _announce_delay(self) -> float:
        jitter = self.config.announce_jitter_sec
        return self.config.announce_interval_sec + random.uniform(0, max(0.0, jitter))
