"""Peer liveness, adoption of a dead hub's members, and client notices.

A group's destination hash belongs to the hub that generated its identity, so a
hub going down takes its address with it. Nothing in RNS or LXMF tells a client
to use a different address, and an unmodified client cannot be told to in any
machine-readable way. What is left is telling the human: a short message, from a
contact the client already has, naming the hash to add.

The liveness signal is the last federation round a peer actually answered, not
the last one this hub attempted. A peer silent for ``peer_timeout_sec`` is
treated as down, which is a statement about this hub's vantage point and not a
claim that the peer is unreachable from anywhere else. For the same window after
this hub's own startup a silent peer is neither up nor down, since a restart says
nothing about anybody else.

Three events produce a notice:

- Adoption. A peer went stale, this hub serves the same group, so it starts
  delivering to that peer's members and tells them which hash to post to.
- Hand-back. The peer answered again; adopted members are released and told.
- Isolation. This hub can reach none of its peers. Its own members are told that
  messages may not be reaching members elsewhere, and are given the other hubs'
  addresses for that group so they can decide for themselves.

A hub does not adopt a peer's members for a group it does not host, and never
touches the peer's database. Adoption rows live in SQLite, so a restart mid
outage neither re-notifies nor forgets.
"""

from __future__ import annotations

import time

import RNS

from .config import HubConfig
from .hub import GroupHub
from .store import Store

FLAG_ISOLATED = "isolated"

LIVE = "live"
STALE = "stale"
UNKNOWN = "unknown"

# Liveness is only refreshed by a federation round, so a timeout shorter than a
# couple of intervals calls a healthy peer dead between rounds. Equal to one
# interval is still too tight: a single slow or lost round is enough.
MIN_TIMEOUT_INTERVALS = 2


def format_age(seconds: float) -> str:
    if seconds < 120:
        return f"{int(seconds)}s"
    if seconds < 7200:
        return f"{int(seconds / 60)}m"
    return f"{int(seconds / 3600)}h"


class FailoverEngine:
    """Watches peer liveness and tells affected clients what changed."""

    def __init__(self, config: HubConfig, store: Store, hub: GroupHub):
        self.config = config
        self.store = store
        self.hub = hub
        self.started_at = time.time()
        self._peers: list[bytes] = config.federation.peer_hashes
        self._last_check = 0.0
        self.peer_timeout = self._peer_timeout()

    def _peer_timeout(self) -> float:
        """The peer timeout to actually use, raised if it undercuts sync timing.

        A peer's liveness only advances when it answers a federation round, so a
        timeout below ``MIN_TIMEOUT_INTERVALS`` sync intervals makes every hub
        declare its healthy peers stale between rounds, adopt their members and
        put failover notices on every client's link. That is worse than a late
        adoption, so the floor wins over the configured value.
        """
        configured = self.config.failover.peer_timeout_sec
        floor = MIN_TIMEOUT_INTERVALS * self.config.federation.sync_interval_sec
        if not self.config.federation.enabled or configured >= floor:
            return configured
        RNS.log(
            f"failover.peer_timeout_sec of {format_age(configured)} is under"
            f" {MIN_TIMEOUT_INTERVALS} federation sync intervals"
            f" (federation.sync_interval_sec"
            f" {format_age(self.config.federation.sync_interval_sec)}), which would"
            f" call a live peer stale between rounds. Using"
            f" {format_age(floor)} instead.",
            RNS.LOG_WARNING,
        )
        return floor

    # -- liveness --------------------------------------------------------

    def peer_status(self, peer_hash: bytes, now: float | None = None) -> str:
        """What this hub can say about a peer: ``LIVE``, ``STALE`` or ``UNKNOWN``.

        A restart is not evidence about a peer. For the first ``peer_timeout_sec``
        after startup a silent peer is ``UNKNOWN`` rather than either, because
        this hub has not yet had as long to reach it as it gives itself before
        calling a peer dead. Treating that window as ``LIVE`` would release an
        adoption made before the restart and send a hand-back naming an address
        that is still down; treating it as ``STALE`` would adopt on the strength
        of a timestamp written before the hub went down.
        """
        now = time.time() if now is None else now
        timeout = self.peer_timeout
        last_success = self.store.peer_last_success(peer_hash)
        if last_success is not None and now - last_success <= timeout:
            return LIVE
        if now - self.started_at <= timeout:
            return UNKNOWN
        return STALE

    def stale_peers(self, now: float | None = None) -> list[bytes]:
        now = time.time() if now is None else now
        return [peer for peer in self._peers if self.peer_status(peer, now) == STALE]

    # -- main loop -------------------------------------------------------

    def check_due(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if now - self._last_check < self.config.failover.check_interval_sec:
            return False
        self._last_check = now
        self.check(now)
        return True

    def check(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        statuses = {peer: self.peer_status(peer, now) for peer in self._peers}

        for peer_hash, status in statuses.items():
            if status == STALE:
                self.adopt_peer(peer_hash)
            elif status == LIVE and peer_hash in set(self.store.adopted_peers()):
                self.release(peer_hash)

        if UNKNOWN not in statuses.values():
            self.check_isolation({peer for peer, s in statuses.items() if s == STALE})

    # -- adoption --------------------------------------------------------

    def adopt_peer(self, peer_hash: bytes) -> int:
        """Serve the members of an unreachable peer, for shared groups only."""
        adopted = 0
        hub_name = self.peer_name(peer_hash)
        for group in self.store.list_groups():
            members = self.store.list_peer_members(peer_hash, group.group_id)
            if not members:
                continue
            # Banned members count as local: adopting one would hand somebody
            # the operator ejected a fresh copy of every message.
            local = {
                user_hash
                for user_hash, _role in self.store.list_members(
                    group.group_id, include_banned=True
                )
            }
            fresh = self.store.adopt(
                peer_hash, group.group_id, [item for item in members if item not in local]
            )
            if not fresh:
                continue
            adopted += len(fresh)
            RNS.log(
                f"Serving {len(fresh)} member(s) of group '{group.group_id}' for unreachable peer"
                f" {RNS.prettyhexrep(peer_hash)}",
                RNS.LOG_NOTICE,
            )
            if self.config.failover.notify_clients:
                body = self.adoption_notice(group.group_id, hub_name)
                for user_hash in fresh:
                    self.store.enqueue_notice(group.group_id, user_hash, body)
        return adopted

    def release(self, peer_hash: bytes) -> int:
        """Hand a recovered peer's members back and tell them so."""
        released = self.store.release_peer(peer_hash)
        if not released:
            return 0
        hub_name = self.peer_name(peer_hash)
        RNS.log(
            f"Peer {RNS.prettyhexrep(peer_hash)} answered again, releasing"
            f" {len(released)} adopted member(s)",
            RNS.LOG_NOTICE,
        )
        if self.config.failover.notify_clients:
            for group_id, user_hash in released:
                self.store.enqueue_notice(
                    group_id, user_hash, self.handback_notice(group_id, hub_name, peer_hash)
                )
        return len(released)

    # -- isolation -------------------------------------------------------

    def check_isolation(self, stale: set[bytes]) -> bool:
        """Tell local members when this hub can reach none of its peers.

        Their messages are still stored and reflected to everyone on this hub, so
        the group has not stopped working; what has stopped is anything crossing
        to the other hubs. That distinction is what the notice states.
        """
        if not self._peers:
            return False
        isolated = len(stale) == len(self._peers)
        was_isolated = self.store.get_flag(FLAG_ISOLATED)
        if isolated == was_isolated:
            return False

        self.store.set_flag(FLAG_ISOLATED, isolated)
        RNS.log(
            "This hub cannot reach any federation peer"
            if isolated
            else "Federation peer connectivity restored",
            RNS.LOG_WARNING if isolated else RNS.LOG_NOTICE,
        )
        if not self.config.failover.notify_isolation:
            return True

        for group in self.store.list_groups():
            body = (
                self.isolation_notice(group.group_id)
                if isolated
                else f"{group.group_id}: this hub is back in contact with its peers."
                " Messages are crossing to the other hubs again."
            )
            for user_hash, _role in self.store.list_members(group.group_id):
                self.store.enqueue_notice(group.group_id, user_hash, body)
        return True

    # -- notice text -----------------------------------------------------

    def adoption_notice(self, group_id: str, peer_name: str) -> str:
        destination = self.local_endpoint(group_id)
        return (
            f"{group_id}: your hub ({peer_name}) has not answered this hub for"
            f" {format_age(self.peer_timeout)}."
            f" {self.config.hub_name} is serving {group_id} in the meantime."
            f" To post, add this contact: {destination}."
            " You keep receiving messages here either way."
        )

    def handback_notice(self, group_id: str, peer_name: str, peer_hash: bytes) -> str:
        endpoint = self.peer_endpoint(peer_hash, group_id)
        home = f" Its address is {endpoint}." if endpoint else ""
        return (
            f"{group_id}: {peer_name} is answering again, so {self.config.hub_name}"
            f" has stopped serving you.{home}"
        )

    def isolation_notice(self, group_id: str) -> str:
        others = self.other_endpoints(group_id)
        alternatives = (
            " Other hubs for this group: " + "; ".join(others) if others else ""
        )
        return (
            f"{group_id}: {self.config.hub_name} cannot reach any peer hub."
            " Messages here still reach everybody on this hub, but may not be"
            f" reaching members on the others.{alternatives}"
        )

    # -- endpoints -------------------------------------------------------

    def local_endpoint(self, group_id: str) -> str:
        destination = self.hub.destinations.destination_for(group_id)
        return destination.hash.hex() if destination is not None else "unknown"

    def peer_endpoint(self, peer_hash: bytes, group_id: str) -> str | None:
        for entry in self.store.list_peer_groups(group_id):
            if entry.peer_hash == peer_hash:
                return entry.destination_hash.hex()
        return None

    def other_endpoints(self, group_id: str) -> list[str]:
        now = time.time()
        return [
            f"{entry.hub_name} {entry.destination_hash.hex()}"
            f" (last seen {format_age(now - entry.updated_at)} ago)"
            for entry in self.store.list_peer_groups(group_id)
        ]

    def peer_name(self, peer_hash: bytes) -> str:
        for entry in self.store.list_peer_groups():
            if entry.peer_hash == peer_hash:
                return entry.hub_name
        return RNS.prettyhexrep(peer_hash)
