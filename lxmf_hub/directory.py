"""Endpoint directory.

A client that wants to know which hubs carry a group has no way to ask RNS: an
announce carries one destination and says nothing about the others. The directory
is an ordinary LXMF destination that answers any message with the group list this
hub knows about, its own address for each group and every peer's, with the age of
the last contact so a reader can judge which is worth using.

The peer entries come from ``/fed/state`` gossip. They are what a peer said about
itself on the last successful sync round; the ages are this hub's evidence, not a
liveness claim about right now. A client with a ping or path tool can settle that
itself against the hash printed here.
"""

from __future__ import annotations

import os
import time

import LXMF
import RNS

from .config import HubConfig
from .destinations import group_destination_hash
from .failover import format_age
from .store import SOURCE_DIRECTORY, Store

MAX_LINE_GROUPS = 40

# A queued directory answer has no group of its own. The column is part of the
# notice queue's key, so it gets a reserved name rather than an empty string.
DIRECTORY_GROUP = "*directory*"


def load_directory_identity(path: str) -> RNS.Identity:
    """The directory needs its own identity.

    The hub identity is already taken: the control destination uses it with the
    LXMF delivery aspect, and a second destination on the same identity and
    aspect would collide on the same hash.
    """
    if os.path.isfile(path):
        identity = RNS.Identity.from_file(path)
        if identity is not None:
            return identity
        raise ValueError(f"Could not load directory identity from {path}")
    identity = RNS.Identity()
    identity.to_file(path)
    return identity


class DirectoryChannel:
    """LXMF destination that lists the hubs and addresses of each group."""

    def __init__(self, config: HubConfig, store: Store, router: LXMF.LXMRouter):
        self.config = config
        self.store = store
        self.router = router
        self.destination: RNS.Destination | None = None
        self._answered: dict[bytes, float] = {}
        self._next_announce = 0.0

    # -- lifecycle -------------------------------------------------------

    def start(self) -> RNS.Destination | None:
        if not self.config.directory.enabled:
            return None
        identity = load_directory_identity(self.config.directory_identity_path)
        destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, LXMF.APP_NAME, "delivery"
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
        destination.display_name = f"{self.config.hub_name} directory"
        destination.stamp_cost = None
        destination.set_default_app_data(
            lambda destination_hash=destination.hash: self.router.get_announce_app_data(
                destination_hash
            )
        )
        self.router.delivery_destinations[destination.hash] = destination
        self.destination = destination
        RNS.log(f"Directory on {RNS.prettyhexrep(destination.hash)}", RNS.LOG_NOTICE)
        return destination

    def owns(self, destination_hash: bytes) -> bool:
        return self.destination is not None and destination_hash == self.destination.hash

    def announce_due(self) -> bool:
        if self.destination is None or time.time() < self._next_announce:
            return False
        self.router.announce(self.destination.hash)
        self._next_announce = time.time() + self.config.announce_interval_sec
        return True

    # -- inbound ---------------------------------------------------------

    def handle(self, message: LXMF.LXMessage) -> None:
        """Answer a query, at most once per requester per interval.

        The directory answers anybody, so the rate limit is what keeps it from
        being used to make this hub transmit on request.
        """
        if not message.signature_validated:
            return
        now = time.time()
        last = self._answered.get(message.source_hash, 0.0)
        if now - last < self.config.directory.min_reply_interval_sec:
            RNS.log(
                f"Ignoring repeat directory query from"
                f" {RNS.prettyhexrep(message.source_hash)}",
                RNS.LOG_DEBUG,
            )
            return
        self._answered[message.source_hash] = now
        # The egress scheduler sends it, so a burst of queries spends the same
        # tokens as reflections instead of transmitting straight away.
        self.store.enqueue_notice(
            DIRECTORY_GROUP, message.source_hash, self.listing(), source=SOURCE_DIRECTORY
        )

    # -- listing ---------------------------------------------------------

    def listing(self) -> str:
        """One line per hub per group: group, ACL, hub, address, last contact."""
        now = time.time()
        lines = []
        for group in self.store.list_groups()[:MAX_LINE_GROUPS]:
            lines.append(
                f"{group.group_id} {group.acl_mode} {self.config.hub_name}"
                f" {group_destination_hash(group.identity_key).hex()} here"
            )
            for entry in self.store.list_peer_groups(group.group_id):
                lines.append(
                    f"{entry.group_id} {entry.acl_mode} {entry.hub_name}"
                    f" {entry.destination_hash.hex()} seen {format_age(now - entry.updated_at)} ago"
                )
        if not lines:
            return "This hub hosts no groups."
        return "\n".join(lines)

    # -- outbound --------------------------------------------------------

    def build_reply(self, recipient_identity: RNS.Identity, body: str) -> LXMF.LXMessage:
        """An answer comes from the directory destination, not from any group."""
        if self.destination is None:
            raise ValueError("The directory is not running")
        target = RNS.Destination(
            recipient_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            LXMF.APP_NAME,
            "delivery",
        )
        return LXMF.LXMessage(target, self.destination, content=body.encode("utf-8"), title=b"")
