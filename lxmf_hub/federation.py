"""Inter-hub federation: Merkle-tree anti-entropy over RNS Links.

Peer hubs are assumed to be reachable over moderate-to-high bandwidth links, so
reconciliation is allowed to be chatty and bulk transfers use RNS Resources
rather than individual LXMF packets.

One sync round with a peer:

1. ``/fed/roots``  -- exchange per-group, per-epoch Merkle roots.
2. ``/fed/tree``   -- for every epoch whose root differs, walk the prefix tree
   down, level by level, requesting only the children of nodes that disagree.
3. ``/fed/bucket`` -- at the leaf level, list the message hashes the peer holds
   in the differing buckets, and subtract what we already have.
4. ``/fed/fetch``  -- ask for the missing messages; the peer answers with an RNS
   Resource carrying the batch, which is ingested into the local store.

``/fed/personas`` replicates usernames: the full persona set and its device rows,
including unlink tombstones, merged by revision with a deterministic rule for a
name two partitioned hubs both claimed. It is the same shape of state exchange as
``/fed/state`` and equally non-fatal -- a peer that cannot answer it still gets
its messages reconciled.

``/fed/state`` runs alongside as the round's first request. It carries what the
peer serves rather than what it holds: hub name, one destination hash per group,
and the member set of each group. That's what lets a hub answer directory
queries with other hubs' addresses, and lets a standby serve the members of a
hub that stopped answering.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from typing import Any

import msgpack
import RNS

from .config import HubConfig
from .destinations import group_destination_hash
from .hub import GroupHub
from .merkle import PrefixMerkleTree, children_of, diverging_nodes
from .personas import PersonaRegistry
from .store import PersonaIdentity, PersonaRecord, Store
from .usercmds import UserCommands

FED_APP_NAME = "lxmfhub"
FED_ASPECT = "federation"

PATH_ROOTS = "/fed/roots"
PATH_TREE = "/fed/tree"
PATH_BUCKET = "/fed/bucket"
PATH_FETCH = "/fed/fetch"
PATH_STATE = "/fed/state"
PATH_PERSONAS = "/fed/personas"

# A persona row is small, there is one per person rather than one per message,
# and a hub that answers with a truncated set would leave the caller unable to
# tell a released name from one it simply did not receive. So the whole set goes
# in one answer, with a ceiling that only a hub with an implausible number of
# users reaches.
MAX_PERSONAS_PER_RESPONSE = 4096
MAX_IDENTITIES_PER_RESPONSE = MAX_PERSONAS_PER_RESPONSE * 4

PROTOCOL_VERSION = 1

RESOURCE_MESSAGES = 1

# A hub that just started has no idea what it missed while it was down, and
# waiting a full sync interval to find out means the gap is invisible for five
# minutes on the default settings. Long enough for interfaces and paths to come
# up, short enough that a restart is not a five-minute hole.
INITIAL_SYNC_DELAY = 15.0

MAX_EPOCHS_PER_RESPONSE = 512
MAX_NODES_PER_REQUEST = 1024
MAX_BUCKETS_PER_REQUEST = 64


class SyncState:
    """Per-sync bookkeeping for resources arriving from a peer."""

    def __init__(self) -> None:
        self.expected = 0
        self.ingested = 0
        self.arrived = threading.Event()


class FederationEngine:
    def __init__(
        self,
        config: HubConfig,
        store: Store,
        hub: GroupHub,
        identity: RNS.Identity,
        registry: PersonaRegistry | None = None,
        commands: UserCommands | None = None,
    ):
        self.config = config
        self.store = store
        self.hub = hub
        self.identity = identity
        # Personas replicate over the same links as messages. Optional so a test
        # or a caller that only wants message anti-entropy can leave them out.
        self.registry = registry if registry is not None else PersonaRegistry(store)
        self.commands = commands
        self.destination: RNS.Destination | None = None
        self._inbound_links: dict[bytes, RNS.Link] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._peers: list[bytes] = config.federation.peer_hashes
        self._allowed: set[bytes] = set(self._peers)

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            FED_APP_NAME,
            FED_ASPECT,
        )
        self.destination.set_link_established_callback(self._inbound_link_established)
        for path, handler in (
            (PATH_ROOTS, self._serve_roots),
            (PATH_TREE, self._serve_tree),
            (PATH_BUCKET, self._serve_bucket),
            (PATH_FETCH, self._serve_fetch),
            (PATH_STATE, self._serve_state),
            (PATH_PERSONAS, self._serve_personas),
        ):
            self.destination.register_request_handler(
                path, response_generator=handler, allow=RNS.Destination.ALLOW_ALL
            )
        RNS.log(
            f"Federation endpoint on {RNS.prettyhexrep(self.destination.hash)}"
            f" with {len(self._peers)} configured peer(s)",
            RNS.LOG_NOTICE,
        )
        self._thread = threading.Thread(target=self._run, name="federation", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def announce(self) -> None:
        if self.destination is not None:
            self.destination.announce()

    def _run(self) -> None:
        delay = min(INITIAL_SYNC_DELAY, self.config.federation.sync_interval_sec)
        while not self._stop.is_set():
            self._stop.wait(delay)
            delay = self.config.federation.sync_interval_sec
            if self._stop.is_set():
                return
            for peer_hash in self._peers:
                if self._stop.is_set():
                    return
                try:
                    self.sync_peer(peer_hash)
                except Exception as exception:
                    RNS.log(
                        f"Sync with {RNS.prettyhexrep(peer_hash)} failed: {exception}",
                        RNS.LOG_ERROR,
                    )
                    self.store.record_peer_sync(peer_hash, str(exception))

    # -- server side -----------------------------------------------------

    def _inbound_link_established(self, link: RNS.Link) -> None:
        link.set_resource_strategy(RNS.Link.ACCEPT_NONE)
        link.set_link_closed_callback(self._inbound_link_closed)
        self._inbound_links[link.link_id] = link

    def _inbound_link_closed(self, link: RNS.Link) -> None:
        self._inbound_links.pop(link.link_id, None)

    def _peer_allowed(self, remote_identity: RNS.Identity | None) -> bool:
        if remote_identity is None:
            return False
        peer_hash = RNS.Destination.hash(remote_identity, FED_APP_NAME, FED_ASPECT)
        if peer_hash in self._allowed:
            return True
        RNS.log(
            f"Rejecting federation request from unconfigured peer"
            f" {RNS.prettyhexrep(peer_hash)}",
            RNS.LOG_NOTICE,
        )
        return False

    def _serve_roots(self, path, data, request_id, remote_identity, requested_at):
        if not self._peer_allowed(remote_identity):
            return None
        version, epoch_seconds, depth, group_ids = _unpack_request(data, 4)
        if version != PROTOCOL_VERSION:
            return [PROTOCOL_VERSION, None]
        if not self._parameters_match(epoch_seconds, depth):
            return [PROTOCOL_VERSION, None]

        wanted = set(group_ids) if group_ids else None
        roots: dict[str, dict[int, bytes]] = {}
        for group_id in self._local_group_ids():
            if wanted is not None and group_id not in wanted:
                continue
            roots[group_id] = self._epoch_roots(group_id)
        return [PROTOCOL_VERSION, roots]

    def _serve_tree(self, path, data, request_id, remote_identity, requested_at):
        if not self._peer_allowed(remote_identity):
            return None
        group_id, epoch, level, indices = _unpack_request(data, 4)
        tree = self._tree(group_id, epoch)
        return tree.node_hashes(level, list(indices)[:MAX_NODES_PER_REQUEST])

    def _serve_bucket(self, path, data, request_id, remote_identity, requested_at):
        if not self._peer_allowed(remote_identity):
            return None
        group_id, epoch, indices = _unpack_request(data, 3)
        tree = self._tree(group_id, epoch)
        return {
            index: tree.bucket_members(index) for index in list(indices)[:MAX_BUCKETS_PER_REQUEST]
        }

    def _serve_fetch(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not self._peer_allowed(remote_identity):
            return None
        group_id, msg_hashes = _unpack_request(data, 2)
        link = self._inbound_links.get(link_id)
        if link is None:
            return [0]

        wanted = list(msg_hashes)[: self.config.federation.max_fetch_batch]
        records = [
            record
            for record in self.store.get_messages(wanted)
            if record.group_id == group_id
        ]
        if not records:
            return [0]

        payload = msgpack.packb(
            [
                RESOURCE_MESSAGES,
                [
                    [record.group_id, record.sender_hash, record.timestamp, record.payload]
                    for record in records
                ],
            ]
        )
        self._push_resource(link, payload)
        RNS.log(
            f"Pushing {len(records)} message(s) of group '{group_id}' to peer as resource",
            RNS.LOG_DEBUG,
        )
        return [len(records)]

    def _serve_state(self, path, data, request_id, remote_identity, requested_at):
        """Tell a peer which groups this hub serves, and to whom.

        Member hashes leave the hub here. A configured peer already receives
        every message and every sender hash for the groups it shares, so this
        exposes nothing to it that federation did not already.
        """
        if not self._peer_allowed(remote_identity):
            return None
        groups: dict[str, list[Any]] = {}
        members: dict[str, list[bytes]] = {}
        for group in self.store.list_groups():
            groups[group.group_id] = [
                group_destination_hash(group.identity_key),
                group.acl_mode,
            ]
            members[group.group_id] = [
                user_hash for user_hash, _role in self.store.list_members(group.group_id)
            ]
        return [PROTOCOL_VERSION, self.config.hub_name, groups, members]

    def _serve_personas(self, path, data, request_id, remote_identity, requested_at):
        """Hand a peer every persona and device row this hub knows.

        The full set every round, rather than a delta: a name is a single small
        row, and full state means a hub that was down for a week converges on its
        first round instead of needing a changelog nobody kept.
        """
        if not self._peer_allowed(remote_identity):
            return None
        personas, identities = self.registry.snapshot()
        if (
            len(personas) > MAX_PERSONAS_PER_RESPONSE
            or len(identities) > MAX_IDENTITIES_PER_RESPONSE
        ):
            RNS.log(
                f"Truncating persona state at {MAX_PERSONAS_PER_RESPONSE} persona(s) and"
                f" {MAX_IDENTITIES_PER_RESPONSE} device(s): this hub holds"
                f" {len(personas)} and {len(identities)}, so peers will not see all of them",
                RNS.LOG_WARNING,
            )
        return [
            PROTOCOL_VERSION,
            personas[:MAX_PERSONAS_PER_RESPONSE],
            identities[:MAX_IDENTITIES_PER_RESPONSE],
        ]

    def _push_resource(self, link: RNS.Link, payload: bytes) -> None:
        """Bulk state moves as a Resource, never as individual LXMF packets."""
        RNS.Resource(payload, link)

    # -- client side -----------------------------------------------------

    def sync_peer(self, peer_hash: bytes) -> int:
        """Reconcile with one peer. Returns the number of messages ingested."""
        federation = self.config.federation
        link = self._establish(peer_hash)
        if link is None:
            self.store.record_peer_sync(peer_hash, "link could not be established")
            return 0

        state = SyncState()
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_concluded_callback(
            lambda resource: self._ingest_resource(resource, state)
        )

        try:
            link.identify(self.identity)
            self._exchange_state(link, peer_hash)
            self._exchange_personas(link, peer_hash)
            response = self._request(
                link,
                PATH_ROOTS,
                [PROTOCOL_VERSION, federation.epoch_seconds, federation.merkle_depth, None],
            )
            if not response or response[0] != PROTOCOL_VERSION or response[1] is None:
                self.store.record_peer_sync(peer_hash, "peer rejected sync parameters")
                RNS.log(
                    f"Peer {RNS.prettyhexrep(peer_hash)} rejected our sync parameters:"
                    " epoch length and Merkle depth must match on both hubs",
                    RNS.LOG_WARNING,
                )
                return 0

            ingested = 0
            failed: list[str] = []
            local_groups = set(self._local_group_ids())
            for group_id, remote_roots in response[1].items():
                if group_id not in local_groups:
                    continue
                try:
                    ingested += self._reconcile_group(link, state, group_id, remote_roots)
                except Exception as exception:
                    # One group's reconciliation failing is not a reason to skip
                    # the groups after it in the same round: they are independent,
                    # and the alternative is that a single wedged group stops this
                    # hub federating anything at all.
                    failed.append(group_id)
                    RNS.log(
                        f"Reconciling group '{group_id}' with"
                        f" {RNS.prettyhexrep(peer_hash)} failed: {exception}",
                        RNS.LOG_WARNING,
                    )

            self.store.record_peer_sync(
                peer_hash,
                f"could not reconcile: {', '.join(sorted(failed))}" if failed else None,
            )
            # The peer answered, whatever happened per group, so it is live.
            self.store.record_peer_success(peer_hash)
            if ingested:
                RNS.log(
                    f"Ingested {ingested} message(s) from {RNS.prettyhexrep(peer_hash)}",
                    RNS.LOG_NOTICE,
                )
            return ingested
        finally:
            link.teardown()

    def _exchange_state(self, link: RNS.Link, peer_hash: bytes) -> None:
        """Record what the peer serves. A failure here must not abort the sync."""
        try:
            response = self._request(link, PATH_STATE, [PROTOCOL_VERSION])
        except Exception as exception:
            RNS.log(f"Could not read peer state: {exception}", RNS.LOG_DEBUG)
            return
        if not response or response[0] != PROTOCOL_VERSION:
            return
        # The peer answered, which is the evidence failover waits for.
        self.store.record_peer_success(peer_hash)
        _version, hub_name, groups, members = response
        self.store.record_peer_state(
            peer_hash,
            str(hub_name),
            {
                str(group_id): (bytes(destination), str(acl_mode))
                for group_id, (destination, acl_mode) in groups.items()
            },
            {
                str(group_id): [bytes(item) for item in hashes]
                for group_id, hashes in members.items()
            },
        )

    def _exchange_personas(self, link: RNS.Link, peer_hash: bytes) -> None:
        """Merge a peer's personas. A failure here must not abort the sync.

        Usernames are a convenience; messages are not. A peer running an older
        build, or one that fails this request, still gets its messages
        reconciled.
        """
        try:
            response = self._request(link, PATH_PERSONAS, [PROTOCOL_VERSION])
        except Exception as exception:
            RNS.log(f"Could not read peer personas: {exception}", RNS.LOG_DEBUG)
            return
        if not response or response[0] != PROTOCOL_VERSION or len(response) != 3:
            return
        _version, personas, identities = response
        try:
            losers = self.registry.merge(
                [_persona_from_wire(row) for row in personas],
                [_identity_from_wire(row) for row in identities],
            )
        except Exception as exception:
            RNS.log(
                f"Merging personas from {RNS.prettyhexrep(peer_hash)} failed: {exception}",
                RNS.LOG_WARNING,
            )
            return
        for persona, lost_name in losers:
            # The name is gone from under its owner, who is holding a client that
            # will keep showing it until somebody says otherwise.
            RNS.log(
                f"Persona {persona.persona_id.hex()} lost the username '{lost_name}' to an"
                f" earlier claim from {RNS.prettyhexrep(peer_hash)}",
                RNS.LOG_NOTICE,
            )
            if self.commands is not None:
                self.commands.notify_name_lost(persona.persona_id, lost_name)

    def _reconcile_group(
        self, link: RNS.Link, state: SyncState, group_id: str, remote_roots: dict[int, bytes]
    ) -> int:
        ingested = 0
        oldest = self._oldest_epoch()
        for epoch, remote_root in sorted(remote_roots.items()):
            if epoch < oldest:
                continue
            local_tree = self._tree(group_id, epoch)
            if local_tree.root == remote_root:
                continue
            missing = self._missing_in_epoch(link, group_id, epoch, local_tree)
            if not missing:
                continue
            RNS.log(
                f"Epoch {epoch} of group '{group_id}': {len(missing)} message(s) to fetch",
                RNS.LOG_DEBUG,
            )
            ingested += self._fetch(link, state, group_id, missing)
        return ingested

    def _missing_in_epoch(
        self, link: RNS.Link, group_id: str, epoch: int, local_tree: PrefixMerkleTree
    ) -> list[bytes]:
        """Walk the tree top-down and return the hashes only the peer holds."""
        depth = local_tree.depth
        diverging = [0]
        for level in range(1, depth + 1):
            candidates = children_of(diverging)[:MAX_NODES_PER_REQUEST]
            remote_nodes = self._request(link, PATH_TREE, [group_id, epoch, level, candidates])
            if not remote_nodes:
                return []
            diverging = diverging_nodes(local_tree.node_hashes(level, candidates), remote_nodes)
            if not diverging:
                return []

        missing: list[bytes] = []
        for chunk in _chunked(diverging, MAX_BUCKETS_PER_REQUEST):
            remote_buckets = self._request(link, PATH_BUCKET, [group_id, epoch, chunk])
            if not remote_buckets:
                continue
            for index, hashes in remote_buckets.items():
                local = set(local_tree.bucket_members(index))
                missing.extend(msg_hash for msg_hash in hashes if msg_hash not in local)
        return missing

    def _fetch(
        self, link: RNS.Link, state: SyncState, group_id: str, msg_hashes: Sequence[bytes]
    ) -> int:
        ingested_before = state.ingested
        for batch in _chunked(list(msg_hashes), self.config.federation.max_fetch_batch):
            state.arrived.clear()
            response = self._request(link, PATH_FETCH, [group_id, batch])
            if not response or not response[0]:
                continue
            state.expected = response[0]
            if not state.arrived.wait(self.config.federation.link_timeout_sec):
                RNS.log("Timed out waiting for a peer message resource", RNS.LOG_WARNING)
                break
        return state.ingested - ingested_before

    def _ingest_resource(self, resource: RNS.Resource, state: SyncState) -> None:
        try:
            if resource.status != RNS.Resource.COMPLETE or resource.data is None:
                RNS.log("Discarding incomplete peer resource", RNS.LOG_WARNING)
                return
            resource_type, records = msgpack.unpackb(resource.data.read(), strict_map_key=False)
            if resource_type != RESOURCE_MESSAGES:
                RNS.log(f"Ignoring unknown peer resource type {resource_type}", RNS.LOG_WARNING)
                return
            state.ingested += self.hub.ingest_federated(
                (group_id, sender_hash, timestamp, payload)
                for group_id, sender_hash, timestamp, payload in records
            )
        except Exception as exception:
            RNS.log(f"Could not ingest peer resource: {exception}", RNS.LOG_ERROR)
        finally:
            state.arrived.set()

    # -- link and request helpers ----------------------------------------

    def _establish(self, peer_hash: bytes) -> RNS.Link | None:
        timeout = self.config.federation.link_timeout_sec
        if not RNS.Transport.has_path(peer_hash):
            RNS.Transport.request_path(peer_hash)
            deadline = time.time() + timeout
            while time.time() < deadline and not RNS.Transport.has_path(peer_hash):
                time.sleep(0.5)

        identity = RNS.Identity.recall(peer_hash)
        if identity is None:
            RNS.log(f"No path or identity for peer {RNS.prettyhexrep(peer_hash)}", RNS.LOG_DEBUG)
            return None

        destination = RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE, FED_APP_NAME, FED_ASPECT
        )
        established = threading.Event()
        link = RNS.Link(destination, established_callback=lambda _link: established.set())
        if not established.wait(timeout):
            link.teardown()
            return None
        return link

    def _request(self, link: RNS.Link, path: str, data: Any) -> Any:
        timeout = self.config.federation.request_timeout_sec
        outcome: dict[str, Any] = {}
        done = threading.Event()

        def on_response(receipt) -> None:
            outcome["response"] = receipt.response
            done.set()

        def on_failure(receipt) -> None:
            outcome["error"] = f"request to {path} failed"
            done.set()

        receipt = link.request(
            path,
            data=data,
            response_callback=on_response,
            failed_callback=on_failure,
            timeout=timeout,
        )
        if receipt is False:
            raise OSError(f"Could not send request to {path}")
        if not done.wait(timeout + 5):
            raise OSError(f"Request to {path} timed out")
        if "error" in outcome:
            raise OSError(outcome["error"])
        return outcome.get("response")

    # -- local state -----------------------------------------------------

    def _local_group_ids(self) -> list[str]:
        return [group.group_id for group in self.store.list_groups()]

    def _parameters_match(self, epoch_seconds: int, depth: int) -> bool:
        return (
            epoch_seconds == self.config.federation.epoch_seconds
            and depth == self.config.federation.merkle_depth
        )

    def _oldest_epoch(self) -> int:
        federation = self.config.federation
        return int(time.time() / federation.epoch_seconds) - federation.retention_epochs

    def _epoch_roots(self, group_id: str) -> dict[int, bytes]:
        epoch_seconds = self.config.federation.epoch_seconds
        epochs = self.store.populated_epochs(
            group_id, epoch_seconds, since=self._oldest_epoch() * epoch_seconds
        )
        roots: dict[int, bytes] = {}
        for epoch in epochs[-MAX_EPOCHS_PER_RESPONSE:]:
            roots[epoch] = self._tree(group_id, epoch).root
        return roots

    def _tree(self, group_id: str, epoch: int) -> PrefixMerkleTree:
        hashes = self.store.epoch_hashes(group_id, epoch, self.config.federation.epoch_seconds)
        return PrefixMerkleTree(hashes, depth=self.config.federation.merkle_depth)


def _persona_from_wire(row: Any) -> PersonaRecord:
    persona_id, name, claimed_at, revision, updated_at = row
    return PersonaRecord(
        persona_id=bytes(persona_id),
        name=None if name is None else str(name),
        claimed_at=float(claimed_at),
        revision=int(revision),
        updated_at=float(updated_at),
    )


def _identity_from_wire(row: Any) -> PersonaIdentity:
    user_hash, persona_id, added_at, removed_at = row
    return PersonaIdentity(
        user_hash=bytes(user_hash),
        persona_id=bytes(persona_id),
        added_at=float(added_at),
        removed_at=None if removed_at is None else float(removed_at),
    )


def _unpack_request(data: Any, arity: int) -> tuple[Any, ...]:
    if not isinstance(data, (list, tuple)) or len(data) != arity:
        raise ValueError("Malformed federation request")
    return tuple(data)


def _chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[index : index + size] for index in range(0, len(items), size)]
