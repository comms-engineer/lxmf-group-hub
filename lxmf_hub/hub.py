"""Group reflection core.

Inbound LXMF messages addressed to a group's virtual destination are verified
against the group ACL, stored once, and fanned out to the other members through
the egress queue. Author attribution is carried in the LXMF fields dictionary of
the reflected message, so threads keep their context on the client side.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import LXMF
import msgpack
import RNS

from .config import HubConfig
from .destinations import VirtualDestinationManager
from .store import (
    ACL_PUBLIC,
    ORIGIN_FEDERATED,
    ORIGIN_LOCAL,
    ROLE_BANNED,
    ROLE_MEMBER,
    GroupRecord,
    MessageRecord,
    Store,
    message_hash,
)

if TYPE_CHECKING:  # The command channel reads liveness, which reads the hub.
    from .usercmds import UserCommands

# Keys inside the author metadata dict carried on reflected messages.
META_AUTHOR = "author"
META_GROUP = "group"
META_HUB = "hub"
META_NAME = "name"


def pack_payload(timestamp: float, title: bytes, content: bytes, fields: dict[int, Any]) -> bytes:
    """Canonical LXMF payload blob, as stored and federated."""
    return msgpack.packb([timestamp, title, content, fields])


def unpack_payload(payload: bytes) -> tuple[float, bytes, bytes, dict[int, Any]]:
    timestamp, title, content, fields = msgpack.unpackb(payload, strict_map_key=False)
    return timestamp, title, content, fields or {}


def _message_text(content: bytes | str | None) -> str:
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace")
    return content or ""


@dataclass
class _UnverifiedEntry:
    """A message held because its sender's identity was not yet cached.

    Its raw bytes are kept rather than the ``LXMessage``: signature validation
    happens once, during unpacking, so re-validating later means unpacking
    again from scratch, not re-checking the object already given up on.
    """

    packed: bytes
    source_hash: bytes
    deadline: float
    next_request: float = 0.0


class GroupHub:
    def __init__(
        self,
        config: HubConfig,
        store: Store,
        router: LXMF.LXMRouter,
        destinations: VirtualDestinationManager,
        commands: UserCommands | None = None,
    ):
        self.config = config
        self.store = store
        self.router = router
        self.destinations = destinations
        # Optional so a hub can be constructed without the command channel;
        # the daemon always wires one in.
        self.commands = commands
        # Messages held because RNS had not yet cached the sender's identity --
        # typically right after a restart, before the hub has heard any fresh
        # announces of its own. Retried from EgressScheduler.tick() rather than
        # a dedicated thread, since that loop already runs every 0.5-2s.
        self._unverified: list[_UnverifiedEntry] = []
        self._unverified_lock = threading.Lock()

    # -- group administration --------------------------------------------

    def create_group(
        self, group_id: str, display_name: str | None = None, acl_mode: str | None = None
    ) -> GroupRecord:
        identity = RNS.Identity()
        group = self.store.create_group(
            group_id=group_id,
            display_name=display_name or group_id,
            identity_key=identity.get_private_key(),
            acl_mode=acl_mode or self.config.default_acl_mode,
        )
        self.destinations.attach(group)
        return group

    # -- inbound ---------------------------------------------------------

    def handle_inbound(self, message: LXMF.LXMessage) -> None:
        """Delivery callback for every group destination on this hub."""
        group_id = self.destinations.group_for_hash(message.destination_hash)
        if group_id is None:
            RNS.log(
                "Dropping LXM for unknown destination"
                f" {RNS.prettyhexrep(message.destination_hash)}",
                RNS.LOG_DEBUG,
            )
            return

        group = self.store.get_group(group_id)
        if group is None:
            return

        # Identity and authorisation rest solely on the Ed25519 signature that
        # RNS already verified while unpacking the message. That verification
        # needs the sender's identity cached locally, which a hub that just
        # restarted may not have yet -- so an unresolved identity is held and
        # retried instead of dropped outright; anything else unverified (a bad
        # signature) is dropped, since retrying it would never change the result.
        if not message.signature_validated:
            if (
                getattr(message, "unverified_reason", None) == LXMF.LXMessage.SOURCE_UNKNOWN
                and getattr(message, "packed", None)
            ):
                self._hold_unverified(group_id, message)
            else:
                RNS.log(
                    f"Dropping unverified LXM for group '{group_id}' from "
                    f"{RNS.prettyhexrep(message.source_hash)}",
                    RNS.LOG_NOTICE,
                )
            return

        if not self.authorise(group, message.source_hash):
            return

        # A command is answered instead of being reflected, so the group does not
        # see one member's '/status'. Only the known verbs are taken: anything
        # else beginning with a slash is a message and is posted as one.
        if self.commands is not None and self.commands.handle(
            group_id, message.source_hash, _message_text(message.content)
        ):
            RNS.log(
                f"Answered command from {RNS.prettyhexrep(message.source_hash)}"
                f" in group '{group_id}'",
                RNS.LOG_INFO,
            )
            return

        payload = pack_payload(
            message.timestamp,
            message.title,
            message.content,
            self.sanitise_fields(message.fields),
        )
        record = MessageRecord(
            msg_hash=message_hash(group_id, message.source_hash, message.timestamp, payload),
            group_id=group_id,
            sender_hash=message.source_hash,
            timestamp=message.timestamp,
            payload=payload,
            origin=ORIGIN_LOCAL,
        )
        stored, queued = self.store_and_fan_out(record)
        if not stored:
            RNS.log(f"Dropping duplicate LXM for group '{group_id}'", RNS.LOG_DEBUG)
            return

        RNS.log(
            f"Accepted message for group '{group_id}' from "
            f"{RNS.prettyhexrep(message.source_hash)}, queued for {queued} recipients",
            RNS.LOG_INFO,
        )

    def authorise(self, group: GroupRecord, sender_hash: bytes) -> bool:
        role = self.store.get_role(group.group_id, sender_hash)
        if role == ROLE_BANNED:
            RNS.log(
                f"Dropping LXM from banned member {RNS.prettyhexrep(sender_hash)}"
                f" in group '{group.group_id}'",
                RNS.LOG_DEBUG,
            )
            return False
        if role is not None:
            return True
        if self.store.is_peer_member(group.group_id, sender_hash):
            # A member of this group on a federated hub is a member of the group.
            # Accepting their posts here is what makes a failover address usable
            # in an invite-only group without the operator re-inviting anyone.
            return True
        if group.acl_mode == ACL_PUBLIC:
            self.store.add_member(group.group_id, sender_hash, ROLE_MEMBER)
            RNS.log(
                f"Enrolled {RNS.prettyhexrep(sender_hash)} in public group '{group.group_id}'",
                RNS.LOG_NOTICE,
            )
            return True
        RNS.log(
            f"Dropping LXM from non-member {RNS.prettyhexrep(sender_hash)}"
            f" in invite-only group '{group.group_id}'",
            RNS.LOG_NOTICE,
        )
        return False

    def sanitise_fields(self, fields: dict[int, Any] | None) -> dict[int, Any]:
        """Strip hub-managed fields so senders cannot forge attribution."""
        clean = dict(fields or {})
        clean.pop(self.config.author_field, None)
        return clean

    # -- unverified retry --------------------------------------------------

    def _hold_unverified(self, group_id: str, message: LXMF.LXMessage) -> None:
        """Park a message whose sender identity RNS has not cached yet.

        A path request nudges the sender to (re-)announce, which is what lets
        the identity resolve without the sender doing anything itself; without
        it, the hub would only ever learn the identity on the sender's own
        announce schedule, which can be much longer than a client is willing to
        wait after one silently dropped message.
        """
        RNS.log(
            f"Identity for {RNS.prettyhexrep(message.source_hash)} not yet cached,"
            f" holding message for group '{group_id}' and requesting a path",
            RNS.LOG_NOTICE,
        )
        if not RNS.Transport.has_path(message.source_hash):
            RNS.Transport.request_path(message.source_hash)
        now = time.time()
        entry = _UnverifiedEntry(
            packed=message.packed,
            source_hash=message.source_hash,
            deadline=now + self.config.egress.unverified_hold_sec,
            next_request=now + self.config.egress.path_request_grace_sec,
        )
        with self._unverified_lock:
            self._unverified.append(entry)

    def retry_unverified(self) -> None:
        """Re-validate held messages, replaying any whose identity resolved.

        Meant to be called from a frequent, already-existing tick (the egress
        scheduler's) rather than run its own thread: held messages are rare and
        short-lived, so a second polling loop would be pure overhead.
        """
        with self._unverified_lock:
            if not self._unverified:
                return
            pending, self._unverified = self._unverified, []

        now = time.time()
        still_pending: list[_UnverifiedEntry] = []
        for entry in pending:
            if now >= entry.deadline:
                RNS.log(
                    f"Giving up on held message from {RNS.prettyhexrep(entry.source_hash)}:"
                    " identity never resolved",
                    RNS.LOG_WARNING,
                )
                continue

            if RNS.Identity.recall(entry.source_hash) is None:
                if now >= entry.next_request:
                    if not RNS.Transport.has_path(entry.source_hash):
                        RNS.Transport.request_path(entry.source_hash)
                    entry.next_request = now + self.config.egress.path_request_grace_sec
                still_pending.append(entry)
                continue

            message = LXMF.LXMessage.unpack_from_bytes(entry.packed)
            if message.signature_validated:
                RNS.log(
                    f"Identity for {RNS.prettyhexrep(entry.source_hash)} resolved,"
                    " replaying held message",
                    RNS.LOG_NOTICE,
                )
                self.handle_inbound(message)
            else:
                RNS.log(
                    f"Held message from {RNS.prettyhexrep(entry.source_hash)} still"
                    " fails signature validation now that its identity is known,"
                    " dropping",
                    RNS.LOG_NOTICE,
                )

        if still_pending:
            with self._unverified_lock:
                self._unverified.extend(still_pending)

    # -- federation ingest -----------------------------------------------

    def ingest_federated(self, records: Iterable[tuple[str, bytes, float, bytes]]) -> int:
        """Store messages received from a peer hub and fan them out locally."""
        ingested = 0
        for group_id, sender_hash, timestamp, payload in records:
            group = self.store.get_group(group_id)
            if group is None:
                continue
            expected = message_hash(group_id, sender_hash, timestamp, payload)
            record = MessageRecord(
                msg_hash=expected,
                group_id=group_id,
                sender_hash=sender_hash,
                timestamp=timestamp,
                payload=payload,
                origin=ORIGIN_FEDERATED,
            )
            stored, _queued = self.store_and_fan_out(record)
            if not stored:
                continue
            ingested += 1
        return ingested

    # -- fan out ---------------------------------------------------------

    def recipients(self, group_id: str) -> list[bytes]:
        """Who this hub delivers to: its own members, plus adopted ones.

        Members of a live peer are deliberately absent. They get their copy from
        their own hub, and delivering to them as well would put two copies of
        every message on their RF link. Adopted members are the exception: their
        hub stopped answering, so this one delivers in its place.

        A ban always wins. An adoption row can outlive the ban that followed it --
        the member was adopted while their hub was down, then banned here -- and a
        banned member who still receives every message is not banned.
        """
        members = self.store.list_members(group_id, include_banned=True)
        local = [user_hash for user_hash, role in members if role != ROLE_BANNED]
        banned = {user_hash for user_hash, role in members if role == ROLE_BANNED}
        known = set(local) | banned
        return local + [
            user_hash for user_hash in self.store.list_adopted(group_id) if user_hash not in known
        ]

    def store_and_fan_out(self, record: MessageRecord) -> tuple[bool, int]:
        """Persist a message and queue it for everyone but its author, atomically.

        Storing first and fanning out afterwards is what makes a message vanish:
        the store is also the deduplication and federation source, so a crash
        between the two leaves a message that every hub agrees exists and nobody
        ever delivers -- and the retry, arriving at a hub that now knows the
        message, is dropped as a duplicate.
        """
        recipients = [
            user_hash
            for user_hash in self.recipients(record.group_id)
            if user_hash != record.sender_hash
        ]
        return self.store.store_and_enqueue(record, recipients)

    def fan_out(self, record: MessageRecord) -> int:
        """Queue an already stored message for every recipient except its author."""
        queued = 0
        for user_hash in self.recipients(record.group_id):
            if user_hash == record.sender_hash:
                continue
            if self.store.enqueue_egress(record.group_id, user_hash, record.msg_hash):
                queued += 1
        return queued

    # -- outbound construction -------------------------------------------

    def reflection_payload(
        self, record: MessageRecord, hub_hash: bytes
    ) -> tuple[bytes, bytes, dict[int, Any]]:
        """Title, content and fields of a reflection, with author attribution."""
        _timestamp, title, content, fields = unpack_payload(record.payload)
        fields = dict(fields)
        # A username where the author has claimed one: a federated persona name
        # is more use to a reader than a hash, and the hash stays in the metadata
        # for anything that wants to match on identity rather than display it.
        name = self.store.display_name_for(record.sender_hash)
        fields[self.config.author_field] = {
            META_AUTHOR: record.sender_hash,
            META_GROUP: record.group_id,
            META_HUB: hub_hash,
            META_NAME: name,
        }
        if self.config.author_prefix_in_content:
            author = name if name else RNS.prettyhexrep(record.sender_hash)
            content = f"{author}: ".encode() + content
        return title, content, fields

    def build_reflection(
        self, record: MessageRecord, recipient_identity: RNS.Identity
    ) -> LXMF.LXMessage:
        """Build the LXMF message reflecting a stored message to one member."""
        source = self.destinations.destination_for(record.group_id)
        if source is None:
            raise ValueError(f"Group '{record.group_id}' is not attached")

        title, content, fields = self.reflection_payload(record, source.hash)
        destination = RNS.Destination(
            recipient_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            LXMF.APP_NAME,
            "delivery",
        )
        return LXMF.LXMessage(
            destination,
            source,
            content=content,
            title=title,
            fields=fields,
        )

    def build_notice(self, group_id: str, recipient_identity: RNS.Identity, body: str):
        """Build a hub-authored message: failover notices and directory answers.

        It carries no author metadata, because the hub is the author. A client
        renders it as ordinary text from the group contact it already holds,
        which is the only channel an unmodified client can be reached on.
        """
        source = self.destinations.destination_for(group_id)
        if source is None:
            raise ValueError(f"Group '{group_id}' is not attached")
        destination = RNS.Destination(
            recipient_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            LXMF.APP_NAME,
            "delivery",
        )
        return LXMF.LXMessage(destination, source, content=body.encode("utf-8"), title=b"")

    # -- retention -------------------------------------------------------

    def prune(self) -> int:
        retention = self.config.federation.retention_epochs * self.config.federation.epoch_seconds
        if retention <= 0:
            return 0
        return self.store.prune_messages(time.time() - retention)

    def stats(self) -> list[str]:
        return [
            f"groups={len(self.destinations.attached_groups())}",
            f"egress_queue={self.store.egress_depth()}",
            f"notice_queue={self.store.notice_depth()}",
            f"control_queue={self.store.control_depth()}",
        ]
