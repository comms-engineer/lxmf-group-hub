"""Group reflection core.

Inbound LXMF messages addressed to a group's virtual destination are verified
against the group ACL, stored once, and fanned out to the other members through
the egress queue. Author attribution is carried in the LXMF fields dictionary of
the reflected message, so threads keep their context on the client side.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

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

# Keys inside the author metadata dict carried on reflected messages.
META_AUTHOR = "author"
META_GROUP = "group"
META_HUB = "hub"


def pack_payload(timestamp: float, title: bytes, content: bytes, fields: dict[int, Any]) -> bytes:
    """Canonical LXMF payload blob, as stored and federated."""
    return msgpack.packb([timestamp, title, content, fields])


def unpack_payload(payload: bytes) -> tuple[float, bytes, bytes, dict[int, Any]]:
    timestamp, title, content, fields = msgpack.unpackb(payload, strict_map_key=False)
    return timestamp, title, content, fields or {}


class GroupHub:
    def __init__(
        self,
        config: HubConfig,
        store: Store,
        router: LXMF.LXMRouter,
        destinations: VirtualDestinationManager,
    ):
        self.config = config
        self.store = store
        self.router = router
        self.destinations = destinations

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
        # RNS already verified while unpacking the message.
        if not message.signature_validated:
            RNS.log(
                f"Dropping unverified LXM for group '{group_id}' from "
                f"{RNS.prettyhexrep(message.source_hash)}",
                RNS.LOG_NOTICE,
            )
            return

        if not self.authorise(group, message.source_hash):
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
        fields[self.config.author_field] = {
            META_AUTHOR: record.sender_hash,
            META_GROUP: record.group_id,
            META_HUB: hub_hash,
        }
        if self.config.author_prefix_in_content:
            author = RNS.prettyhexrep(record.sender_hash)
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
