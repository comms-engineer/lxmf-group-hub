"""Reflection core tests.

The LXMF router and the RNS destinations are stubbed: ``GroupHub`` only reads
attributes off the delivered message and looks group destinations up by hash, so
the reflection path can be exercised without a live Reticulum instance.
"""

from types import SimpleNamespace

from lxmf_hub.config import HubConfig
from lxmf_hub.hub import META_AUTHOR, GroupHub, pack_payload, unpack_payload
from lxmf_hub.store import ACL_INVITE, ACL_PUBLIC, ROLE_BANNED, Store, message_hash

GROUP = "ops"
GROUP_DESTINATION = bytes.fromhex("aabbccddeeff00112233445566778899")
ALICE = b"\xa1" * 16
BOB = b"\xb0" * 16
CAROL = b"\xc0" * 16


class StubDestinations:
    def __init__(self, mapping):
        self._mapping = mapping

    def group_for_hash(self, destination_hash):
        return self._mapping.get(destination_hash)

    def destination_for(self, group_id):
        for destination_hash, gid in self._mapping.items():
            if gid == group_id:
                return SimpleNamespace(hash=destination_hash)
        return None

    def attach(self, group):
        self._mapping[GROUP_DESTINATION] = group.group_id

    def attached_groups(self):
        return sorted(set(self._mapping.values()))


def make_hub(tmp_path, acl_mode=ACL_INVITE, config=None):
    store = Store(str(tmp_path / "hub.db"))
    store.create_group(GROUP, "Ops", b"\x00" * 64, acl_mode=acl_mode)
    destinations = StubDestinations({GROUP_DESTINATION: GROUP})
    hub = GroupHub(config or HubConfig(), store, router=None, destinations=destinations)
    return hub, store


def inbound(
    source=ALICE,
    destination=GROUP_DESTINATION,
    content=b"hello",
    timestamp=1000.0,
    fields=None,
    signed=True,
):
    return SimpleNamespace(
        destination_hash=destination,
        source_hash=source,
        timestamp=timestamp,
        title=b"",
        content=content,
        fields=fields or {},
        signature_validated=signed,
    )


def test_message_is_stored_and_reflected_to_other_members(tmp_path):
    hub, store = make_hub(tmp_path)
    for member in (ALICE, BOB, CAROL):
        store.add_member(GROUP, member)

    hub.handle_inbound(inbound())

    history = store.group_history(GROUP)
    assert len(history) == 1
    assert history[0].sender_hash == ALICE

    recipients = {item.recipient_hash for item in store.due_egress(10)}
    assert recipients == {BOB, CAROL}


def test_retransmission_is_dropped_and_not_reflected_twice(tmp_path):
    hub, store = make_hub(tmp_path)
    store.add_member(GROUP, ALICE)
    store.add_member(GROUP, BOB)

    hub.handle_inbound(inbound())
    hub.handle_inbound(inbound())

    assert len(store.group_history(GROUP)) == 1
    assert store.egress_depth() == 1


def test_unsigned_messages_are_dropped(tmp_path):
    hub, store = make_hub(tmp_path)
    store.add_member(GROUP, ALICE)
    store.add_member(GROUP, BOB)

    hub.handle_inbound(inbound(signed=False))

    assert store.group_history(GROUP) == []


def test_non_members_are_dropped_in_invite_groups(tmp_path):
    hub, store = make_hub(tmp_path)
    store.add_member(GROUP, BOB)

    hub.handle_inbound(inbound(source=ALICE))

    assert store.group_history(GROUP) == []
    assert store.get_role(GROUP, ALICE) is None


def test_public_groups_enroll_senders(tmp_path):
    hub, store = make_hub(tmp_path, acl_mode=ACL_PUBLIC)
    store.add_member(GROUP, BOB)

    hub.handle_inbound(inbound(source=ALICE))

    assert store.get_role(GROUP, ALICE) == "member"
    assert [item.recipient_hash for item in store.due_egress(10)] == [BOB]


def test_banned_members_are_dropped(tmp_path):
    hub, store = make_hub(tmp_path, acl_mode=ACL_PUBLIC)
    store.add_member(GROUP, ALICE, ROLE_BANNED)
    store.add_member(GROUP, BOB)

    hub.handle_inbound(inbound(source=ALICE))

    assert store.group_history(GROUP) == []


def test_banned_members_receive_nothing(tmp_path):
    hub, store = make_hub(tmp_path)
    store.add_member(GROUP, ALICE)
    store.add_member(GROUP, BOB, ROLE_BANNED)
    store.add_member(GROUP, CAROL)

    hub.handle_inbound(inbound())

    assert [item.recipient_hash for item in store.due_egress(10)] == [CAROL]


def test_messages_for_unknown_destinations_are_ignored(tmp_path):
    hub, store = make_hub(tmp_path)
    hub.handle_inbound(inbound(destination=b"\x09" * 16))
    assert store.group_history(GROUP) == []


def test_sender_supplied_author_field_is_stripped(tmp_path):
    config = HubConfig()
    hub, store = make_hub(tmp_path, acl_mode=ACL_PUBLIC, config=config)

    hub.handle_inbound(inbound(fields={config.author_field: {META_AUTHOR: BOB}, 0x08: b"thread"}))

    _timestamp, _title, _content, fields = unpack_payload(store.group_history(GROUP)[0].payload)
    assert config.author_field not in fields
    assert fields[0x08] == b"thread"


def test_federated_ingest_stores_once_and_fans_out(tmp_path):
    hub, store = make_hub(tmp_path)
    store.add_member(GROUP, ALICE)
    store.add_member(GROUP, BOB)

    payload = pack_payload(1234.0, b"", b"from a peer", {})
    records = [(GROUP, ALICE, 1234.0, payload)]

    assert hub.ingest_federated(records) == 1
    assert hub.ingest_federated(records) == 0
    assert [item.recipient_hash for item in store.due_egress(10)] == [BOB]
    assert store.group_history(GROUP)[0].msg_hash == message_hash(GROUP, ALICE, 1234.0, payload)


def test_federated_ingest_ignores_unknown_groups(tmp_path):
    hub, store = make_hub(tmp_path)
    payload = pack_payload(1.0, b"", b"x", {})
    assert hub.ingest_federated([("unknown", ALICE, 1.0, payload)]) == 0
