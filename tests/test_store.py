import pytest

from lxmf_hub.store import (
    ACL_PUBLIC,
    ORIGIN_LOCAL,
    ROLE_BANNED,
    MessageRecord,
    Store,
    message_hash,
)

GROUP = "ops"
SENDER = bytes.fromhex("00112233445566778899aabbccddeeff")


def make_store(tmp_path, at_rest="none"):
    store = Store(str(tmp_path / "hub.db"))
    if at_rest != "none":
        store.bind_cipher(at_rest, str(tmp_path / "at_rest.key"))
    return store


def make_message(index=0, group_id=GROUP, sender=SENDER, timestamp=1000.0):
    payload = f"payload-{index}".encode()
    return MessageRecord(
        msg_hash=message_hash(group_id, sender, timestamp, payload),
        group_id=group_id,
        sender_hash=sender,
        timestamp=timestamp,
        payload=payload,
        origin=ORIGIN_LOCAL,
    )


def test_database_uses_wal(tmp_path):
    store = make_store(tmp_path)
    mode = store._db.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_duplicate_messages_are_dropped(tmp_path):
    store = make_store(tmp_path)
    record = make_message()
    assert store.store_message(record) is True
    assert store.store_message(record) is False
    assert store.has_message(record.msg_hash)


def test_message_hash_is_hub_independent():
    payload = b"hello"
    first = message_hash(GROUP, SENDER, 1.5, payload)
    second = message_hash(GROUP, SENDER, 1.5, payload)
    assert first == second
    assert message_hash("other", SENDER, 1.5, payload) != first
    assert message_hash(GROUP, SENDER, 1.6, payload) != first


def test_members_and_roles(tmp_path):
    store = make_store(tmp_path)
    store.create_group(GROUP, "Ops", b"\x00" * 64, acl_mode=ACL_PUBLIC)
    store.add_member(GROUP, SENDER)
    other = b"\x01" * 16
    store.add_member(GROUP, other, ROLE_BANNED)

    assert store.get_role(GROUP, SENDER) == "member"
    assert [user for user, _ in store.list_members(GROUP)] == [SENDER]
    assert len(store.list_members(GROUP, include_banned=True)) == 2

    store.remove_member(GROUP, SENDER)
    assert store.get_role(GROUP, SENDER) is None


def test_egress_queue_is_deduplicated_and_deferred(tmp_path):
    store = make_store(tmp_path)
    record = make_message()
    store.store_message(record)

    assert store.enqueue_egress(GROUP, SENDER, record.msg_hash) is True
    assert store.enqueue_egress(GROUP, SENDER, record.msg_hash) is False
    assert store.egress_depth() == 1

    item = store.due_egress(10)[0]
    store.defer_egress(item.item_id, 3600)
    assert store.due_egress(10) == []

    later = store.due_egress(10, now=2**31)
    assert later[0].attempts == 1

    store.complete_egress(item.item_id)
    assert store.egress_depth() == 0


def test_epoch_bucketing(tmp_path):
    store = make_store(tmp_path)
    for index, timestamp in enumerate([10.0, 20.0, 3700.0]):
        store.store_message(make_message(index=index, timestamp=timestamp))

    assert store.populated_epochs(GROUP, 3600) == [0, 1]
    assert len(store.epoch_hashes(GROUP, 0, 3600)) == 2
    assert len(store.epoch_hashes(GROUP, 1, 3600)) == 1
    assert store.epoch_hashes(GROUP, 0, 3600) == sorted(store.epoch_hashes(GROUP, 0, 3600))


def test_prune_drops_expired_history(tmp_path):
    store = make_store(tmp_path)
    store.store_message(make_message(index=0, timestamp=10.0))
    store.store_message(make_message(index=1, timestamp=5000.0))
    assert store.prune_messages(1000.0) == 1
    assert len(store.group_history(GROUP)) == 1


def test_payloads_are_encrypted_at_rest(tmp_path):
    store = make_store(tmp_path, at_rest="keyfile")
    record = make_message()
    store.store_message(record)
    group = store.create_group(GROUP, "Ops", b"\x02" * 64)

    raw_payload = store._db.execute(
        "SELECT lxmf_payload_blob FROM messages WHERE msg_hash = ?", (record.msg_hash,)
    ).fetchone()[0]
    raw_identity = store._db.execute(
        "SELECT identity_key FROM groups WHERE group_id = ?", (GROUP,)
    ).fetchone()[0]

    assert record.payload not in raw_payload
    assert group.identity_key not in raw_identity
    assert store.get_message(record.msg_hash).payload == record.payload
    assert store.get_group(GROUP).identity_key == group.identity_key


def test_wrong_at_rest_key_is_detected(tmp_path):
    store = make_store(tmp_path, at_rest="keyfile")
    store.close()

    with open(tmp_path / "at_rest.key", "wb") as key_file:
        key_file.write(b"\x03" * 64)

    reopened = Store(str(tmp_path / "hub.db"))
    with pytest.raises(ValueError):
        reopened.bind_cipher("keyfile", str(tmp_path / "at_rest.key"))


def test_encrypted_database_refuses_plaintext_mode(tmp_path):
    store = make_store(tmp_path, at_rest="keyfile")
    record = make_message()
    store.store_message(record)
    store.close()

    reopened = Store(str(tmp_path / "hub.db"))
    with pytest.raises(ValueError):
        reopened.get_message(record.msg_hash)
