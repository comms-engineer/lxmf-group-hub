"""Author attribution on reflected messages."""

from lxmf_hub.config import HubConfig
from lxmf_hub.hub import (
    META_AUTHOR,
    META_GROUP,
    META_HUB,
    META_NAME,
    GroupHub,
    pack_payload,
)
from lxmf_hub.personas import PersonaRegistry
from lxmf_hub.store import MessageRecord, Store, message_hash
from tests.test_hub import GROUP, GROUP_DESTINATION, StubDestinations

AUTHOR = b"\xa1" * 16
HUB_HASH = b"\x0f" * 16


def make(tmp_path, config, content=b"hello", fields=None):
    store = Store(str(tmp_path / "hub.db"))
    store.create_group(GROUP, "Ops", b"\x00" * 64)
    destinations = StubDestinations({GROUP_DESTINATION: GROUP})
    hub = GroupHub(config, store, router=None, destinations=destinations)
    payload = pack_payload(1000.0, b"title", content, fields or {})
    record = MessageRecord(
        msg_hash=message_hash(GROUP, AUTHOR, 1000.0, payload),
        group_id=GROUP,
        sender_hash=AUTHOR,
        timestamp=1000.0,
        payload=payload,
    )
    return hub, record


def test_author_metadata_is_injected(tmp_path):
    config = HubConfig()
    hub, record = make(tmp_path, config)

    title, content, fields = hub.reflection_payload(record, HUB_HASH)

    assert title == b"title"
    assert fields[config.author_field] == {
        META_AUTHOR: AUTHOR,
        META_GROUP: GROUP,
        META_HUB: HUB_HASH,
        META_NAME: None,
    }
    assert content.endswith(b"hello")


def test_author_field_index_is_configurable(tmp_path):
    config = HubConfig()
    config.author_field = 0x01
    hub, record = make(tmp_path, config)

    _title, _content, fields = hub.reflection_payload(record, HUB_HASH)

    assert 0x01 in fields
    assert fields[0x01][META_AUTHOR] == AUTHOR


def test_existing_fields_are_preserved(tmp_path):
    config = HubConfig()
    hub, record = make(tmp_path, config, fields={0x08: b"thread-id"})

    _title, _content, fields = hub.reflection_payload(record, HUB_HASH)

    assert fields[0x08] == b"thread-id"


def test_content_prefix_can_be_disabled(tmp_path):
    config = HubConfig()
    config.author_prefix_in_content = False
    hub, record = make(tmp_path, config)

    _title, content, _fields = hub.reflection_payload(record, HUB_HASH)

    assert content == b"hello"


def test_a_named_sender_is_attributed_by_username(tmp_path):
    config = HubConfig()
    hub, record = make(tmp_path, config)
    PersonaRegistry(hub.store).claim(AUTHOR, "alice")

    _title, content, fields = hub.reflection_payload(record, HUB_HASH)

    assert fields[config.author_field][META_NAME] == "alice"
    assert content.startswith(b"alice")
    # The hash stays on the message: a client that verifies authorship must not
    # have to trust a display name to do it.
    assert fields[config.author_field][META_AUTHOR] == AUTHOR


def test_an_unnamed_sender_is_still_attributed_by_hash(tmp_path):
    config = HubConfig()
    hub, record = make(tmp_path, config)

    _title, content, fields = hub.reflection_payload(record, HUB_HASH)

    assert fields[config.author_field][META_NAME] is None
    assert content.startswith(b"<")
