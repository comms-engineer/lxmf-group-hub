"""Anti-entropy tests.

Two hubs are wired together with an in-process fake link that serialises every
request and response through msgpack, the way an RNS Link would, and delivers
"resources" straight to the requester's resource callback. That exercises the
real reconciliation logic -- root exchange, tree traversal, bucket listing and
resource ingest -- without needing radios or a Reticulum instance.
"""

from types import SimpleNamespace

import msgpack
import pytest
import RNS

from lxmf_hub.config import HubConfig
from lxmf_hub.federation import FederationEngine
from lxmf_hub.hub import GroupHub, pack_payload
from lxmf_hub.store import ACL_PUBLIC, MessageRecord, Store, message_hash
from tests.test_hub import GROUP, GROUP_DESTINATION, StubDestinations

PEER_A = b"\x0a" * 16
PEER_B = b"\x0b" * 16
AUTHOR = b"\xa1" * 16
MEMBER = b"\xb0" * 16


def roundtrip(value):
    return msgpack.unpackb(msgpack.packb(value), strict_map_key=False)


class FakeLink:
    """Routes requests to a server engine's handlers, as an RNS Link would."""

    def __init__(self, server: "HarnessEngine", remote_identity):
        self.link_id = b"\x01" * 16
        self.server = server
        self.remote_identity = remote_identity
        self.resource_callback = None
        self.torn_down = False
        self.server._inbound_links[self.link_id] = self
        self.requests = []

    # -- RNS.Link surface used by the engine ----------------------------

    def identify(self, identity):
        self.identified_as = identity

    def set_resource_strategy(self, strategy):
        self.strategy = strategy

    def set_resource_concluded_callback(self, callback):
        self.resource_callback = callback

    def teardown(self):
        self.torn_down = True

    def request(self, path, data=None, response_callback=None, failed_callback=None, timeout=None):
        self.requests.append(path)
        handler = {
            "/fed/roots": self.server._serve_roots,
            "/fed/tree": self.server._serve_tree,
            "/fed/bucket": self.server._serve_bucket,
            "/fed/fetch": self.server._serve_fetch,
            "/fed/state": self.server._serve_state,
        }[path]
        arguments = [path, roundtrip(data), b"request", self.remote_identity, 0.0]
        if path == "/fed/fetch":
            arguments.insert(3, self.link_id)
        response = handler(*arguments)
        if response is None:
            failed_callback(SimpleNamespace(response=None))
            return True
        response_callback(SimpleNamespace(response=roundtrip(response)))
        return True

    # -- resource delivery ----------------------------------------------

    def deliver(self, payload):
        resource = SimpleNamespace(
            status=RESOURCE_COMPLETE, data=SimpleNamespace(read=lambda: payload)
        )
        self.resource_callback(resource)


RESOURCE_COMPLETE = 0x06  # RNS.Resource.COMPLETE


class HarnessEngine(FederationEngine):
    """Federation engine with the RNS-touching edges replaced."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._inbound_links = {}
        self.link_to_peer = None

    def _peer_allowed(self, remote_identity):
        return remote_identity == "trusted"

    def _push_resource(self, link, payload):
        link.deliver(payload)

    def _establish(self, peer_hash):
        return self.link_to_peer


def build_hub(tmp_path, name, peers, epoch_seconds=3600, depth=6):
    config = HubConfig()
    config.federation.peers = [peer.hex() for peer in peers]
    config.federation.epoch_seconds = epoch_seconds
    config.federation.merkle_depth = depth
    config.federation.retention_epochs = 10**6
    config.hub_name = name

    store = Store(str(tmp_path / f"{name}.db"))
    store.create_group(GROUP, "Ops", RNS.Identity().get_private_key(), acl_mode=ACL_PUBLIC)
    store.add_member(GROUP, AUTHOR)
    store.add_member(GROUP, MEMBER)
    destinations = StubDestinations({GROUP_DESTINATION: GROUP})
    hub = GroupHub(config, store, router=None, destinations=destinations)
    engine = HarnessEngine(config, store, hub, identity="local")
    return engine, store


def seed(store, count, start=0, timestamp=1000.0, salt=b""):
    stored = []
    for index in range(start, start + count):
        payload = pack_payload(timestamp, b"", salt + f"message-{index}".encode(), {})
        record = MessageRecord(
            msg_hash=message_hash(GROUP, AUTHOR, timestamp, payload),
            group_id=GROUP,
            sender_hash=AUTHOR,
            timestamp=timestamp,
            payload=payload,
        )
        store.store_message(record)
        stored.append(record)
    return stored


@pytest.fixture
def pair(tmp_path):
    local, local_store = build_hub(tmp_path, "local", [PEER_B])
    remote, remote_store = build_hub(tmp_path, "remote", [PEER_A])
    local.link_to_peer = FakeLink(remote, "trusted")
    return local, local_store, remote, remote_store


def test_identical_hubs_transfer_nothing(pair):
    local, local_store, remote, remote_store = pair
    for store in (local_store, remote_store):
        seed(store, 5)

    assert local.sync_peer(PEER_B) == 0
    assert local.link_to_peer.requests == ["/fed/state", "/fed/roots"]


def test_missing_messages_are_fetched_as_a_resource(pair):
    local, local_store, remote, remote_store = pair
    shared = seed(remote_store, 20)
    for record in shared[:12]:
        local_store.store_message(record)

    ingested = local.sync_peer(PEER_B)

    assert ingested == 8
    assert len(local_store.group_history(GROUP, limit=100)) == 20
    assert "/fed/tree" in local.link_to_peer.requests
    assert "/fed/bucket" in local.link_to_peer.requests
    assert local.link_to_peer.torn_down


def test_empty_local_store_backfills_whole_epoch(pair):
    local, local_store, remote, remote_store = pair
    seed(remote_store, 15)

    assert local.sync_peer(PEER_B) == 15
    assert local_store.epoch_hashes(GROUP, 0, 3600) == remote_store.epoch_hashes(GROUP, 0, 3600)


def test_backfill_spans_multiple_epochs(pair):
    local, local_store, remote, remote_store = pair
    seed(remote_store, 4, start=0, timestamp=100.0)
    seed(remote_store, 4, start=10, timestamp=4000.0)
    seed(remote_store, 4, start=20, timestamp=8000.0)

    assert local.sync_peer(PEER_B) == 12
    assert local_store.populated_epochs(GROUP, 3600) == [0, 1, 2]


def test_ingested_messages_are_queued_for_local_members(pair):
    local, local_store, remote, remote_store = pair
    seed(remote_store, 3)

    local.sync_peer(PEER_B)

    # The author is excluded, so only the other local member is queued.
    assert {item.recipient_hash for item in local_store.due_egress(50)} == {MEMBER}
    assert local_store.egress_depth() == 3


def test_messages_only_we_hold_are_not_re_requested(pair):
    local, local_store, remote, remote_store = pair
    shared = seed(remote_store, 5)
    for record in shared:
        local_store.store_message(record)
    seed(local_store, 5, start=50, salt=b"local-only")

    assert local.sync_peer(PEER_B) == 0


def test_unconfigured_peers_are_refused(pair):
    local, local_store, remote, remote_store = pair
    seed(remote_store, 5)
    local.link_to_peer.remote_identity = "stranger"

    with pytest.raises(IOError):
        local.sync_peer(PEER_B)


def test_mismatched_sync_parameters_abort_the_round(tmp_path):
    local, local_store = build_hub(tmp_path, "local", [PEER_B], epoch_seconds=3600)
    remote, remote_store = build_hub(tmp_path, "remote", [PEER_A], epoch_seconds=300)
    local.link_to_peer = FakeLink(remote, "trusted")
    seed(remote_store, 5)

    assert local.sync_peer(PEER_B) == 0
    assert local_store.group_history(GROUP) == []
    assert local_store.peer_state(PEER_B)[1] == "peer rejected sync parameters"


def test_groups_the_peer_alone_hosts_are_ignored(pair):
    local, local_store, remote, remote_store = pair
    remote_store.create_group("secret", "Secret", b"\x01" * 64)
    payload = pack_payload(1000.0, b"", b"not ours", {})
    remote_store.store_message(
        MessageRecord(
            msg_hash=message_hash("secret", AUTHOR, 1000.0, payload),
            group_id="secret",
            sender_hash=AUTHOR,
            timestamp=1000.0,
            payload=payload,
        )
    )

    assert local.sync_peer(PEER_B) == 0
    assert local_store.get_group("secret") is None


def test_sync_failure_is_recorded_when_no_link_can_be_made(pair):
    local, local_store, remote, remote_store = pair
    local.link_to_peer = None

    assert local.sync_peer(PEER_B) == 0
    assert local_store.peer_state(PEER_B)[1] == "link could not be established"
