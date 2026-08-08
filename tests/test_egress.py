"""Egress scheduler tests: rate limiting, persistence and retry behaviour."""

from types import SimpleNamespace

import LXMF
import pytest

from lxmf_hub.config import HubConfig
from lxmf_hub.egress import EgressScheduler, TokenBucket
from lxmf_hub.hub import GroupHub, pack_payload
from lxmf_hub.store import MessageRecord, Store, message_hash
from tests.test_hub import GROUP, GROUP_DESTINATION, StubDestinations

AUTHOR = b"\xa1" * 16
MEMBER = b"\xb0" * 16


class StubRouter:
    def __init__(self, propagation_node=None):
        self.sent = []
        self.propagation_node = propagation_node

    def get_outbound_propagation_node(self):
        return self.propagation_node

    def handle_outbound(self, message):
        self.sent.append(message)


def build(tmp_path, monkeypatch, config=None, identity="known", router=None):
    config = config or HubConfig()
    store = Store(str(tmp_path / "hub.db"))
    store.create_group(GROUP, "Ops", b"\x00" * 64)
    store.add_member(GROUP, MEMBER)

    destinations = StubDestinations({GROUP_DESTINATION: GROUP})
    hub = GroupHub(config, store, router=None, destinations=destinations)
    router = router or StubRouter()
    scheduler = EgressScheduler(config, store, hub, router, destinations)

    payload = pack_payload(1000.0, b"", b"hello", {})
    record = MessageRecord(
        msg_hash=message_hash(GROUP, AUTHOR, 1000.0, payload),
        group_id=GROUP,
        sender_hash=AUTHOR,
        timestamp=1000.0,
        payload=payload,
    )
    store.store_message(record)
    store.enqueue_egress(GROUP, MEMBER, record.msg_hash)

    monkeypatch.setattr("RNS.Identity.recall", staticmethod(lambda _hash: identity))
    monkeypatch.setattr("RNS.Transport.has_path", staticmethod(lambda _hash: True))
    monkeypatch.setattr(
        "RNS.Transport.request_path", staticmethod(lambda _hash: requested.append(_hash))
    )
    monkeypatch.setattr(
        hub, "build_reflection", lambda rec, ident: SimpleNamespace(
            desired_method=None,
            register_delivery_callback=lambda callback: None,
            register_failed_callback=lambda callback: None,
        )
    )
    return scheduler, store, router, record


requested = []


def test_token_bucket_limits_burst_then_refills():
    bucket = TokenBucket(rate=100.0, burst=2)
    assert bucket.consume() and bucket.consume()
    assert not bucket.consume()
    assert bucket.time_until() > 0


def test_delivery_is_rate_limited(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.tokens_per_second = 0.0
    config.egress.burst = 1
    scheduler, store, router, _record = build(tmp_path, monkeypatch, config=config)

    for extra in range(3):
        store.enqueue_egress(GROUP, bytes([extra]) * 16, _first_hash(store))

    scheduler.tick()

    assert len(router.sent) == 1
    assert store.egress_depth() == 4


def test_item_stays_queued_until_delivery_callback(tmp_path, monkeypatch):
    scheduler, store, router, record = build(tmp_path, monkeypatch)

    scheduler.tick()

    assert len(router.sent) == 1
    assert store.egress_depth() == 1
    assert store.due_egress(10, now=2**31)[0].attempts == 1


def test_unknown_identity_defers_without_burning_an_attempt(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch, identity=None)

    scheduler.tick()

    assert router.sent == []
    assert store.due_egress(10, now=2**31)[0].attempts == 0


def test_delivery_for_pruned_message_is_dropped(tmp_path, monkeypatch):
    scheduler, store, router, record = build(tmp_path, monkeypatch)
    store.prune_messages(2000.0)

    scheduler.tick()

    assert router.sent == []
    assert store.egress_depth() == 0


def test_attempts_are_capped(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.max_attempts = 2
    scheduler, store, router, _record = build(tmp_path, monkeypatch, config=config)

    item = store.due_egress(1)[0]
    store.defer_egress(item.item_id, -1)
    store.defer_egress(item.item_id, -1)
    scheduler.tick()

    assert router.sent == []
    assert store.egress_depth() == 0


def test_propagation_is_preferred_when_a_node_is_configured(tmp_path, monkeypatch):
    router = StubRouter(propagation_node=b"\x05" * 16)
    scheduler, store, _router, _record = build(tmp_path, monkeypatch, router=router)

    scheduler.tick()

    assert router.sent[0].desired_method == LXMF.LXMessage.PROPAGATED


def test_direct_delivery_without_a_propagation_node(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch)

    scheduler.tick()

    assert router.sent[0].desired_method == LXMF.LXMessage.DIRECT


def test_backoff_grows_and_is_capped(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.retry_backoff_sec = 10
    config.egress.retry_backoff_max_sec = 50
    scheduler, _store, _router, _record = build(tmp_path, monkeypatch, config=config)

    assert scheduler._backoff(0) == 10
    assert scheduler._backoff(2) == 40
    assert scheduler._backoff(9) == 50


def _first_hash(store):
    return store.group_history(GROUP)[0].msg_hash


@pytest.fixture(autouse=True)
def clear_path_requests():
    requested.clear()
    yield
