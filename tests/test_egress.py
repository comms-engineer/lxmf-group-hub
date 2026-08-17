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
        self.pending_outbound = []
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
            method=LXMF.LXMessage.DIRECT,
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


def test_a_notice_goes_out_before_queued_reflections(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.tokens_per_second = 0.0
    config.egress.burst = 1
    scheduler, store, router, _record = build(tmp_path, monkeypatch, config=config)
    store.enqueue_notice(GROUP, MEMBER, "your hub moved")
    monkeypatch.setattr(
        scheduler.hub, "build_notice", lambda group_id, identity, body: _stub_message()
    )

    scheduler.tick()

    assert len(router.sent) == 1
    assert store.egress_depth() == 1
    assert store.notice_depth() == 1


def test_a_notice_stays_queued_until_it_is_delivered(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch)
    store.enqueue_notice(GROUP, MEMBER, "your hub moved")
    sent = _stub_message()
    monkeypatch.setattr(scheduler.hub, "build_notice", lambda group_id, identity, body: sent)

    scheduler.tick()

    assert store.notice_depth() == 1
    sent.delivered(sent)
    assert store.notice_depth() == 0


def test_a_notice_for_an_unknown_identity_waits_for_a_path(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch, identity=None)
    store.enqueue_notice(GROUP, MEMBER, "your hub moved")

    scheduler.tick()

    assert router.sent == []
    assert store.due_notices(10, now=2**31)[0].attempts == 0


def test_a_row_in_flight_is_not_sent_twice(tmp_path, monkeypatch):
    """LXMF may take longer to deliver than the row's backoff."""
    scheduler, store, router, _record = build(tmp_path, monkeypatch)

    scheduler.tick()
    _due_now(store, store.due_egress(10, now=2**31)[0].item_id)
    scheduler.tick()

    assert len(router.sent) == 1


def test_a_row_is_retried_once_the_router_has_dropped_the_message(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch)
    scheduler.config.egress.delivery_timeout_sec = -1

    scheduler.tick()
    _due_now(store, store.due_egress(10, now=2**31)[0].item_id)
    scheduler.tick()

    assert len(router.sent) == 2


def test_a_row_the_router_still_holds_is_not_resent_after_the_timeout(tmp_path, monkeypatch):
    """A slow delivery is not a lost one, and a duplicate cannot be recalled."""
    router = StubRouter()
    # Sending appends to both, so LXMF "still holds" every message it was given.
    router.pending_outbound = router.sent
    scheduler, store, _router, _record = build(tmp_path, monkeypatch, router=router)
    scheduler.config.egress.delivery_timeout_sec = -1

    scheduler.tick()
    _due_now(store, store.due_egress(10, now=2**31)[0].item_id)
    scheduler.tick()

    assert len(router.sent) == 1


def test_a_delivered_row_is_completed_and_no_longer_in_flight(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch)
    sent = _stub_message()
    monkeypatch.setattr(scheduler.hub, "build_reflection", lambda record, identity: sent)

    scheduler.tick()
    sent.delivered(sent)

    assert store.egress_depth() == 0
    assert scheduler._inflight == {}


def test_a_failed_row_is_released_so_the_backoff_retries_it(tmp_path, monkeypatch):
    scheduler, store, router, _record = build(tmp_path, monkeypatch)
    sent = _stub_message()
    monkeypatch.setattr(scheduler.hub, "build_reflection", lambda record, identity: sent)

    scheduler.tick()
    sent.failed(sent)
    _due_now(store, store.due_egress(10, now=2**31)[0].item_id)
    scheduler.tick()

    assert len(router.sent) == 2
    assert store.egress_depth() == 1


def test_an_outbound_exception_leaves_the_row_queued_and_retriable(tmp_path, monkeypatch):
    """handle_outbound raising means neither callback will ever fire."""
    scheduler, store, router, _record = build(tmp_path, monkeypatch)
    monkeypatch.setattr(
        router, "handle_outbound", lambda message: (_ for _ in ()).throw(OSError("no interface"))
    )

    scheduler.tick()

    assert store.egress_depth() == 1
    assert scheduler._inflight == {}


def test_a_row_that_cannot_be_sent_gives_its_token_back(tmp_path, monkeypatch):
    """A detached group must not stall the deliverable rows behind it."""
    config = HubConfig()
    config.egress.tokens_per_second = 0.0
    config.egress.burst = 1
    scheduler, store, router, record = build(tmp_path, monkeypatch, config=config)
    store.enqueue_egress("ghost", b"\xc0" * 16, record.msg_hash)
    ghost = [item for item in store.due_egress(10) if item.group_id == "ghost"][0]
    store.defer_egress(ghost.item_id, -1_000, count_attempt=False)

    scheduler.tick()

    assert len(router.sent) == 1


def test_the_wait_after_a_path_request_grows_with_each_grace(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.path_request_grace_sec = 10
    config.egress.retry_backoff_max_sec = 100
    scheduler, _store, _router, _record = build(tmp_path, monkeypatch, config=config)

    assert scheduler._grace(0) == 10
    assert scheduler._grace(2) == 40
    assert scheduler._grace(9) == 100


def test_repeated_path_requests_count_graces_not_attempts(tmp_path, monkeypatch):
    scheduler, store, _router, _record = build(tmp_path, monkeypatch, identity=None)

    scheduler.tick()
    _due_now(store, store.due_egress(10, now=2**31)[0].item_id)
    scheduler.tick()

    item = store.due_egress(10, now=2**31)[0]
    assert item.attempts == 0
    assert item.graces == 3


def test_an_operator_answer_goes_out_before_client_traffic(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.tokens_per_second = 0.0
    config.egress.burst = 1
    control = StubControl()
    scheduler, store, router, _record = build(tmp_path, monkeypatch, config=config)
    scheduler.control = control
    store.enqueue_control(MEMBER, "groups\t1")
    scheduler.bucket.consume()

    scheduler.tick()

    # The bucket is empty, so the reflection has to wait -- and the answer to an
    # operator, which is not paced, does not.
    assert control.built == ["groups\t1"]
    assert len(router.sent) == 1
    assert store.egress_depth() == 1


def test_an_operator_answer_stays_queued_until_it_is_delivered(tmp_path, monkeypatch):
    control = StubControl()
    scheduler, store, router, _record = build(tmp_path, monkeypatch)
    scheduler.control = control
    store.enqueue_control(MEMBER, "done")

    scheduler.tick()
    assert store.control_depth() == 1

    sent = router.sent[0]
    sent.delivered(sent)
    assert store.control_depth() == 0


def test_an_undeliverable_operator_answer_is_retried_then_dropped(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.max_attempts = 2
    control = StubControl()
    scheduler, store, _router, _record = build(tmp_path, monkeypatch, config=config)
    scheduler.control = control
    store.enqueue_control(MEMBER, "done")

    reply = store.due_control(1)[0]
    store.defer_control(reply.item_id, -1)
    store.defer_control(reply.item_id, -1)
    scheduler.tick()

    assert store.control_depth() == 0


def test_an_answer_queued_without_a_control_channel_is_dropped(tmp_path, monkeypatch):
    """Operators were removed from the config while an answer was queued."""
    scheduler, store, _router, _record = build(tmp_path, monkeypatch)
    store.enqueue_control(MEMBER, "done")

    scheduler.tick()

    assert store.control_depth() == 0


def test_notice_attempts_are_capped(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.max_attempts = 2
    scheduler, store, router, _record = build(tmp_path, monkeypatch, config=config)
    store.enqueue_notice(GROUP, MEMBER, "your hub moved")

    item = store.due_notices(1)[0]
    store.defer_notice(item.item_id, -1)
    store.defer_notice(item.item_id, -1)
    scheduler.tick()

    assert store.notice_depth() == 0


class StubMessage:
    """Enough of LXMessage for the scheduler: a method slot and two callbacks."""

    def __init__(self):
        self.desired_method = None
        self.method = LXMF.LXMessage.DIRECT
        self.delivered = None
        self.failed = None

    def register_delivery_callback(self, callback):
        self.delivered = callback

    def register_failed_callback(self, callback):
        self.failed = callback


class StubControl:
    """Stands in for ControlChannel: the scheduler only builds replies with it."""

    def __init__(self):
        self.built = []

    def build_reply(self, identity, body):
        message = StubMessage()
        self.built.append(body)
        return message


def _stub_message():
    return StubMessage()


def _due_now(store, item_id):
    """Make a re-armed row due again without counting an attempt."""
    store.defer_egress(item_id, -1_000, count_attempt=False)


def _first_hash(store):
    return store.group_history(GROUP)[0].msg_hash


@pytest.fixture(autouse=True)
def clear_path_requests():
    requested.clear()
    yield
