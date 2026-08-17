"""Peer liveness, adoption and notice tests.

``FailoverEngine`` reads peer state out of SQLite and writes notices back into
it, so the whole state machine can be driven by writing peer state and moving
the clock, with no Reticulum instance and no links involved.
"""

from types import SimpleNamespace

import pytest

from lxmf_hub.config import HubConfig
from lxmf_hub.failover import FLAG_ISOLATED, FailoverEngine, format_age
from lxmf_hub.hub import GroupHub, pack_payload
from lxmf_hub.store import ACL_INVITE, ROLE_BANNED, MessageRecord, Store, message_hash
from tests.test_hub import GROUP, GROUP_DESTINATION, StubDestinations, inbound

PEER = b"\x0b" * 16
OTHER_PEER = b"\x0c" * 16
PEER_DESTINATION = bytes.fromhex("11223344556677889900aabbccddeeff")
LOCAL_MEMBER = b"\xa1" * 16
REMOTE_MEMBER = b"\xb0" * 16
SECOND_REMOTE = b"\xb1" * 16


def build(tmp_path, peers=(PEER,), config=None, notify_isolation=False):
    config = config or HubConfig()
    config.hub_name = "Standby"
    config.federation.peers = [peer.hex() for peer in peers]
    # Losing the only peer is also isolation, so the adoption tests silence that
    # notice to keep the two audiences apart. The isolation tests turn it back on.
    config.failover.notify_isolation = notify_isolation

    store = Store(str(tmp_path / "hub.db"))
    store.create_group(GROUP, "Ops", b"\x00" * 64, acl_mode=ACL_INVITE)
    store.add_member(GROUP, LOCAL_MEMBER)
    destinations = StubDestinations({GROUP_DESTINATION: GROUP})
    hub = GroupHub(config, store, router=None, destinations=destinations)
    engine = FailoverEngine(config, store, hub)
    return engine, store


def answered(store, at, peer=PEER):
    """Record the evidence a real sync round leaves behind when a peer replies."""
    store.record_peer_success(peer, now=at)


def gossip(store, peer=PEER, members=(REMOTE_MEMBER,), groups=(GROUP,), hub_name="Home"):
    store.record_peer_state(
        peer,
        hub_name,
        {group_id: (PEER_DESTINATION, ACL_INVITE) for group_id in groups},
        {group_id: list(members) for group_id in groups},
    )


def bodies(store):
    return [notice.body for notice in store.due_notices(50, now=2**31)]


# -- liveness ------------------------------------------------------------


def test_a_peer_never_reached_is_measured_from_startup(tmp_path):
    engine, _store = build(tmp_path)

    assert engine.stale_peers(now=engine.started_at + 10) == []
    assert engine.stale_peers(now=engine.started_at + 1801) == [PEER]


def test_a_recent_answer_keeps_a_peer_live(tmp_path):
    engine, store = build(tmp_path)
    answered(store, engine.started_at + 1000)

    assert engine.stale_peers(now=engine.started_at + 1500) == []


def test_a_failed_sync_round_still_counts_as_silence(tmp_path):
    """A hub records every attempt, so only an answer may refresh liveness.

    Otherwise the sync round a hub runs against a dead peer would keep marking it
    alive and nothing would ever fail over.
    """
    engine, store = build(tmp_path)
    for round_at in range(0, 2000, 300):
        store.record_peer_sync(PEER, "link could not be established")
        assert store.peer_last_success(PEER) is None, round_at

    assert engine.stale_peers(now=engine.started_at + 1801) == [PEER]


def test_checks_are_throttled_to_the_interval(tmp_path):
    engine, _store = build(tmp_path)

    assert engine.check_due(now=1000.0)
    assert not engine.check_due(now=1030.0)
    assert engine.check_due(now=1100.0)


# -- adoption ------------------------------------------------------------


def test_stale_peer_members_are_adopted_and_notified(tmp_path):
    engine, store = build(tmp_path)
    gossip(store, members=(REMOTE_MEMBER, SECOND_REMOTE))

    engine.check(now=engine.started_at + 1801)

    assert set(store.list_adopted(GROUP)) == {REMOTE_MEMBER, SECOND_REMOTE}
    notice = bodies(store)
    assert len(notice) == 2
    assert GROUP_DESTINATION.hex() in notice[0]
    assert "Home" in notice[0]


def test_adoption_does_not_renotify_on_every_check(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)

    engine.check(now=engine.started_at + 1801)
    for item in store.due_notices(50, now=2**31):
        store.complete_notice(item.item_id)
    engine.check(now=engine.started_at + 1900)

    assert store.notice_depth() == 0
    assert store.list_adopted(GROUP) == [REMOTE_MEMBER]


def test_groups_this_hub_does_not_host_are_not_adopted(tmp_path):
    engine, store = build(tmp_path)
    gossip(store, groups=("elsewhere",))

    engine.check(now=engine.started_at + 1801)

    assert store.list_adopted("elsewhere") == []
    assert store.notice_depth() == 0


def test_a_local_member_is_not_adopted_or_notified(tmp_path):
    engine, store = build(tmp_path)
    gossip(store, members=(LOCAL_MEMBER,))

    engine.check(now=engine.started_at + 1801)

    assert store.list_adopted(GROUP) == []
    assert store.notice_depth() == 0


def test_notices_can_be_turned_off_while_adoption_still_happens(tmp_path):
    config = HubConfig()
    config.failover.notify_clients = False
    engine, store = build(tmp_path, config=config)
    gossip(store)

    engine.check(now=engine.started_at + 1801)

    assert store.list_adopted(GROUP) == [REMOTE_MEMBER]
    assert store.notice_depth() == 0


# -- hand-back -----------------------------------------------------------


def test_recovered_peer_is_handed_back_with_its_address(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)
    engine.check(now=engine.started_at + 1801)
    for item in store.due_notices(50, now=2**31):
        store.complete_notice(item.item_id)

    answered(store, engine.started_at + 1900)
    engine.check(now=engine.started_at + 1950)

    assert store.list_adopted(GROUP) == []
    notice = bodies(store)
    assert len(notice) == 1
    assert PEER_DESTINATION.hex() in notice[0]


def test_hand_back_happens_once(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)
    engine.check(now=engine.started_at + 1801)
    answered(store, engine.started_at + 1900)

    assert engine.release(PEER) == 1
    assert engine.release(PEER) == 0


def restarted(engine, store, at):
    """A second engine over the same database, as a restart of the daemon is."""
    fresh = FailoverEngine(engine.config, store, engine.hub)
    fresh.started_at = at
    return fresh


def test_a_restart_mid_outage_neither_hands_back_nor_re_notifies(tmp_path):
    """A restart is evidence about this hub, not about the peer.

    The peer's last answer is older than the timeout and stays that way, so
    measuring from a fresh startup would read a long-dead peer as freshly alive,
    release the adoption and send a hand-back naming an address still down.
    """
    engine, store = build(tmp_path, notify_isolation=True)
    gossip(store)
    answered(store, engine.started_at)
    engine.check(now=engine.started_at + 1801)
    for item in store.due_notices(50, now=2**31):
        store.complete_notice(item.item_id)
    assert store.list_adopted(GROUP) == [REMOTE_MEMBER]

    after = restarted(engine, store, engine.started_at + 1900)
    after.check(now=after.started_at + 10)

    assert store.list_adopted(GROUP) == [REMOTE_MEMBER]
    assert store.get_flag(FLAG_ISOLATED)
    assert bodies(store) == []


def test_a_peer_that_answers_after_a_restart_is_still_handed_back(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)
    engine.check(now=engine.started_at + 1801)
    for item in store.due_notices(50, now=2**31):
        store.complete_notice(item.item_id)

    after = restarted(engine, store, engine.started_at + 1900)
    answered(store, after.started_at + 10)
    after.check(now=after.started_at + 20)

    assert store.list_adopted(GROUP) == []
    assert len(bodies(store)) == 1


def test_a_peer_still_silent_after_the_restart_window_is_stale_again(tmp_path):
    engine, store = build(tmp_path)
    answered(store, engine.started_at)

    after = restarted(engine, store, engine.started_at + 1900)

    assert after.stale_peers(now=after.started_at + 10) == []
    assert after.stale_peers(now=after.started_at + 1801) == [PEER]


# -- isolation -----------------------------------------------------------


def test_isolation_notifies_local_members_once_per_transition(tmp_path):
    engine, store = build(tmp_path, notify_isolation=True)

    assert engine.check_isolation({PEER})
    assert store.get_flag(FLAG_ISOLATED)
    assert not engine.check_isolation({PEER})

    notice = bodies(store)
    assert len(notice) == 1
    assert "cannot reach any peer hub" in notice[0]


def test_one_live_peer_is_not_isolation(tmp_path):
    engine, store = build(tmp_path, peers=(PEER, OTHER_PEER), notify_isolation=True)

    assert not engine.check_isolation({PEER})
    assert not store.get_flag(FLAG_ISOLATED)
    assert store.notice_depth() == 0


def test_recovery_from_isolation_notifies_again(tmp_path):
    engine, store = build(tmp_path, notify_isolation=True)
    engine.check_isolation({PEER})
    for item in store.due_notices(50, now=2**31):
        store.complete_notice(item.item_id)

    assert engine.check_isolation(set())
    assert not store.get_flag(FLAG_ISOLATED)
    assert "back in contact" in bodies(store)[0]


def test_isolation_notice_lists_the_other_hubs(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)

    body = engine.isolation_notice(GROUP)

    assert PEER_DESTINATION.hex() in body
    assert "Home" in body


def test_a_hub_without_peers_is_never_isolated(tmp_path):
    engine, store = build(tmp_path, peers=(), notify_isolation=True)

    assert not engine.check_isolation(set())
    assert store.notice_depth() == 0


# -- effect on message handling ------------------------------------------


def test_an_adopted_member_receives_reflections(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)
    engine.check(now=engine.started_at + 1801)

    engine.hub.handle_inbound(inbound(source=LOCAL_MEMBER))

    recipients = {item.recipient_hash for item in store.due_egress(10)}
    assert recipients == {REMOTE_MEMBER}


def test_a_peer_member_may_post_to_the_standby(tmp_path):
    """The standby's address is useless to an invited member it cannot verify."""
    engine, store = build(tmp_path)
    gossip(store)

    engine.hub.handle_inbound(inbound(source=REMOTE_MEMBER))

    assert len(store.group_history(GROUP)) == 1


def test_a_banned_member_stays_banned_when_gossiped_as_a_peer_member(tmp_path):
    engine, store = build(tmp_path)
    store.add_member(GROUP, REMOTE_MEMBER, ROLE_BANNED)
    gossip(store)

    engine.hub.handle_inbound(inbound(source=REMOTE_MEMBER))

    assert store.group_history(GROUP) == []


def test_a_banned_member_is_not_adopted_from_a_stale_peer(tmp_path):
    """A local ban outranks a peer's member list, however the member arrives."""
    engine, store = build(tmp_path)
    store.add_member(GROUP, REMOTE_MEMBER, ROLE_BANNED)
    gossip(store)

    engine.check(now=engine.started_at + 1801)

    assert store.list_adopted(GROUP) == []


def test_a_banned_member_receives_no_reflections_after_an_adoption(tmp_path):
    engine, store = build(tmp_path)
    gossip(store, members=(REMOTE_MEMBER, SECOND_REMOTE))
    engine.check(now=engine.started_at + 1801)
    store.add_member(GROUP, REMOTE_MEMBER, ROLE_BANNED)

    engine.hub.handle_inbound(inbound(source=LOCAL_MEMBER))

    recipients = {item.recipient_hash for item in store.due_egress(10)}
    assert recipients == {SECOND_REMOTE}


def test_removing_a_member_on_the_peer_withdraws_it_here(tmp_path):
    engine, store = build(tmp_path)
    gossip(store, members=(REMOTE_MEMBER, SECOND_REMOTE))
    gossip(store, members=(REMOTE_MEMBER,))

    assert store.is_peer_member(GROUP, REMOTE_MEMBER)
    assert not store.is_peer_member(GROUP, SECOND_REMOTE)


# -- text ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(5.0, "5s"), (119.0, "119s"), (600.0, "10m"), (7200.0, "2h"), (1800.0, "30m")],
)
def test_ages_read_as_durations(seconds, expected):
    assert format_age(seconds) == expected


def test_an_unattached_group_reports_an_unknown_endpoint(tmp_path):
    engine, _store = build(tmp_path)

    assert engine.local_endpoint("missing") == "unknown"


def test_a_peer_with_no_gossip_yet_is_named_by_hash(tmp_path):
    engine, _store = build(tmp_path)

    assert PEER.hex()[:4] in engine.peer_name(PEER).replace(":", "")


def _seed_message(store):
    payload = pack_payload(1000.0, b"", b"hello", {})
    record = MessageRecord(
        msg_hash=message_hash(GROUP, LOCAL_MEMBER, 1000.0, payload),
        group_id=GROUP,
        sender_hash=LOCAL_MEMBER,
        timestamp=1000.0,
        payload=payload,
    )
    store.store_message(record)
    return record


def test_notices_survive_a_restart(tmp_path):
    engine, store = build(tmp_path)
    gossip(store)
    engine.check(now=engine.started_at + 1801)
    _seed_message(store)

    reopened = Store(str(tmp_path / "hub.db"))

    assert len(reopened.due_notices(10, now=2**31)) == 1
    assert reopened.list_adopted(GROUP) == [REMOTE_MEMBER]


def test_stats_report_the_notice_queue(tmp_path):
    engine, store = build(tmp_path)
    store.enqueue_notice(GROUP, REMOTE_MEMBER, "text")

    assert "notice_queue=1" in engine.hub.stats()


def test_identical_notices_are_not_queued_twice(tmp_path):
    _engine, store = build(tmp_path)

    assert store.enqueue_notice(GROUP, REMOTE_MEMBER, "text")
    assert not store.enqueue_notice(GROUP, REMOTE_MEMBER, "text")


def test_a_deferred_notice_is_not_immediately_due(tmp_path):
    _engine, store = build(tmp_path)
    store.enqueue_notice(GROUP, REMOTE_MEMBER, "text")
    item = store.due_notices(1)[0]

    store.defer_notice(item.item_id, 600.0)

    assert store.due_notices(1) == []
    assert store.due_notices(1, now=2**31)[0].attempts == 1


def test_deferring_for_a_path_does_not_burn_an_attempt(tmp_path):
    _engine, store = build(tmp_path)
    store.enqueue_notice(GROUP, REMOTE_MEMBER, "text")
    item = store.due_notices(1)[0]

    store.defer_notice(item.item_id, -1.0, count_attempt=False)

    assert store.due_notices(1)[0].attempts == 0


def test_hub_authored_notice_carries_no_author_field(tmp_path, monkeypatch):
    engine, _store = build(tmp_path)
    built = {}

    class FakeDestination:
        OUT = 1
        SINGLE = 2

        def __init__(self, *args, **kwargs):
            built["args"] = args

    class FakeMessage:
        def __init__(self, destination, source, content=b"", title=b"", **kwargs):
            built["content"] = content
            built["fields"] = kwargs.get("fields")

    monkeypatch.setattr("RNS.Destination", FakeDestination)
    monkeypatch.setattr("LXMF.LXMessage", FakeMessage)

    engine.hub.build_notice(GROUP, SimpleNamespace(), "hub speaking")

    assert built["content"] == b"hub speaking"
    assert built["fields"] is None


def test_a_notice_for_an_unattached_group_is_refused(tmp_path):
    engine, _store = build(tmp_path)

    with pytest.raises(ValueError):
        engine.hub.build_notice("missing", SimpleNamespace(), "text")
