"""Directory tests.

``DirectoryChannel`` needs a live Reticulum instance to build a destination, so
the destination is stubbed out and the listing, the rate limit and the queued
reply are exercised directly. A reply is queued rather than sent, so most of
these assert against the notice queue.
"""

from types import SimpleNamespace

import LXMF
import RNS

from lxmf_hub.config import HubConfig
from lxmf_hub.destinations import group_destination_hash
from lxmf_hub.directory import DIRECTORY_GROUP, DirectoryChannel, load_directory_identity
from lxmf_hub.egress import EgressScheduler
from lxmf_hub.hub import GroupHub
from lxmf_hub.store import ACL_INVITE, ACL_PUBLIC, SOURCE_DIRECTORY, Store
from lxmf_hub.tickets import ScopedTickets
from tests.test_hub import StubDestinations

GROUP = "ops"
OTHER_GROUP = "weather"
PEER = b"\x0b" * 16
PEER_DESTINATION = bytes.fromhex("11223344556677889900aabbccddeeff")
REQUESTER = b"\xa1" * 16


class StubRouter:
    def __init__(self):
        self.sent = []
        self.pending_outbound = []
        self.announced = []
        self.available_tickets = {"outbound": {}, "inbound": {}, "last_deliveries": {}}

    def get_outbound_propagation_node(self):
        return None

    def handle_outbound(self, message):
        self.sent.append(message)

    def announce(self, destination_hash):
        self.announced.append(destination_hash)


def build(tmp_path, config=None, groups=((GROUP, ACL_INVITE),)):
    config = config or HubConfig()
    config.hub_name = "Example Hub"
    store = Store(str(tmp_path / "hub.db"))
    keys = {}
    for group_id, acl_mode in groups:
        keys[group_id] = RNS.Identity().get_private_key()
        store.create_group(group_id, group_id.title(), keys[group_id], acl_mode=acl_mode)
    router = StubRouter()
    channel = DirectoryChannel(config, store, router)
    channel.destination = SimpleNamespace(hash=b"\xdd" * 16)
    return channel, store, router, keys


def query(source=REQUESTER, signed=True):
    return SimpleNamespace(source_hash=source, signature_validated=signed, content=b"")


# -- listing -------------------------------------------------------------


def test_local_group_is_listed_with_the_address_a_client_would_use(tmp_path):
    channel, _store, _router, keys = build(tmp_path)

    line = channel.listing()

    assert line == (
        f"{GROUP} {ACL_INVITE} Example Hub {group_destination_hash(keys[GROUP]).hex()} here"
    )


def test_peer_endpoints_are_listed_with_their_age(tmp_path):
    channel, store, _router, _keys = build(tmp_path)
    store.record_peer_state(PEER, "Standby", {GROUP: (PEER_DESTINATION, ACL_INVITE)}, {GROUP: []})

    lines = channel.listing().splitlines()

    assert len(lines) == 2
    assert lines[1].startswith(f"{GROUP} {ACL_INVITE} Standby {PEER_DESTINATION.hex()} seen ")
    assert lines[1].endswith(" ago")


def test_a_peer_group_this_hub_does_not_host_is_not_invented(tmp_path):
    """The listing walks local groups, so a peer-only group stays out of it."""
    channel, store, _router, _keys = build(tmp_path)
    store.record_peer_state(
        PEER, "Standby", {"elsewhere": (PEER_DESTINATION, ACL_PUBLIC)}, {"elsewhere": []}
    )

    assert "elsewhere" not in channel.listing()


def test_every_group_is_listed(tmp_path):
    channel, _store, _router, _keys = build(
        tmp_path, groups=((GROUP, ACL_INVITE), (OTHER_GROUP, ACL_PUBLIC))
    )

    lines = channel.listing().splitlines()

    assert {line.split()[0] for line in lines} == {GROUP, OTHER_GROUP}
    assert f" {ACL_PUBLIC} " in channel.listing()


def test_a_hub_with_no_groups_says_so(tmp_path):
    channel, _store, _router, _keys = build(tmp_path, groups=())

    assert channel.listing() == "This hub hosts no groups."


# -- inbound -------------------------------------------------------------


def test_a_query_is_queued_for_the_requester(tmp_path):
    channel, store, _router, _keys = build(tmp_path)

    channel.handle(query())

    queued = store.due_notices(10, now=2**31)
    assert len(queued) == 1
    assert queued[0].recipient_hash == REQUESTER
    assert queued[0].source == SOURCE_DIRECTORY
    assert queued[0].group_id == DIRECTORY_GROUP
    assert queued[0].body.startswith(GROUP)


def test_an_unsigned_query_is_dropped(tmp_path):
    channel, store, _router, _keys = build(tmp_path)

    channel.handle(query(signed=False))

    assert store.notice_depth() == 0


def test_repeat_queries_are_rate_limited_per_requester(tmp_path):
    channel, store, _router, _keys = build(tmp_path)

    channel.handle(query())
    channel.handle(query())
    channel.handle(query(source=b"\xa2" * 16))

    assert store.notice_depth() == 2


def test_the_rate_limit_expires(tmp_path):
    """A second answer with the same text is still deduplicated by the queue."""
    config = HubConfig()
    config.directory.min_reply_interval_sec = 0.0
    channel, store, _router, _keys = build(tmp_path, config=config)

    channel.handle(query())
    for item in store.due_notices(10):
        store.complete_notice(item.item_id)
    channel.handle(query())

    assert store.notice_depth() == 1


# -- outbound ------------------------------------------------------------


def test_a_queued_answer_is_sent_from_the_directory_destination(tmp_path, monkeypatch):
    channel, store, router, _keys = build(tmp_path)
    _stub_outbound(monkeypatch)
    scheduler = _scheduler(channel, store, router)
    channel.handle(query())

    scheduler.tick()

    assert len(router.sent) == 1
    assert router.sent[0].source is channel.destination
    assert router.sent[0].content.decode("utf-8").startswith(GROUP)


def test_a_queued_answer_is_paced_with_reflections(tmp_path, monkeypatch):
    config = HubConfig()
    config.egress.tokens_per_second = 0.0
    config.egress.burst = 1
    channel, store, router, _keys = build(tmp_path, config=config)
    _stub_outbound(monkeypatch)
    scheduler = _scheduler(channel, store, router)
    channel.handle(query())
    channel.handle(query(source=b"\xa2" * 16))

    scheduler.tick()

    assert len(router.sent) == 1
    assert store.notice_depth() == 2


def test_a_requester_with_no_known_identity_is_not_answered_yet(tmp_path, monkeypatch):
    channel, store, router, _keys = build(tmp_path)
    requested = []
    monkeypatch.setattr("RNS.Identity.recall", staticmethod(lambda _hash: None))
    monkeypatch.setattr("RNS.Transport.has_path", staticmethod(lambda _hash: False))
    monkeypatch.setattr(
        "RNS.Transport.request_path", staticmethod(lambda hash_: requested.append(hash_))
    )
    scheduler = _scheduler(channel, store, router)
    channel.handle(query())

    scheduler.tick()

    assert router.sent == []
    assert requested == [REQUESTER]
    assert store.due_notices(10, now=2**31)[0].attempts == 0


# -- lifecycle -----------------------------------------------------------


def test_the_directory_identity_is_reused_across_restarts(tmp_path):
    path = str(tmp_path / "directory_identity")

    first = load_directory_identity(path)
    second = load_directory_identity(path)

    assert first.get_private_key() == second.get_private_key()


def test_the_directory_is_off_when_disabled(tmp_path):
    config = HubConfig()
    config.directory.enabled = False
    channel, _store, _router, _keys = build(tmp_path, config=config)
    channel.destination = None

    assert channel.start() is None
    assert not channel.owns(b"\xdd" * 16)


def test_only_the_directory_destination_is_claimed(tmp_path):
    channel, _store, _router, _keys = build(tmp_path)

    assert channel.owns(b"\xdd" * 16)
    assert not channel.owns(b"\xee" * 16)


def test_announces_are_spaced_by_the_configured_interval(tmp_path):
    channel, _store, router, _keys = build(tmp_path)

    assert channel.announce_due()
    assert not channel.announce_due()
    assert router.announced == [b"\xdd" * 16]


class FakeDestination:
    OUT = 1
    SINGLE = 2
    # Patching the name in the directory module patches it for every module that
    # imported RNS, so the real hash function has to stay reachable.
    hash = staticmethod(RNS.Destination.hash)

    def __init__(self, *args, **kwargs):
        self.args = args


class FakeMessage:
    DIRECT = LXMF.LXMessage.DIRECT
    PROPAGATED = LXMF.LXMessage.PROPAGATED

    def __init__(self, destination, source, content=b"", title=b"", desired_method=None):
        self.destination = destination
        self.source = source
        self.destination_hash = getattr(destination, "hash", b"\x00" * 16)
        self.source_hash = getattr(source, "hash", b"\x00" * 16)
        self.content = content
        self.desired_method = desired_method
        self.method = LXMF.LXMessage.DIRECT
        self.delivered = None

    def register_delivery_callback(self, callback):
        self.delivered = callback

    def register_failed_callback(self, callback):
        pass


def _scheduler(channel, store, router):
    hub = GroupHub(channel.config, store, router=None, destinations=StubDestinations({}))
    return EgressScheduler(
        channel.config, store, hub, router, StubDestinations({}), ScopedTickets(), directory=channel
    )


def _stub_outbound(monkeypatch):
    """Replace only the two RNS/LXMF constructors that need a live instance."""
    monkeypatch.setattr("RNS.Identity.recall", staticmethod(lambda _hash: SimpleNamespace()))
    monkeypatch.setattr("lxmf_hub.directory.RNS.Destination", FakeDestination)
    monkeypatch.setattr("lxmf_hub.directory.LXMF.LXMessage", FakeMessage)


class StartDestination:
    """Stands in for the destination ``start`` builds, which needs a live RNS."""

    IN = 0
    SINGLE = 2
    hexrep = staticmethod(RNS.hexrep)

    def __init__(self, identity, direction, destination_type, app_name, aspect):
        self.identity = identity
        self.direction = direction
        self.hash = b"\xdd" * 16
        self.ratchet_path = None
        self.packet_callback = None
        self.link_callback = None
        self.app_data = None

    def enable_ratchets(self, path):
        self.ratchet_path = path

    def set_packet_callback(self, callback):
        self.packet_callback = callback

    def set_link_established_callback(self, callback):
        self.link_callback = callback

    def set_default_app_data(self, callable_or_data):
        self.app_data = callable_or_data


class RegisteringRouter(StubRouter):
    def __init__(self, ratchetpath):
        super().__init__()
        self.ratchetpath = ratchetpath
        self.delivery_destinations = {}

    def delivery_packet(self, *args):
        pass

    def delivery_link_established(self, *args):
        pass

    def get_announce_app_data(self, destination_hash):
        return b""


def test_the_directory_destination_carries_what_lxmf_reads_on_delivery(tmp_path, monkeypatch):
    """LXMF reads ``destination.stamp_cost`` for every inbound message.

    ``register_delivery_identity`` sets it, and the directory cannot use that
    call because the router allows one delivery identity and the control channel
    holds it. Without the attribute, an inbound query raises inside LXMF.
    """
    config = HubConfig()
    config.storage_path = str(tmp_path)
    store = Store(str(tmp_path / "hub.db"))
    router = RegisteringRouter(str(tmp_path / "ratchets"))
    monkeypatch.setattr("lxmf_hub.directory.RNS.Destination", StartDestination)

    destination = DirectoryChannel(config, store, router).start()

    assert destination is not None
    assert destination.stamp_cost is None
    assert destination.ratchet_path is not None
    assert router.delivery_destinations[destination.hash] is destination
