"""Operator control channel tests.

The router is stubbed: ``ControlChannel`` only needs somewhere to hand replies,
and command execution goes straight to SQLite, so the whole authorisation and
command path runs without a live Reticulum instance.
"""

from types import SimpleNamespace

import pytest

from lxmf_hub.config import HubConfig
from lxmf_hub.control import ControlChannel
from lxmf_hub.store import ROLE_BANNED, Store

OPERATOR = bytes.fromhex("11111111111111111111111111111111")
OPERATOR_HEX = OPERATOR.hex()
INTRUDER = bytes.fromhex("22222222222222222222222222222222")
MEMBER = "33333333333333333333333333333333"
CONTROL_DESTINATION = bytes.fromhex("44444444444444444444444444444444")


class StubRouter:
    identity = object()

    def __init__(self):
        self.sent = []
        self.announced = []

    def register_delivery_identity(self, identity, display_name=None):
        return SimpleNamespace(hash=CONTROL_DESTINATION)

    def announce(self, destination_hash):
        self.announced.append(destination_hash)

    def get_outbound_propagation_node(self):
        return None


def make_channel(tmp_path, operators=OPERATOR_HEX):
    config = HubConfig(operator_identity=operators)
    store = Store(str(tmp_path / "hub.db"))
    channel = ControlChannel(config, store, StubRouter())
    channel.start()
    return channel, store


def command(text, source=OPERATOR, signed=True):
    return SimpleNamespace(
        destination_hash=CONTROL_DESTINATION,
        source_hash=source,
        content=text.encode("utf-8"),
        signature_validated=signed,
    )


def test_no_operators_means_no_control_destination(tmp_path):
    channel, _store = make_channel(tmp_path, operators=None)
    assert channel.destination is None
    assert channel.owns(CONTROL_DESTINATION) is False


def test_operators_can_create_a_group_and_add_a_member(tmp_path):
    channel, store = make_channel(tmp_path)

    created = channel.execute("create-group ops --acl public")
    assert created.startswith("ops\tpublic\t")
    assert store.get_group("ops") is not None

    assert channel.execute(f"add-member ops {MEMBER}").endswith("in ops")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) == "member"

    assert channel.execute("groups").startswith("ops\tpublic\t1 member(s)\t")


def test_roles_and_acl_changes_go_through(tmp_path):
    channel, store = make_channel(tmp_path)
    channel.execute("create-group ops")

    channel.execute(f"add-member ops {MEMBER} --role banned")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) == ROLE_BANNED

    assert channel.execute("set-acl ops public") == "ops is now public"
    assert store.get_group("ops").acl_mode == "public"

    channel.execute(f"remove-member ops {MEMBER}")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) is None


def test_status_reports_group_count_and_queue_depth(tmp_path):
    channel, _store = make_channel(tmp_path)
    channel.execute("create-group ops")
    assert channel.execute("status") == "groups\t1\negress_queue\t0"


@pytest.mark.parametrize(
    "text",
    ["run", "--config /etc/passwd status", "rm -rf /", "'unterminated"],
)
def test_commands_outside_the_allowlist_are_refused(tmp_path, text):
    channel, store = make_channel(tmp_path)
    reply = channel.execute(text)
    assert "Commands:" in reply or "Could not parse" in reply
    assert store.list_groups() == []


def test_bad_arguments_come_back_as_text_not_an_exit(tmp_path):
    channel, store = make_channel(tmp_path)
    assert "No such group" in channel.execute(f"add-member missing {MEMBER}")
    channel.execute("create-group ops")
    assert "not a hex destination hash" in channel.execute("add-member ops zzzz")
    assert "invalid choice" in channel.execute("set-acl ops sideways")
    assert channel.execute("create-group ops") == "Group 'ops' already exists"
    assert len(store.list_groups()) == 1


def test_non_operators_get_no_reply_and_change_nothing(tmp_path):
    channel, store = make_channel(tmp_path)
    replies = []
    channel.reply = lambda operator_hash, text: replies.append((operator_hash, text))

    channel.handle(command("create-group ops", source=INTRUDER))
    channel.handle(command("create-group ops", signed=False))

    assert replies == []
    assert store.list_groups() == []

    channel.handle(command("create-group ops"))
    assert len(replies) == 1
    assert replies[0][0] == OPERATOR
    assert store.get_group("ops") is not None


def test_several_operators_are_accepted(tmp_path):
    channel, _store = make_channel(tmp_path, operators=[OPERATOR_HEX, INTRUDER.hex()])
    assert channel.operators == [OPERATOR, INTRUDER]


def test_announces_are_rate_limited_to_the_configured_interval(tmp_path):
    channel, _store = make_channel(tmp_path)
    assert channel.announce_due() is True
    assert channel.announce_due() is False
    assert channel.router.announced == [CONTROL_DESTINATION]
