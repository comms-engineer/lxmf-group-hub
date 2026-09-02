"""Operator control channel tests.

The router is stubbed: ``ControlChannel`` only needs somewhere to hand replies,
and command execution goes straight to SQLite, so the whole authorisation and
command path runs without a live Reticulum instance.
"""

from types import SimpleNamespace

import pytest

from lxmf_hub.aliases import PUBLIC_ALIASES
from lxmf_hub.config import HubConfig
from lxmf_hub.control import MAX_COMMAND_BYTES, REMOTE_COMMANDS, ControlChannel
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

    created = channel.execute("/create-group ops --acl public")
    assert created.startswith("ops\tpublic\t")
    assert store.get_group("ops").display_name in PUBLIC_ALIASES

    assert channel.execute(f"/add-member ops {MEMBER}").endswith("in ops")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) == "member"

    assert channel.execute("/groups").startswith("ops\tpublic\t1 member(s)\t")


def test_group_aliases_are_unique_and_explicit_names_remain_supported(tmp_path):
    channel, store = make_channel(tmp_path)

    channel.execute("/create-group ops")
    channel.execute("/create-group weather")
    channel.execute('/create-group nets --name "Mission Nets"')

    aliases = {group.display_name for group in store.list_groups()}
    assert len(aliases) == 3
    assert store.get_group("nets").display_name == "Mission Nets"


def test_roles_and_acl_changes_go_through(tmp_path):
    channel, store = make_channel(tmp_path)
    channel.execute("/create-group ops")

    channel.execute(f"/add-member ops {MEMBER} --role banned")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) == ROLE_BANNED

    assert channel.execute("/set-acl ops public") == "ops is now public"
    assert store.get_group("ops").acl_mode == "public"

    channel.execute(f"/remove-member ops {MEMBER}")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) is None


def test_deleting_a_group_removes_its_members(tmp_path):
    channel, store = make_channel(tmp_path)
    channel.execute("/create-group ops")
    channel.execute(f"/add-member ops {MEMBER}")

    assert channel.execute("/delete-group ops") == "ops deleted"
    assert store.get_group("ops") is None
    assert store.list_members("ops", include_banned=True) == []
    assert "No such group" in channel.execute("/delete-group ops")


def test_status_reports_group_count_and_queue_depth(tmp_path):
    channel, _store = make_channel(tmp_path)
    channel.execute("/create-group ops")
    assert channel.execute("/status") == (
        "groups\t1\negress_queue\t0\nnotice_queue\t0\ncontrol_queue\t0"
    )


def test_an_answer_is_queued_so_it_survives_an_unknown_path(tmp_path):
    """The command already changed the database; the answer cannot be dropped."""
    channel, store = make_channel(tmp_path)

    channel.handle(command("/create-group ops"))

    assert store.control_depth() == 1
    queued = store.due_control(10)[0]
    assert queued.recipient_hash == OPERATOR
    assert queued.body.startswith("ops\t")


def test_identical_answers_are_both_queued(tmp_path):
    """Two commands are two answers, unlike deduplicated client notices."""
    channel, store = make_channel(tmp_path)

    channel.handle(command("/status"))
    channel.handle(command("/status"))

    assert store.control_depth() == 2


def test_a_verb_is_recognised_whatever_the_keyboard_capitalised(tmp_path):
    channel, store = make_channel(tmp_path)

    assert channel.execute("/Create-Group ops").startswith("ops\t")
    assert store.get_group("ops") is not None


def test_a_hash_is_accepted_in_the_forms_a_client_displays(tmp_path):
    channel, store = make_channel(tmp_path)
    channel.execute("/create-group ops")
    grouped = ":".join(MEMBER[index : index + 2] for index in range(0, len(MEMBER), 2))

    assert channel.execute(f"/add-member ops <{MEMBER}>").startswith(MEMBER)
    assert store.get_role("ops", bytes.fromhex(MEMBER)) == "member"

    channel.execute(f"/remove-member ops {grouped}")
    assert store.get_role("ops", bytes.fromhex(MEMBER)) is None


def test_a_truncated_hash_is_refused_rather_than_stored(tmp_path):
    """bytes.fromhex accepts a short hash; nothing would ever match it."""
    channel, store = make_channel(tmp_path)
    channel.execute("/create-group ops")

    reply = channel.execute("/add-member ops 3333")

    assert "delivery destination" in reply and "16" in reply
    assert store.list_members("ops", include_banned=True) == []


def test_help_lists_the_usage_of_every_remote_command(tmp_path):
    channel, _store = make_channel(tmp_path)

    listing = channel.execute("/help")

    assert "add-member [--role {member,admin,banned}] group_id user_hash" in listing
    for verb in REMOTE_COMMANDS:
        assert verb in listing
    # "run" is a CLI-only verb and must not be advertised to an operator.
    assert "  /run" not in listing.splitlines()


def test_help_for_one_command_quotes_its_arguments(tmp_path):
    channel, _store = make_channel(tmp_path)

    assert "--role" in channel.execute("/help add-member")
    assert "--role" in channel.execute("/add-member --help")


def test_removing_somebody_who_is_not_a_member_says_so(tmp_path):
    channel, _store = make_channel(tmp_path)
    channel.execute("/create-group ops")

    assert "was not a member" in channel.execute(f"/remove-member ops {MEMBER}")
    assert "No such group" in channel.execute(f"/remove-member missing {MEMBER}")


def test_listing_the_members_of_a_group_that_does_not_exist_is_an_error(tmp_path):
    channel, _store = make_channel(tmp_path)

    assert "No such group" in channel.execute("/members missing")


def test_an_overlong_command_is_refused_before_it_is_parsed(tmp_path):
    channel, store = make_channel(tmp_path)

    assert "too long" in channel.execute("/create-group " + "a" * MAX_COMMAND_BYTES)
    assert store.list_groups() == []


def test_peers_reports_a_hub_that_has_never_answered(tmp_path):
    channel, _store = make_channel(tmp_path)
    channel.config.federation.peers = ["0b" * 16]

    assert channel.execute("/peers").startswith(f"{'0b' * 16}\tlast answered never")


def test_peers_says_so_when_none_are_configured(tmp_path):
    channel, _store = make_channel(tmp_path)

    assert channel.execute("/peers") == "no peers configured"


def test_a_malformed_peer_hash_is_reported_not_raised(tmp_path):
    channel, _store = make_channel(tmp_path)
    channel.config.federation.peers = ["nonsense"]

    assert "Command failed" in channel.execute("/peers")


@pytest.mark.parametrize(
    "text",
    ["/run", "--config /etc/passwd status", "rm -rf /", "'unterminated"],
)
def test_commands_outside_the_allowlist_are_refused(tmp_path, text):
    channel, store = make_channel(tmp_path)
    reply = channel.execute(text)
    assert "Commands:" in reply or "Could not parse" in reply
    assert store.list_groups() == []


def test_bad_arguments_come_back_as_text_not_an_exit(tmp_path):
    channel, store = make_channel(tmp_path)
    assert "No such group" in channel.execute(f"/add-member missing {MEMBER}")
    channel.execute("/create-group ops")
    assert "not a hex LXMF address" in channel.execute("/add-member ops zzzz")
    assert "invalid choice" in channel.execute("/set-acl ops sideways")
    assert channel.execute("/create-group ops") == "Group 'ops' already exists"
    assert len(store.list_groups()) == 1


def test_non_operators_get_no_reply_and_change_nothing(tmp_path):
    channel, store = make_channel(tmp_path)
    replies = []
    channel.reply = lambda operator_hash, text: replies.append((operator_hash, text))

    channel.handle(command("/create-group ops", source=INTRUDER))
    channel.handle(command("/create-group ops", signed=False))

    assert replies == []
    assert store.list_groups() == []

    channel.handle(command("/create-group ops"))
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
