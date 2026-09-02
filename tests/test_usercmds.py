"""In-band member command tests: what is swallowed, what is answered, and /status."""

import pytest

from lxmf_hub.config import HubConfig
from lxmf_hub.personas import PersonaRegistry
from lxmf_hub.store import ACL_PUBLIC, ROLE_ADMIN, ROLE_BANNED, Store
from lxmf_hub.usercmds import UserCommands, verb_of
from tests.test_hub import GROUP, GROUP_DESTINATION, StubDestinations

ALICE = b"\xa1" * 16
LAPTOP = b"\xa2" * 16
OPERATOR = b"\xf0" * 16
PEER = b"\xc0" * 16


@pytest.fixture
def commands(tmp_path):
    config = HubConfig()
    config.hub_name = "hub-one"
    config.operator_identity = [OPERATOR.hex()]
    config.commands.min_reply_interval_sec = 0.0
    store = Store(str(tmp_path / "hub.db"))
    store.create_group(GROUP, "Ops", b"\x00" * 64, acl_mode=ACL_PUBLIC)
    store.add_member(GROUP, ALICE)
    destinations = StubDestinations({GROUP_DESTINATION: GROUP})
    return UserCommands(config, store, PersonaRegistry(store), destinations, started_at=0.0)


def answers(commands):
    return [item.body for item in commands.store.due_user(10, now=2**31)]


# -- what counts as a command --------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("/help", "/help"),
        ("  /STATUS  ", "/status"),
        ("/name Alice", "/name"),
        ("/nameless thoughts", None),
        ("hello", None),
        ("/path/to/file is broken", None),
        ("look at /status in the docs", None),
        ("/" + "x" * 2000, None),
    ],
)
def test_only_known_verbs_are_commands(text, expected):
    assert verb_of(text) == expected


def test_an_ordinary_message_is_left_alone(commands):
    assert commands.handle(GROUP, ALICE, "/etc/hosts is the file") is False
    assert answers(commands) == []


def test_a_command_is_swallowed_and_answered(commands):
    assert commands.handle(GROUP, ALICE, "/name alice") is True

    assert commands.store.user_depth() == 1
    assert commands.store.display_name_for(ALICE) == "alice"


def test_a_member_cannot_moderate_the_group(commands):
    assert commands.handle(GROUP, ALICE, f"/ban {LAPTOP.hex()}", role="member") is True

    assert commands.store.get_role(GROUP, LAPTOP) is None
    assert "Only a group admin" in answers(commands)[0]


def test_an_admin_can_manage_members_but_not_another_admin(commands):
    commands.store.add_member(GROUP, ALICE, ROLE_ADMIN)

    assert commands.handle(GROUP, ALICE, f"/ban {LAPTOP.hex()}", role=ROLE_ADMIN) is True
    assert commands.store.get_role(GROUP, LAPTOP) == ROLE_BANNED
    assert "banned" in answers(commands)[0]

    commands.handle(GROUP, ALICE, f"/unban {LAPTOP.hex()}", role=ROLE_ADMIN)
    assert commands.store.get_role(GROUP, LAPTOP) == "member"

    commands.store.add_member(GROUP, LAPTOP, ROLE_ADMIN)
    commands.handle(GROUP, ALICE, f"/remove {LAPTOP.hex()}", role=ROLE_ADMIN)
    assert commands.store.get_role(GROUP, LAPTOP) == ROLE_ADMIN


def test_a_repeat_inside_the_interval_is_swallowed_without_an_answer(commands):
    commands.config.commands.min_reply_interval_sec = 60.0

    assert commands.handle(GROUP, ALICE, "/help") is True
    # Still consumed: the flood must not land in the group as messages.
    assert commands.handle(GROUP, ALICE, "/help") is True
    assert commands.store.user_depth() == 1


def test_commands_can_be_turned_off(commands):
    commands.config.commands.enabled = False

    assert commands.handle(GROUP, ALICE, "/help") is False
    assert commands.store.user_depth() == 0


def test_a_failing_command_still_answers(commands):
    body = commands.execute(ALICE, "/name ")

    assert "change it" in body


def test_a_rejected_name_is_explained_rather_than_raised(commands):
    commands.registry.claim(LAPTOP, "alice")

    assert "already taken" in commands.execute(ALICE, "/name ALICE")


def test_an_unparseable_device_hash_is_explained(commands):
    commands.registry.claim(ALICE, "alice")

    assert "hex" in commands.execute(ALICE, "/unlink zzz").lower()


# -- help ---------------------------------------------------------------


def test_help_lists_the_member_commands(commands):
    body = commands.help(ALICE)

    for verb in ("/help", "/status", "/name", "/whoami", "/link", "/unlink", "/who", "/names"):
        assert verb in body
    assert "operator" not in body.lower()


def test_an_operator_also_gets_the_control_commands(commands):
    body = commands.help(OPERATOR)

    assert "control address" in body
    assert "members" in body


# -- persona commands ---------------------------------------------------


def test_whoami_lists_the_devices_and_marks_this_one(commands):
    commands.registry.claim(ALICE, "alice")
    code, _expires_at = commands.registry.mint_code(ALICE)
    commands.registry.join(LAPTOP, code)

    body = commands.execute(LAPTOP, "/whoami")

    assert "alice" in body
    assert f"{LAPTOP.hex()} <- this device" in body
    assert ALICE.hex() in body


def test_link_hands_out_a_code_that_the_other_device_uses(commands):
    commands.registry.claim(ALICE, "alice")

    offer = commands.execute(ALICE, "/link")
    code = offer.split("'")[1].split()[1]

    assert "now alice" in commands.execute(LAPTOP, f"/link {code}")
    assert commands.store.display_name_for(LAPTOP) == "alice"


def test_who_and_names_report_the_directory(commands):
    commands.registry.claim(ALICE, "alice")

    assert ALICE.hex() in commands.execute(LAPTOP, "/who ALICE")
    assert "Nobody here is called bob" in commands.execute(LAPTOP, "/who bob")
    assert "alice" in commands.execute(LAPTOP, "/names")


def test_names_is_empty_before_anybody_claims_one(commands):
    assert "Nobody has claimed" in commands.execute(ALICE, "/names")


# -- status -------------------------------------------------------------


def test_status_reports_the_hub_groups_and_reader(commands):
    commands.registry.claim(ALICE, "alice")

    body = commands.status(ALICE)

    assert "hub-one" in body
    assert "1 group(s)" in body
    assert "you: alice" in body
    assert f"{GROUP} (public): 1 member(s) here" in body
    assert GROUP_DESTINATION.hex() in body
    assert "queues:" in body


def test_status_tells_an_unnamed_reader_how_to_claim_a_name(commands):
    assert "no username yet" in commands.status(ALICE)


def test_status_reports_a_peer_and_the_members_it_is_serving(commands):
    commands.config.federation.peers = [PEER.hex()]
    commands.store.record_peer_state(PEER, "hub-two", {GROUP: (b"\xd0" * 16, ACL_PUBLIC)}, {})
    commands.store.adopt(PEER, GROUP, [LAPTOP])

    body = commands.status(ALICE)

    assert "1 peer hub(s)" in body
    assert "hub-two" in body
    assert "1 of its member(s) served here" in body
    assert "0/1 peer(s) answering" in body
    assert "never answered" in body


def test_status_says_so_when_federation_is_off(commands):
    commands.config.federation.enabled = False

    assert "federation: off" in commands.status(ALICE)


def test_a_malformed_peer_does_not_break_status(commands):
    commands.config.federation.peers = ["not-a-hash"]

    assert "0 peer hub(s)" in commands.status(ALICE)


def test_an_operator_sees_the_control_queue_and_persona_counts(commands):
    commands.registry.claim(ALICE, "alice")

    body = commands.status(OPERATOR)

    assert "operator:" in body
    assert "1/1 persona(s) named" in body


# -- losing a name to another hub ---------------------------------------


def test_a_persona_that_lost_its_name_is_told_in_a_group_it_is_in(commands):
    persona = commands.registry.claim(ALICE, "alice")

    assert commands.notify_name_lost(persona.persona_id, "alice") == 1

    assert "no longer yours" in answers(commands)[0]


def test_a_persona_with_no_group_is_not_queued_an_answer(commands):
    persona = commands.registry.claim(LAPTOP, "alice")

    assert commands.notify_name_lost(persona.persona_id, "alice") == 0
    assert answers(commands) == []
