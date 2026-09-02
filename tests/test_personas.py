"""Persona tests: claiming, device linking, tombstones and federated merges."""

import time

import pytest

from lxmf_hub.personas import CODE_TTL_SEC, PersonaError, PersonaRegistry, validate_name, wins
from lxmf_hub.store import ACL_INVITE, ROLE_ADMIN, ROLE_BANNED, PersonaIdentity, PersonaRecord, Store

PHONE = b"\xa1" * 16
LAPTOP = b"\xa2" * 16
RADIO = b"\xa3" * 16
STRANGER = b"\xb0" * 16
GROUP = "ops"


@pytest.fixture
def registry(tmp_path):
    return PersonaRegistry(Store(str(tmp_path / "hub.db")))


def test_a_name_is_claimed_and_resolves_case_insensitively(registry):
    persona = registry.claim(PHONE, "Alice")

    assert persona.name == "Alice"
    assert registry.display_name(PHONE) == "Alice"
    assert registry.store.persona_by_name("ALICE").persona_id == persona.persona_id


def test_renaming_keeps_the_persona_and_its_devices(registry):
    first = registry.claim(PHONE, "alice")
    second = registry.claim(PHONE, "alice2")

    assert second.persona_id == first.persona_id
    assert second.name == "alice2"
    assert registry.store.persona_by_name("alice") is None
    assert [device.user_hash for device in registry.devices(second.persona_id)] == [PHONE]


def test_a_name_another_persona_holds_is_refused(registry):
    registry.claim(PHONE, "alice")

    with pytest.raises(PersonaError, match="already taken"):
        registry.claim(STRANGER, "ALICE")


def test_reclaiming_your_own_name_is_allowed(registry):
    registry.claim(PHONE, "alice")

    assert registry.claim(PHONE, "alice").name == "alice"
    assert registry.claim(PHONE, "Alice").name == "Alice"


@pytest.mark.parametrize("name", ["a", "x" * 33, "-alice", "al ice", "ali:ce", "ali\ne"])
def test_unusable_names_are_rejected(name):
    with pytest.raises(PersonaError):
        validate_name(name)


def test_a_second_device_joins_with_a_one_time_code(registry):
    persona = registry.claim(PHONE, "alice")
    code, expires_at = registry.mint_code(PHONE)

    joined = registry.join(LAPTOP, code.lower())

    assert joined.persona_id == persona.persona_id
    assert registry.display_name(LAPTOP) == "alice"
    assert expires_at == pytest.approx(time.time() + CODE_TTL_SEC, abs=5.0)


def test_a_code_cannot_be_spent_twice(registry):
    registry.claim(PHONE, "alice")
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)

    with pytest.raises(PersonaError, match="not valid"):
        registry.join(RADIO, code)


def test_joining_inherits_the_persona_s_group_membership(registry):
    registry.claim(PHONE, "alice")
    registry.store.create_group(GROUP, "Ops", b"\x00" * 64, acl_mode=ACL_INVITE)
    registry.store.add_member(GROUP, PHONE, ROLE_ADMIN)
    code, _expires_at = registry.mint_code(PHONE)

    registry.join(LAPTOP, code)

    assert registry.store.get_role(GROUP, LAPTOP) == ROLE_ADMIN


def test_a_banned_device_does_not_get_its_ban_carried_onto_a_new_one(registry):
    registry.claim(PHONE, "alice")
    registry.store.create_group(GROUP, "Ops", b"\x00" * 64, acl_mode=ACL_INVITE)
    registry.store.add_member(GROUP, PHONE, ROLE_BANNED)
    code, _expires_at = registry.mint_code(PHONE)

    registry.join(LAPTOP, code)

    assert registry.store.get_role(GROUP, LAPTOP) is None


def test_an_expired_code_is_refused(registry):
    persona = registry.claim(PHONE, "alice")
    registry.store.create_link_code("EXPIRE", persona.persona_id, expires_at=0.0)

    with pytest.raises(PersonaError, match="not valid"):
        registry.join(LAPTOP, "EXPIRE")


def test_linking_before_naming_creates_the_persona(registry):
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)

    persona = registry.claim(LAPTOP, "alice")

    assert registry.display_name(PHONE) == "alice"
    assert len(registry.devices(persona.persona_id)) == 2


def test_unlinking_leaves_a_tombstone(registry):
    persona = registry.claim(PHONE, "alice")
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)

    registry.unlink(PHONE, LAPTOP)

    assert registry.display_name(LAPTOP) is None
    assert [device.user_hash for device in registry.devices(persona.persona_id)] == [PHONE]
    tombstone = registry.store.get_persona_identity(LAPTOP)
    assert tombstone.removed_at is not None and not tombstone.active


def test_an_unlink_code_lets_that_device_unlink_itself(registry):
    persona = registry.claim(PHONE, "alice")
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)
    unlink_code, expires_at = registry.mint_unlink_code(PHONE)

    unlinked = registry.unlink_with_code(LAPTOP, unlink_code.lower())

    assert unlinked.persona_id == persona.persona_id
    assert registry.display_name(LAPTOP) is None
    assert [device.user_hash for device in registry.devices(persona.persona_id)] == [PHONE]
    assert expires_at == pytest.approx(time.time() + CODE_TTL_SEC, abs=5.0)


def test_an_unlink_code_for_a_persona_cannot_unlink_another_device(registry):
    registry.claim(PHONE, "alice")
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)
    unlink_code, _expires_at = registry.mint_unlink_code(PHONE)

    with pytest.raises(PersonaError, match="not for this device"):
        registry.unlink_with_code(STRANGER, unlink_code)


def test_an_expired_unlink_code_is_refused(registry):
    persona = registry.claim(PHONE, "alice")
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)
    registry.store.create_unlink_code("EXPIRE", persona.persona_id, expires_at=0.0)

    with pytest.raises(PersonaError, match="not valid"):
        registry.unlink_with_code(LAPTOP, "EXPIRE")


def test_the_last_device_cannot_unlink_itself(registry):
    registry.claim(PHONE, "alice")

    with pytest.raises(PersonaError, match="only device"):
        registry.unlink(PHONE, PHONE)


def test_only_your_own_devices_can_be_unlinked(registry):
    registry.claim(PHONE, "alice")
    registry.claim(STRANGER, "bob")

    with pytest.raises(PersonaError, match="not one of your devices"):
        registry.unlink(PHONE, STRANGER)


# -- federation ----------------------------------------------------------


def second(tmp_path):
    return PersonaRegistry(Store(str(tmp_path / "peer.db")))


def sync(source: PersonaRegistry, target: PersonaRegistry):
    personas, identities = source.snapshot()
    return target.merge(
        [PersonaRecord(row[0], row[1], row[2], row[3], row[4]) for row in personas],
        [PersonaIdentity(row[0], row[1], row[2], row[3]) for row in identities],
    )


def test_a_name_replicates_to_a_peer(registry, tmp_path):
    peer = second(tmp_path)
    registry.claim(PHONE, "alice")

    assert sync(registry, peer) == []
    assert peer.display_name(PHONE) == "alice"


def test_a_tombstone_replicates_instead_of_being_relinked(registry, tmp_path):
    peer = second(tmp_path)
    registry.claim(PHONE, "alice")
    code, _expires_at = registry.mint_code(PHONE)
    registry.join(LAPTOP, code)
    sync(registry, peer)
    assert peer.display_name(LAPTOP) == "alice"

    registry.unlink(PHONE, LAPTOP)
    sync(registry, peer)

    assert peer.display_name(LAPTOP) is None
    # And the peer does not push the device back on the next round.
    sync(peer, registry)
    assert registry.display_name(LAPTOP) is None


def test_the_earlier_claim_keeps_a_name_both_hubs_minted(registry, tmp_path):
    peer = second(tmp_path)
    early = registry.store.create_persona(b"\x01" * 16, "alice", PHONE, claimed_at=1000.0)
    late = peer.store.create_persona(b"\x02" * 16, "alice", LAPTOP, claimed_at=2000.0)
    assert wins(early, late)

    losers = sync(registry, peer)

    assert [(persona.persona_id, name) for persona, name in losers] == [(late.persona_id, "alice")]
    assert peer.display_name(LAPTOP) is None
    assert peer.display_name(PHONE) == "alice"


def test_both_hubs_converge_on_the_same_winner(registry, tmp_path):
    peer = second(tmp_path)
    registry.store.create_persona(b"\x01" * 16, "alice", PHONE, claimed_at=1000.0)
    peer.store.create_persona(b"\x02" * 16, "alice", LAPTOP, claimed_at=2000.0)

    for _round in range(2):
        sync(registry, peer)
        sync(peer, registry)

    for hub in (registry, peer):
        assert hub.display_name(PHONE) == "alice"
        assert hub.display_name(LAPTOP) is None


def test_a_device_whose_persona_is_unknown_is_left_for_the_next_round(registry):
    orphan = PersonaIdentity(user_hash=RADIO, persona_id=b"\x09" * 16, added_at=1.0)

    assert registry.merge([], [orphan]) == []
    assert registry.store.get_persona_identity(RADIO) is None


def test_an_older_revision_from_a_peer_is_ignored(registry, tmp_path):
    peer = second(tmp_path)
    registry.claim(PHONE, "alice")
    sync(registry, peer)
    registry.claim(PHONE, "alice2")

    sync(peer, registry)

    assert registry.display_name(PHONE) == "alice2"
