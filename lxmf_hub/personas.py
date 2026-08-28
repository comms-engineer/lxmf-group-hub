"""Usernames and multi-device personas.

A persona is a person; the LXMF destinations they send from are their devices. A
member claims a name once and then attaches further devices to the same persona
with a one-time code, so a phone and a base station post under one username
without the hub ever seeing a private key.

Personas are federated state. Every hub merges the personas of every peer into
its own tables -- rather than into a ``peer_*`` shadow, the way member sets are
kept -- because a name has to resolve on whichever hub is attributing a message,
including one relaying it on behalf of a hub that is down.

Two hubs can mint the same name while they cannot see each other. That is
resolved without asking anybody: the earlier claim keeps the name, ties break on
the persona id, and the loser is told to pick another. The rule is a pure
function of replicated state, so every hub reaches the same answer.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time

from .store import PersonaIdentity, PersonaRecord, Store, fold_name

PERSONA_ID_LENGTH = 16

NAME_MIN_LENGTH = 2
NAME_MAX_LENGTH = 32
# Deliberately narrow: a username is quoted back into message prefixes and
# operator listings, so control characters, whitespace and colons stay out of it.
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Codes are read off one screen and typed into another, so the alphabet excludes
# the characters that get confused doing that.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 6
CODE_TTL_SEC = 900.0


class PersonaError(Exception):
    """A persona operation that failed for a reason worth telling the user."""


def validate_name(name: str) -> str:
    """Return the name as it will be stored, or raise ``PersonaError``."""
    cleaned = name.strip()
    if len(cleaned) < NAME_MIN_LENGTH or len(cleaned) > NAME_MAX_LENGTH:
        raise PersonaError(
            f"A username is {NAME_MIN_LENGTH}-{NAME_MAX_LENGTH} characters;"
            f" '{cleaned}' is {len(cleaned)}."
        )
    if not NAME_PATTERN.match(cleaned):
        raise PersonaError(
            "A username starts with a letter or digit and may then use letters,"
            " digits, dot, dash and underscore."
        )
    return cleaned


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def wins(first: PersonaRecord, second: PersonaRecord) -> bool:
    """Whether ``first`` keeps a name both personas claim.

    Earlier claim wins; the persona id breaks a tie. Both inputs are replicated
    verbatim, so every hub decides this identically without talking to anyone.
    """
    return (first.claimed_at, first.persona_id) < (second.claimed_at, second.persona_id)


class PersonaRegistry:
    """Claiming, linking and merging personas."""

    def __init__(self, store: Store):
        self.store = store

    # -- lookups ---------------------------------------------------------

    def persona_for(self, user_hash: bytes) -> PersonaRecord | None:
        return self.store.persona_for_identity(user_hash)

    def display_name(self, user_hash: bytes) -> str | None:
        return self.store.display_name_for(user_hash)

    # -- claiming --------------------------------------------------------

    def claim(self, user_hash: bytes, name: str) -> PersonaRecord:
        """Claim or change the username of the persona a device belongs to."""
        wanted = validate_name(name)
        mine = self.persona_for(user_hash)
        holder = self.store.persona_by_name(wanted)
        if holder is not None and (mine is None or holder.persona_id != mine.persona_id):
            raise PersonaError(f"'{wanted}' is already taken. Pick another username.")
        if mine is not None and mine.name_folded == fold_name(wanted):
            # Same name in different capitalisation is still a change worth
            # writing, so it replicates; an identical name is a no-op.
            if mine.name == wanted:
                return mine
        try:
            if mine is None:
                return self.store.create_persona(
                    os.urandom(PERSONA_ID_LENGTH), wanted, user_hash
                )
            self.store.set_persona_name(mine.persona_id, wanted)
        except sqlite3.IntegrityError as exception:
            # The unique index, not the check above: another device claimed the
            # same name between the two statements.
            raise PersonaError(f"'{wanted}' was just taken. Pick another username.") from exception
        persona = self.store.get_persona(mine.persona_id)
        if persona is None:  # pragma: no cover - the row was just updated
            raise PersonaError("That persona no longer exists.")
        return persona

    # -- devices ---------------------------------------------------------

    def mint_code(self, user_hash: bytes) -> tuple[str, float]:
        """Mint a one-time code that adds another device to this persona.

        A device with no persona gets one first: a code has to name a persona,
        and a member who links two devices before choosing a username is a
        perfectly ordinary order of events.
        """
        persona = self.persona_for(user_hash)
        if persona is None:
            persona = self.store.create_persona(os.urandom(PERSONA_ID_LENGTH), None, user_hash)
        expires_at = time.time() + CODE_TTL_SEC
        code = new_code()
        self.store.create_link_code(code, persona.persona_id, expires_at)
        return code, expires_at

    def join(self, user_hash: bytes, code: str) -> PersonaRecord:
        """Attach a device to the persona a code was minted for.

        The new device inherits whatever group membership its persona already
        has, so linking a device is enough to authorise it in an invite-only
        group -- an operator does not have to add-member a hash that is already,
        transitively, a member through another of the same person's devices.
        """
        persona_id = self.store.claim_link_code(code.strip().upper())
        if persona_id is None:
            raise PersonaError("That code is not valid. Codes are single-use and expire.")
        persona = self.store.get_persona(persona_id)
        if persona is None:
            raise PersonaError("The persona that code belonged to is gone.")
        existing = [device.user_hash for device in self.store.persona_devices(persona_id)]
        roles = self.store.memberships_for(existing)
        self.store.link_identity(persona_id, user_hash)
        for group_id, role in roles.items():
            self.store.add_member(group_id, user_hash, role)
        return persona

    def unlink(self, user_hash: bytes, target_hash: bytes) -> PersonaRecord:
        """Detach one of the caller's own devices from their persona."""
        mine = self.persona_for(user_hash)
        if mine is None:
            raise PersonaError("You have no persona to unlink anything from.")
        target = self.store.get_persona_identity(target_hash)
        if target is None or not target.active or target.persona_id != mine.persona_id:
            raise PersonaError(f"{target_hash.hex()} is not one of your devices.")
        if len(self.store.persona_devices(mine.persona_id)) == 1:
            # The last device is what makes the name reachable, and a persona
            # with none is a name nobody can ever claim again.
            raise PersonaError(
                "That is your only device. Claim the name from another device first."
            )
        self.store.unlink_identity(target_hash)
        return mine

    def devices(self, persona_id: bytes) -> list[PersonaIdentity]:
        return self.store.persona_devices(persona_id)

    # -- federation ------------------------------------------------------

    def snapshot(self) -> tuple[list[list], list[list]]:
        """Personas and device rows as they go on the wire.

        Tombstones travel too: a peer that never saw an unlink would otherwise
        reattach the device on its next round, and the two hubs would hand it
        back and forth forever.
        """
        personas = [
            [
                persona.persona_id,
                persona.name,
                persona.claimed_at,
                persona.revision,
                persona.updated_at,
            ]
            for persona in self.store.list_personas()
        ]
        identities = [
            [row.user_hash, row.persona_id, row.added_at, row.removed_at]
            for row in self.store.list_persona_identities()
        ]
        return personas, identities

    def merge(
        self, personas: list[PersonaRecord], identities: list[PersonaIdentity]
    ) -> list[tuple[PersonaRecord, str]]:
        """Merge a peer's personas into the local tables.

        Returns each local persona whose name was taken away by an earlier remote
        claim, with the name it lost, so its owner can be told to choose another.
        """
        losers: list[tuple[PersonaRecord, str]] = []
        for remote in personas:
            local = self.store.get_persona(remote.persona_id)
            if local is not None and not _newer(remote, local):
                continue
            losers.extend(self._adopt(remote))
        for row in identities:
            self._adopt_identity(row)
        return losers

    def _adopt(self, remote: PersonaRecord) -> list[tuple[PersonaRecord, str]]:
        """Write one remote persona, resolving a name collision if there is one."""
        losers: list[tuple[PersonaRecord, str]] = []
        holder = self.store.persona_by_name(remote.name) if remote.name else None
        if holder is not None and holder.persona_id != remote.persona_id:
            if wins(holder, remote):
                # Ours is the earlier claim, so the remote persona arrives without
                # a name. Its own hub will come to the same conclusion when it
                # merges ours, and stop sending the name.
                remote = PersonaRecord(
                    persona_id=remote.persona_id,
                    name=None,
                    claimed_at=remote.claimed_at,
                    revision=remote.revision,
                    updated_at=remote.updated_at,
                )
            else:
                # Theirs is earlier: clear ours with a bumped revision so the
                # release replicates, and hand the owner back for notification.
                lost = holder.name or ""
                self.store.set_persona_name(holder.persona_id, None)
                cleared = self.store.get_persona(holder.persona_id)
                losers.append((cleared if cleared is not None else holder, lost))
        self.store.upsert_persona(remote)
        return losers

    def _adopt_identity(self, remote: PersonaIdentity) -> None:
        if self.store.get_persona(remote.persona_id) is None:
            # A device whose persona this hub has not heard of yet. The next
            # round brings the persona, and the row with it.
            return
        local = self.store.get_persona_identity(remote.user_hash)
        if local is not None and local.version >= remote.version:
            return
        self.store.upsert_persona_identity(remote)


def _newer(remote: PersonaRecord, local: PersonaRecord) -> bool:
    return (remote.revision, remote.updated_at) > (local.revision, local.updated_at)
