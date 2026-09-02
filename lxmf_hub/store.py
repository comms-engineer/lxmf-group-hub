"""Crash-consistent persistence layer for the hub.

Everything the daemon needs to resume after an unclean shutdown lives here:
group identities, ACLs, the message log, the client egress queue and peer sync
state. SQLite runs in WAL mode so a killed daemon never leaves a torn write.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .crypto import Cipher, build_cipher

ROLE_MEMBER = "member"
ROLE_ADMIN = "admin"
ROLE_BANNED = "banned"

ACL_PUBLIC = "public"
ACL_INVITE = "invite"

ORIGIN_LOCAL = "local"
ORIGIN_FEDERATED = "federated"

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    group_id      TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    identity_key  BLOB NOT NULL,
    created_at    REAL NOT NULL,
    acl_mode      TEXT NOT NULL DEFAULT 'invite'
);

CREATE TABLE IF NOT EXISTS members (
    group_id  TEXT NOT NULL,
    user_hash BLOB NOT NULL,
    role      TEXT NOT NULL DEFAULT 'member',
    added_at  REAL NOT NULL,
    PRIMARY KEY (group_id, user_hash)
);

CREATE TABLE IF NOT EXISTS messages (
    msg_hash          BLOB PRIMARY KEY,
    group_id          TEXT NOT NULL,
    sender_hash       BLOB NOT NULL,
    timestamp         REAL NOT NULL,
    lxmf_payload_blob BLOB NOT NULL,
    origin            TEXT NOT NULL DEFAULT 'local',
    received_at       REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_group_ts ON messages (group_id, timestamp);

-- ``graces`` counts deferrals spent waiting for a path to the recipient. They
-- are deliberately not delivery attempts, so a member whose radio is off does
-- not burn through max_attempts without a single transmission, but they do pace
-- the path requests: a recipient that never appears is asked for with a growing
-- backoff instead of once per tick until the message ages out.
CREATE TABLE IF NOT EXISTS egress_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id        TEXT NOT NULL,
    recipient_hash  BLOB NOT NULL,
    msg_hash        BLOB NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    graces          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    created_at      REAL NOT NULL,
    UNIQUE (recipient_hash, msg_hash)
);

CREATE INDEX IF NOT EXISTS idx_egress_due ON egress_queue (next_attempt_at);

CREATE TABLE IF NOT EXISTS peers (
    peer_hash    BLOB PRIMARY KEY,
    last_sync_at REAL NOT NULL DEFAULT 0,
    last_error   TEXT
);

-- Last time a peer actually answered. Separate from peers.last_sync_at, which
-- records every attempt including the failed ones: a hub whose peer is down
-- still writes a row every sync round, so that column cannot say who is up.
CREATE TABLE IF NOT EXISTS peer_liveness (
    peer_hash       BLOB PRIMARY KEY,
    last_success_at REAL NOT NULL
);

-- What a peer told us it serves, so the directory can answer with other hubs'
-- endpoints and a standby knows which destination to name in a notice.
CREATE TABLE IF NOT EXISTS peer_groups (
    peer_hash        BLOB NOT NULL,
    group_id         TEXT NOT NULL,
    destination_hash BLOB NOT NULL,
    hub_name         TEXT NOT NULL,
    acl_mode         TEXT NOT NULL,
    updated_at       REAL NOT NULL,
    PRIMARY KEY (peer_hash, group_id)
);

-- Peer member sets, kept so a standby can serve a dead hub's members.
CREATE TABLE IF NOT EXISTS peer_members (
    peer_hash  BLOB NOT NULL,
    group_id   TEXT NOT NULL,
    user_hash  BLOB NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (peer_hash, group_id, user_hash)
);

-- Members of an unreachable peer that this hub is currently serving. Rows
-- survive restarts, so an adoption is announced once and released once.
CREATE TABLE IF NOT EXISTS adoptions (
    peer_hash  BLOB NOT NULL,
    group_id   TEXT NOT NULL,
    user_hash  BLOB NOT NULL,
    adopted_at REAL NOT NULL,
    PRIMARY KEY (peer_hash, group_id, user_hash)
);

-- Hub-generated text for one client: failover notices and directory answers do
-- not reference a stored message, but still have to be paced and retried.
-- ``source`` says which of the hub's destinations it goes out from, since a
-- directory answer cannot come from a group the reader may not be a member of.
CREATE TABLE IF NOT EXISTS notice_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,
    group_id        TEXT NOT NULL,
    recipient_hash  BLOB NOT NULL,
    body            TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    graces          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    created_at      REAL NOT NULL,
    UNIQUE (recipient_hash, body)
);

CREATE INDEX IF NOT EXISTS idx_notice_due ON notice_queue (next_attempt_at);

-- Answers to operator commands. Kept apart from notice_queue because control
-- traffic has the opposite requirements: it must not be deduplicated (two
-- status commands deserve two answers even when the text is identical) and it
-- is not paced by the client token bucket, since it only ever goes to an
-- operator. It is queued rather than handed straight to the router so an answer
-- survives an unknown path, a failed delivery and a restart.
CREATE TABLE IF NOT EXISTS control_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_hash  BLOB NOT NULL,
    body            TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    graces          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    created_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_control_due ON control_queue (next_attempt_at);

-- Answers to a member's own commands (``/name``, ``/whoami``). Separate from
-- notice_queue for the same reason control_queue is: a notice is deduplicated on
-- (recipient, body) because two identical failover notices are one piece of
-- news, while two ``/whoami`` messages deserve two answers even though the text
-- is identical. Unlike control_queue these are ordinary client traffic, so they
-- go out from the group destination and spend client tokens.
CREATE TABLE IF NOT EXISTS user_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id        TEXT NOT NULL,
    recipient_hash  BLOB NOT NULL,
    body            TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    graces          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    created_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_due ON user_queue (next_attempt_at);

-- A person, as opposed to one of their devices. ``persona_id`` is 16 random
-- bytes minted where the persona is claimed, so hubs never have to agree on an
-- id space. ``name_folded`` is the case-insensitive form the uniqueness index
-- and every lookup use; ``name`` keeps the capitalisation the owner typed.
-- ``revision`` orders updates during federation merges, and a NULL name is a
-- real state: a persona that lost a name conflict keeps its devices.
CREATE TABLE IF NOT EXISTS personas (
    persona_id  BLOB PRIMARY KEY,
    name        TEXT,
    name_folded TEXT,
    claimed_at  REAL NOT NULL,
    revision    INTEGER NOT NULL DEFAULT 1,
    updated_at  REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_personas_name ON personas (name_folded);

-- Which LXMF identities are that person. One identity belongs to at most one
-- persona, several identities to one persona is the multi-device case.
-- ``removed_at`` is a tombstone rather than a delete: an unlink has to
-- replicate, and a peer that only ever saw the link would otherwise hand the
-- device back on the next sync round.
CREATE TABLE IF NOT EXISTS persona_identities (
    user_hash  BLOB PRIMARY KEY,
    persona_id BLOB NOT NULL,
    added_at   REAL NOT NULL,
    removed_at REAL
);

CREATE INDEX IF NOT EXISTS idx_persona_identities ON persona_identities (persona_id);

-- One-time codes a member's first device mints so a second device can join the
-- same persona. Deliberately local: a code is short-lived and single-use, so
-- replicating it would only widen where it can be replayed.
CREATE TABLE IF NOT EXISTS persona_links (
    code       TEXT PRIMARY KEY,
    persona_id BLOB NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

-- One-time codes a member mints to let another of their existing devices unlink
-- itself. Deliberately local for the same reason as persona_links.
CREATE TABLE IF NOT EXISTS persona_unlinks (
    code       TEXT PRIMARY KEY,
    persona_id BLOB NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
"""

# Framing byte on encryptable columns, so a database written in one at-rest mode
# still reports a clear error rather than returning garbage in another.
BLOB_PLAIN = b"\x00"
BLOB_ENCRYPTED = b"\x01"


@dataclass(frozen=True)
class GroupRecord:
    group_id: str
    display_name: str
    identity_key: bytes
    created_at: float
    acl_mode: str


@dataclass(frozen=True)
class MessageRecord:
    msg_hash: bytes
    group_id: str
    sender_hash: bytes
    timestamp: float
    payload: bytes
    origin: str = ORIGIN_LOCAL


@dataclass(frozen=True)
class EgressItem:
    item_id: int
    group_id: str
    recipient_hash: bytes
    msg_hash: bytes
    attempts: int
    graces: int = 0


SOURCE_GROUP = "group"
SOURCE_DIRECTORY = "directory"

# Tables the shared deferral helper may write to. Named here so the table cannot
# reach the statement from anywhere but this module.
QUEUE_TABLES = frozenset({"egress_queue", "notice_queue", "control_queue", "user_queue"})


@dataclass(frozen=True)
class NoticeItem:
    item_id: int
    source: str
    group_id: str
    recipient_hash: bytes
    body: str
    attempts: int
    graces: int = 0


@dataclass(frozen=True)
class ControlItem:
    item_id: int
    recipient_hash: bytes
    body: str
    attempts: int
    graces: int = 0


@dataclass(frozen=True)
class UserItem:
    item_id: int
    group_id: str
    recipient_hash: bytes
    body: str
    attempts: int
    graces: int = 0


@dataclass(frozen=True)
class PersonaRecord:
    persona_id: bytes
    name: str | None
    claimed_at: float
    revision: int
    updated_at: float

    @property
    def name_folded(self) -> str | None:
        return fold_name(self.name)


@dataclass(frozen=True)
class PersonaIdentity:
    user_hash: bytes
    persona_id: bytes
    added_at: float
    removed_at: float | None = None

    @property
    def active(self) -> bool:
        return self.removed_at is None

    @property
    def version(self) -> float:
        """How recent this row is, for merging one hub's row against another's."""
        return max(self.added_at, self.removed_at or 0.0)


@dataclass(frozen=True)
class PeerGroup:
    peer_hash: bytes
    group_id: str
    destination_hash: bytes
    hub_name: str
    acl_mode: str
    updated_at: float


def fold_name(name: str | None) -> str | None:
    """The case-insensitive form of a username, or None.

    Case folding rather than lowercasing: two names that differ only in case are
    the same name to a reader, and ``casefold`` gets the non-ASCII pairs that
    ``lower`` does not.
    """
    if name is None:
        return None
    return name.casefold()


def group_hash(group_id: str) -> bytes:
    """Hub-independent hash of a group id.

    Federating hubs each hold their own RNS identity for a group, so the shared
    identifier -- and therefore the message hash -- is derived from the group id
    rather than from any single hub's destination hash.
    """
    return hashlib.sha256(group_id.encode("utf-8")).digest()


def message_hash(group_id: str, sender_hash: bytes, timestamp: float, payload: bytes) -> bytes:
    """SHA-256 of (group hash + sender hash + timestamp + payload)."""
    digest = hashlib.sha256()
    digest.update(group_hash(group_id))
    digest.update(sender_hash)
    digest.update(struct.pack(">d", timestamp))
    digest.update(payload)
    return digest.digest()


class Store:
    """Thread-safe SQLite store. One connection, guarded by a re-entrant lock."""

    def __init__(self, path: str):
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self._cipher: Cipher | None = None
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=30.0)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=30000")
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate()
            self._db.commit()

    def _migrate(self) -> None:
        """Add columns that a database written by an older version lacks."""
        for table, column, definition in (
            ("egress_queue", "graces", "INTEGER NOT NULL DEFAULT 0"),
            ("notice_queue", "graces", "INTEGER NOT NULL DEFAULT 0"),
        ):
            present = {
                row["name"]
                for row in self._db.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if column not in present:
                self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- at-rest encryption ----------------------------------------------

    def bind_cipher(self, mode: str, keyfile_path: str) -> None:
        """Install the at-rest cipher for encryptable columns."""
        salt = self._meta_get("at_rest_salt")
        if salt is None:
            salt = os.urandom(32)
            self._meta_set("at_rest_salt", salt)
        self._cipher = build_cipher(mode, keyfile_path, salt)

        canary = self._meta_get("at_rest_canary")
        if canary is None:
            self._meta_set("at_rest_canary", self._encode(b"lxmf_hub"))
        elif self._decode(canary) != b"lxmf_hub":
            raise ValueError("At-rest key does not match this database")

    def _encode(self, plaintext: bytes) -> bytes:
        if self._cipher is None:
            return BLOB_PLAIN + plaintext
        return BLOB_ENCRYPTED + self._cipher.encrypt(plaintext)

    def _decode(self, stored: bytes) -> bytes:
        marker, body = stored[:1], stored[1:]
        if marker == BLOB_PLAIN:
            return body
        if marker == BLOB_ENCRYPTED:
            if self._cipher is None:
                raise ValueError("Database holds encrypted values but no at-rest key is configured")
            return self._cipher.decrypt(body)
        raise ValueError("Unrecognised stored value framing")

    def _meta_get(self, key: str) -> bytes | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _meta_set(self, key: str, value: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._db.commit()

    # -- groups ----------------------------------------------------------

    def create_group(
        self,
        group_id: str,
        display_name: str,
        identity_key: bytes,
        acl_mode: str = ACL_INVITE,
        created_at: float | None = None,
    ) -> GroupRecord:
        if acl_mode not in (ACL_PUBLIC, ACL_INVITE):
            raise ValueError(f"Invalid ACL mode: {acl_mode}")
        record = GroupRecord(
            group_id=group_id,
            display_name=display_name,
            identity_key=identity_key,
            created_at=created_at if created_at is not None else time.time(),
            acl_mode=acl_mode,
        )
        with self._lock:
            self._db.execute(
                "INSERT INTO groups (group_id, display_name, identity_key, created_at, acl_mode)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    record.group_id,
                    record.display_name,
                    self._encode(record.identity_key),
                    record.created_at,
                    record.acl_mode,
                ),
            )
            self._db.commit()
        return record

    def get_group(self, group_id: str) -> GroupRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM groups WHERE group_id = ?", (group_id,)
            ).fetchone()
        return self._group_from_row(row) if row else None

    def list_groups(self) -> list[GroupRecord]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM groups ORDER BY group_id").fetchall()
        return [self._group_from_row(row) for row in rows]

    def set_acl_mode(self, group_id: str, acl_mode: str) -> None:
        if acl_mode not in (ACL_PUBLIC, ACL_INVITE):
            raise ValueError(f"Invalid ACL mode: {acl_mode}")
        with self._lock:
            self._db.execute(
                "UPDATE groups SET acl_mode = ? WHERE group_id = ?", (acl_mode, group_id)
            )
            self._db.commit()

    def delete_group(self, group_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM groups WHERE group_id = ?", (group_id,))
            self._db.execute("DELETE FROM members WHERE group_id = ?", (group_id,))
            self._db.commit()

    # -- members ---------------------------------------------------------

    def add_member(self, group_id: str, user_hash: bytes, role: str = ROLE_MEMBER) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO members (group_id, user_hash, role, added_at) VALUES (?, ?, ?, ?)"
                " ON CONFLICT (group_id, user_hash) DO UPDATE SET role = excluded.role",
                (group_id, user_hash, role, time.time()),
            )
            self._db.commit()

    def remove_member(self, group_id: str, user_hash: bytes) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM members WHERE group_id = ? AND user_hash = ?", (group_id, user_hash)
            )
            self._db.commit()

    def get_role(self, group_id: str, user_hash: bytes) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM members WHERE group_id = ? AND user_hash = ?",
                (group_id, user_hash),
            ).fetchone()
        return row["role"] if row else None

    def list_members(self, group_id: str, include_banned: bool = False) -> list[tuple[bytes, str]]:
        query = "SELECT user_hash, role FROM members WHERE group_id = ?"
        params: list[object] = [group_id]
        if not include_banned:
            query += " AND role != ?"
            params.append(ROLE_BANNED)
        with self._lock:
            rows = self._db.execute(query, params).fetchall()
        return [(row["user_hash"], row["role"]) for row in rows]

    def memberships_for(self, user_hashes: list[bytes]) -> dict[str, str]:
        """The best non-banned role held by any of the given devices, per group.

        Used to carry a persona's group membership onto a device it just linked,
        so joining a device is enough to authorise it -- an operator should not
        have to add-member a hash that is already, transitively, a member.
        """
        if not user_hashes:
            return {}
        placeholders = ",".join("?" for _ in user_hashes)
        with self._lock:
            rows = self._db.execute(
                f"SELECT group_id, role FROM members WHERE user_hash IN ({placeholders})"
                " AND role != ?",
                (*user_hashes, ROLE_BANNED),
            ).fetchall()
        roles: dict[str, str] = {}
        for row in rows:
            group_id, role = row["group_id"], row["role"]
            if role == ROLE_ADMIN or group_id not in roles:
                roles[group_id] = role
        return roles

    # -- messages --------------------------------------------------------

    def has_message(self, msg_hash: bytes) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM messages WHERE msg_hash = ?", (msg_hash,)
            ).fetchone()
        return row is not None

    def store_message(self, record: MessageRecord) -> bool:
        """Persist a message. Returns False if it was already known."""
        with self._lock:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO messages"
                " (msg_hash, group_id, sender_hash, timestamp, lxmf_payload_blob, origin,"
                " received_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.msg_hash,
                    record.group_id,
                    record.sender_hash,
                    record.timestamp,
                    self._encode(record.payload),
                    record.origin,
                    time.time(),
                ),
            )
            self._db.commit()
        return cursor.rowcount > 0

    def store_and_enqueue(
        self, record: MessageRecord, recipients: Sequence[bytes]
    ) -> tuple[bool, int]:
        """Persist a message and queue it for its recipients in one transaction.

        Storing and fanning out separately loses messages: the store call is what
        makes a message known, so a crash -- or an exception raised while
        building the recipient set -- between the two leaves a message that is
        recorded, deduplicated against on the next delivery and federated to
        peers, but never queued for anybody. Doing both under one commit means a
        message is either unknown and retriable, or known and queued.

        Returns (stored, queued): stored is False if the message was already
        known, in which case nothing is queued.
        """
        now = time.time()
        with self._lock:
            try:
                cursor = self._db.execute(
                    "INSERT OR IGNORE INTO messages"
                    " (msg_hash, group_id, sender_hash, timestamp, lxmf_payload_blob, origin,"
                    " received_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        record.msg_hash,
                        record.group_id,
                        record.sender_hash,
                        record.timestamp,
                        self._encode(record.payload),
                        record.origin,
                        now,
                    ),
                )
                if cursor.rowcount == 0:
                    self._db.commit()
                    return False, 0
                queued = 0
                for recipient in recipients:
                    inserted = self._db.execute(
                        "INSERT OR IGNORE INTO egress_queue"
                        " (group_id, recipient_hash, msg_hash, attempts, next_attempt_at,"
                        " created_at)"
                        " VALUES (?, ?, ?, 0, ?, ?)",
                        (record.group_id, recipient, record.msg_hash, now, now),
                    )
                    queued += inserted.rowcount
                self._db.commit()
            except Exception:
                # Rolled back so the message stays unknown: the sender's client
                # will retry it, and a retry can only work if this hub has not
                # already recorded the message and started deduplicating it.
                self._db.rollback()
                raise
        return True, queued

    def get_message(self, msg_hash: bytes) -> MessageRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM messages WHERE msg_hash = ?", (msg_hash,)
            ).fetchone()
        return self._message_from_row(row) if row else None

    def get_messages(self, msg_hashes: Sequence[bytes]) -> list[MessageRecord]:
        results: list[MessageRecord] = []
        for chunk in _chunks(list(msg_hashes), 256):
            placeholders = ",".join("?" for _ in chunk)
            with self._lock:
                rows = self._db.execute(
                    f"SELECT * FROM messages WHERE msg_hash IN ({placeholders})", chunk
                ).fetchall()
            results.extend(self._message_from_row(row) for row in rows)
        return results

    def epoch_hashes(self, group_id: str, epoch: int, epoch_seconds: int) -> list[bytes]:
        """Message hashes stored in a time bucket, sorted for Merkle building."""
        start = epoch * epoch_seconds
        with self._lock:
            rows = self._db.execute(
                "SELECT msg_hash FROM messages"
                " WHERE group_id = ? AND timestamp >= ? AND timestamp < ?"
                " ORDER BY msg_hash",
                (group_id, start, start + epoch_seconds),
            ).fetchall()
        return [row["msg_hash"] for row in rows]

    def populated_epochs(self, group_id: str, epoch_seconds: int, since: float = 0.0) -> list[int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT CAST(timestamp / ? AS INTEGER) AS epoch FROM messages"
                " WHERE group_id = ? AND timestamp >= ? ORDER BY epoch",
                (epoch_seconds, group_id, since),
            ).fetchall()
        return [int(row["epoch"]) for row in rows]

    def group_history(self, group_id: str, limit: int = 50) -> list[MessageRecord]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM messages WHERE group_id = ? ORDER BY timestamp DESC LIMIT ?",
                (group_id, limit),
            ).fetchall()
        return [self._message_from_row(row) for row in reversed(rows)]

    # -- egress queue ----------------------------------------------------

    def enqueue_egress(
        self, group_id: str, recipient_hash: bytes, msg_hash: bytes, not_before: float = 0.0
    ) -> bool:
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO egress_queue"
                " (group_id, recipient_hash, msg_hash, attempts, next_attempt_at, created_at)"
                " VALUES (?, ?, ?, 0, ?, ?)",
                (group_id, recipient_hash, msg_hash, max(now, not_before), now),
            )
            self._db.commit()
        return cursor.rowcount > 0

    def due_egress(self, limit: int, now: float | None = None) -> list[EgressItem]:
        now = time.time() if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM egress_queue WHERE next_attempt_at <= ?"
                " ORDER BY next_attempt_at, id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            EgressItem(
                item_id=row["id"],
                group_id=row["group_id"],
                recipient_hash=row["recipient_hash"],
                msg_hash=row["msg_hash"],
                attempts=row["attempts"],
                graces=row["graces"],
            )
            for row in rows
        ]

    def egress_depth(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) AS depth FROM egress_queue").fetchone()
        return int(row["depth"])

    def complete_egress(self, item_id: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM egress_queue WHERE id = ?", (item_id,))
            self._db.commit()

    def defer_egress(self, item_id: int, delay: float, count_attempt: bool = True) -> None:
        """Re-arm a queue row.

        A counted deferral is a real delivery attempt and resets the grace
        counter, since the recipient's path was known this time round. An
        uncounted one is a grace: it advances ``graces`` so the wait before the
        next path request can grow.
        """
        self._defer("egress_queue", item_id, delay, count_attempt)

    # -- peers -----------------------------------------------------------

    def record_peer_sync(self, peer_hash: bytes, error: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO peers (peer_hash, last_sync_at, last_error) VALUES (?, ?, ?)"
                " ON CONFLICT (peer_hash) DO UPDATE SET"
                " last_sync_at = excluded.last_sync_at, last_error = excluded.last_error",
                (peer_hash, time.time(), error),
            )
            self._db.commit()

    def peer_state(self, peer_hash: bytes) -> tuple[float, str | None] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT last_sync_at, last_error FROM peers WHERE peer_hash = ?", (peer_hash,)
            ).fetchone()
        return (row["last_sync_at"], row["last_error"]) if row else None

    def record_peer_success(self, peer_hash: bytes, now: float | None = None) -> None:
        """Note that a peer answered. This is the only liveness evidence there is."""
        now = time.time() if now is None else now
        with self._lock:
            self._db.execute(
                "INSERT INTO peer_liveness (peer_hash, last_success_at) VALUES (?, ?)"
                " ON CONFLICT (peer_hash) DO UPDATE SET last_success_at = excluded.last_success_at",
                (peer_hash, now),
            )
            self._db.commit()

    def peer_last_success(self, peer_hash: bytes) -> float | None:
        with self._lock:
            row = self._db.execute(
                "SELECT last_success_at FROM peer_liveness WHERE peer_hash = ?", (peer_hash,)
            ).fetchone()
        return row["last_success_at"] if row else None

    # -- peer state gossip -----------------------------------------------

    def record_peer_state(
        self,
        peer_hash: bytes,
        hub_name: str,
        groups: dict[str, tuple[bytes, str]],
        members: dict[str, list[bytes]],
    ) -> None:
        """Replace what we know a peer serves, in one transaction.

        Replacing rather than merging matters: a group unregistered or a member
        removed on the peer has to disappear here too, or a standby would keep
        serving somebody the other operator ejected.
        """
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM peer_groups WHERE peer_hash = ?", (peer_hash,))
            self._db.execute("DELETE FROM peer_members WHERE peer_hash = ?", (peer_hash,))
            self._db.executemany(
                "INSERT INTO peer_groups"
                " (peer_hash, group_id, destination_hash, hub_name, acl_mode, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (peer_hash, group_id, destination, hub_name, acl_mode, now)
                    for group_id, (destination, acl_mode) in groups.items()
                ],
            )
            self._db.executemany(
                "INSERT INTO peer_members (peer_hash, group_id, user_hash, updated_at)"
                " VALUES (?, ?, ?, ?)",
                [
                    (peer_hash, group_id, user_hash, now)
                    for group_id, user_hashes in members.items()
                    for user_hash in user_hashes
                ],
            )
            self._db.commit()

    def list_peer_groups(self, group_id: str | None = None) -> list[PeerGroup]:
        query = "SELECT * FROM peer_groups"
        params: list[object] = []
        if group_id is not None:
            query += " WHERE group_id = ?"
            params.append(group_id)
        query += " ORDER BY group_id, hub_name"
        with self._lock:
            rows = self._db.execute(query, params).fetchall()
        return [
            PeerGroup(
                peer_hash=row["peer_hash"],
                group_id=row["group_id"],
                destination_hash=row["destination_hash"],
                hub_name=row["hub_name"],
                acl_mode=row["acl_mode"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    def list_peer_members(self, peer_hash: bytes, group_id: str) -> list[bytes]:
        with self._lock:
            rows = self._db.execute(
                "SELECT user_hash FROM peer_members WHERE peer_hash = ? AND group_id = ?",
                (peer_hash, group_id),
            ).fetchall()
        return [row["user_hash"] for row in rows]

    def is_peer_member(self, group_id: str, user_hash: bytes) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM peer_members WHERE group_id = ? AND user_hash = ? LIMIT 1",
                (group_id, user_hash),
            ).fetchone()
        return row is not None

    # -- adoptions -------------------------------------------------------

    def adopt(self, peer_hash: bytes, group_id: str, user_hashes: Sequence[bytes]) -> list[bytes]:
        """Start serving a peer's members. Returns the ones newly adopted."""
        adopted = []
        now = time.time()
        with self._lock:
            for user_hash in user_hashes:
                cursor = self._db.execute(
                    "INSERT OR IGNORE INTO adoptions (peer_hash, group_id, user_hash, adopted_at)"
                    " VALUES (?, ?, ?, ?)",
                    (peer_hash, group_id, user_hash, now),
                )
                if cursor.rowcount > 0:
                    adopted.append(user_hash)
            self._db.commit()
        return adopted

    def release_peer(self, peer_hash: bytes) -> list[tuple[str, bytes]]:
        """Stop serving a peer's members. Returns what was released."""
        with self._lock:
            rows = self._db.execute(
                "SELECT group_id, user_hash FROM adoptions WHERE peer_hash = ?", (peer_hash,)
            ).fetchall()
            self._db.execute("DELETE FROM adoptions WHERE peer_hash = ?", (peer_hash,))
            self._db.commit()
        return [(row["group_id"], row["user_hash"]) for row in rows]

    def adopted_peers(self) -> list[bytes]:
        with self._lock:
            rows = self._db.execute("SELECT DISTINCT peer_hash FROM adoptions").fetchall()
        return [row["peer_hash"] for row in rows]

    def list_adopted(self, group_id: str) -> list[bytes]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT user_hash FROM adoptions WHERE group_id = ?", (group_id,)
            ).fetchall()
        return [row["user_hash"] for row in rows]

    def adopted_for_peer(self, peer_hash: bytes, group_id: str) -> list[bytes]:
        """The members of one peer's group this hub is currently serving."""
        with self._lock:
            rows = self._db.execute(
                "SELECT user_hash FROM adoptions WHERE peer_hash = ? AND group_id = ?",
                (peer_hash, group_id),
            ).fetchall()
        return [row["user_hash"] for row in rows]

    def is_adopted(self, group_id: str, user_hash: bytes) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM adoptions WHERE group_id = ? AND user_hash = ? LIMIT 1",
                (group_id, user_hash),
            ).fetchone()
        return row is not None

    # -- notice queue ----------------------------------------------------

    def enqueue_notice(
        self,
        group_id: str,
        recipient_hash: bytes,
        body: str,
        source: str = SOURCE_GROUP,
    ) -> bool:
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO notice_queue"
                " (source, group_id, recipient_hash, body, attempts, next_attempt_at, created_at)"
                " VALUES (?, ?, ?, ?, 0, ?, ?)",
                (source, group_id, recipient_hash, body, now, now),
            )
            self._db.commit()
        return cursor.rowcount > 0

    def due_notices(self, limit: int, now: float | None = None) -> list[NoticeItem]:
        now = time.time() if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM notice_queue WHERE next_attempt_at <= ?"
                " ORDER BY next_attempt_at, id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            NoticeItem(
                item_id=row["id"],
                source=row["source"],
                group_id=row["group_id"],
                recipient_hash=row["recipient_hash"],
                body=row["body"],
                attempts=row["attempts"],
                graces=row["graces"],
            )
            for row in rows
        ]

    def notice_depth(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) AS depth FROM notice_queue").fetchone()
        return int(row["depth"])

    def complete_notice(self, item_id: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM notice_queue WHERE id = ?", (item_id,))
            self._db.commit()

    def defer_notice(self, item_id: int, delay: float, count_attempt: bool = True) -> None:
        self._defer("notice_queue", item_id, delay, count_attempt)

    # -- control queue ---------------------------------------------------

    def enqueue_control(self, recipient_hash: bytes, body: str) -> int:
        """Queue an answer to an operator command. Never deduplicated."""
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO control_queue"
                " (recipient_hash, body, attempts, next_attempt_at, created_at)"
                " VALUES (?, ?, 0, ?, ?)",
                (recipient_hash, body, now, now),
            )
            self._db.commit()
        return int(cursor.lastrowid or 0)

    def due_control(self, limit: int, now: float | None = None) -> list[ControlItem]:
        now = time.time() if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM control_queue WHERE next_attempt_at <= ?"
                " ORDER BY next_attempt_at, id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            ControlItem(
                item_id=row["id"],
                recipient_hash=row["recipient_hash"],
                body=row["body"],
                attempts=row["attempts"],
                graces=row["graces"],
            )
            for row in rows
        ]

    def control_depth(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) AS depth FROM control_queue").fetchone()
        return int(row["depth"])

    def complete_control(self, item_id: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM control_queue WHERE id = ?", (item_id,))
            self._db.commit()

    def defer_control(self, item_id: int, delay: float, count_attempt: bool = True) -> None:
        self._defer("control_queue", item_id, delay, count_attempt)

    # -- user answer queue -----------------------------------------------

    def enqueue_user(self, group_id: str, recipient_hash: bytes, body: str) -> int:
        """Queue an answer to a member's own command. Never deduplicated."""
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO user_queue"
                " (group_id, recipient_hash, body, attempts, next_attempt_at, created_at)"
                " VALUES (?, ?, ?, 0, ?, ?)",
                (group_id, recipient_hash, body, now, now),
            )
            self._db.commit()
        return int(cursor.lastrowid or 0)

    def due_user(self, limit: int, now: float | None = None) -> list[UserItem]:
        now = time.time() if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM user_queue WHERE next_attempt_at <= ?"
                " ORDER BY next_attempt_at, id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            UserItem(
                item_id=row["id"],
                group_id=row["group_id"],
                recipient_hash=row["recipient_hash"],
                body=row["body"],
                attempts=row["attempts"],
                graces=row["graces"],
            )
            for row in rows
        ]

    def user_depth(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) AS depth FROM user_queue").fetchone()
        return int(row["depth"])

    def complete_user(self, item_id: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM user_queue WHERE id = ?", (item_id,))
            self._db.commit()

    def defer_user(self, item_id: int, delay: float, count_attempt: bool = True) -> None:
        self._defer("user_queue", item_id, delay, count_attempt)

    # -- personas --------------------------------------------------------

    def create_persona(
        self,
        persona_id: bytes,
        name: str | None,
        user_hash: bytes,
        claimed_at: float | None = None,
    ) -> PersonaRecord:
        """Mint a persona and attach its first device, in one transaction.

        A persona with no device is unreachable and a device attached to a
        persona that does not exist resolves to nothing, so neither half is ever
        committed alone.
        """
        now = time.time()
        claimed_at = now if claimed_at is None else claimed_at
        record = PersonaRecord(
            persona_id=persona_id,
            name=name,
            claimed_at=claimed_at,
            revision=1,
            updated_at=now,
        )
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO personas"
                    " (persona_id, name, name_folded, claimed_at, revision, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (persona_id, name, fold_name(name), claimed_at, 1, now),
                )
                self._db.execute(
                    "INSERT INTO persona_identities (user_hash, persona_id, added_at, removed_at)"
                    " VALUES (?, ?, ?, NULL)"
                    " ON CONFLICT (user_hash) DO UPDATE SET"
                    " persona_id = excluded.persona_id, added_at = excluded.added_at,"
                    " removed_at = NULL",
                    (user_hash, persona_id, now),
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return record

    def get_persona(self, persona_id: bytes) -> PersonaRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM personas WHERE persona_id = ?", (persona_id,)
            ).fetchone()
        return _persona_from_row(row) if row else None

    def persona_by_name(self, name: str) -> PersonaRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM personas WHERE name_folded = ?", (fold_name(name),)
            ).fetchone()
        return _persona_from_row(row) if row else None

    def persona_for_identity(self, user_hash: bytes) -> PersonaRecord | None:
        """The persona a device belongs to, ignoring unlinked ones."""
        with self._lock:
            row = self._db.execute(
                "SELECT personas.* FROM personas"
                " JOIN persona_identities USING (persona_id)"
                " WHERE persona_identities.user_hash = ?"
                " AND persona_identities.removed_at IS NULL",
                (user_hash,),
            ).fetchone()
        return _persona_from_row(row) if row else None

    def list_personas(self) -> list[PersonaRecord]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM personas ORDER BY name_folded IS NULL, name_folded"
            ).fetchall()
        return [_persona_from_row(row) for row in rows]

    def persona_devices(
        self, persona_id: bytes, include_removed: bool = False
    ) -> list[PersonaIdentity]:
        query = "SELECT * FROM persona_identities WHERE persona_id = ?"
        if not include_removed:
            query += " AND removed_at IS NULL"
        with self._lock:
            rows = self._db.execute(query + " ORDER BY added_at", (persona_id,)).fetchall()
        return [_identity_from_row(row) for row in rows]

    def display_name_for(self, user_hash: bytes) -> str | None:
        """The username to attribute a message to, or None for an unnamed device."""
        persona = self.persona_for_identity(user_hash)
        return persona.name if persona is not None else None

    def set_persona_name(
        self,
        persona_id: bytes,
        name: str | None,
        revision: int | None = None,
        updated_at: float | None = None,
    ) -> None:
        """Rename a persona, or clear its name with ``None``.

        The revision is bumped unless one is supplied, which is what a federation
        merge does when it is replaying a peer's revision rather than making a
        change of its own.
        """
        now = time.time() if updated_at is None else updated_at
        with self._lock:
            if revision is None:
                self._db.execute(
                    "UPDATE personas SET name = ?, name_folded = ?, revision = revision + 1,"
                    " updated_at = ? WHERE persona_id = ?",
                    (name, fold_name(name), now, persona_id),
                )
            else:
                self._db.execute(
                    "UPDATE personas SET name = ?, name_folded = ?, revision = ?,"
                    " updated_at = ? WHERE persona_id = ?",
                    (name, fold_name(name), revision, now, persona_id),
                )
            self._db.commit()

    def upsert_persona(self, record: PersonaRecord) -> None:
        """Write a peer's persona row verbatim, for federation merges."""
        with self._lock:
            self._db.execute(
                "INSERT INTO personas"
                " (persona_id, name, name_folded, claimed_at, revision, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (persona_id) DO UPDATE SET"
                " name = excluded.name, name_folded = excluded.name_folded,"
                " claimed_at = excluded.claimed_at, revision = excluded.revision,"
                " updated_at = excluded.updated_at",
                (
                    record.persona_id,
                    record.name,
                    record.name_folded,
                    record.claimed_at,
                    record.revision,
                    record.updated_at,
                ),
            )
            self._db.commit()

    def link_identity(
        self, persona_id: bytes, user_hash: bytes, added_at: float | None = None
    ) -> None:
        """Attach a device to a persona, moving it off any previous one."""
        now = time.time() if added_at is None else added_at
        with self._lock:
            self._db.execute(
                "INSERT INTO persona_identities (user_hash, persona_id, added_at, removed_at)"
                " VALUES (?, ?, ?, NULL)"
                " ON CONFLICT (user_hash) DO UPDATE SET"
                " persona_id = excluded.persona_id, added_at = excluded.added_at,"
                " removed_at = NULL",
                (user_hash, persona_id, now),
            )
            self._db.commit()

    def unlink_identity(self, user_hash: bytes, removed_at: float | None = None) -> bool:
        """Tombstone a device. Returns False if it was not linked."""
        now = time.time() if removed_at is None else removed_at
        with self._lock:
            cursor = self._db.execute(
                "UPDATE persona_identities SET removed_at = ?"
                " WHERE user_hash = ? AND removed_at IS NULL",
                (now, user_hash),
            )
            self._db.commit()
        return cursor.rowcount > 0

    def upsert_persona_identity(self, row: PersonaIdentity) -> None:
        """Write a peer's device row verbatim, tombstone included."""
        with self._lock:
            self._db.execute(
                "INSERT INTO persona_identities (user_hash, persona_id, added_at, removed_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (user_hash) DO UPDATE SET"
                " persona_id = excluded.persona_id, added_at = excluded.added_at,"
                " removed_at = excluded.removed_at",
                (row.user_hash, row.persona_id, row.added_at, row.removed_at),
            )
            self._db.commit()

    def list_persona_identities(self) -> list[PersonaIdentity]:
        """Every device row including tombstones, for federation."""
        with self._lock:
            rows = self._db.execute("SELECT * FROM persona_identities").fetchall()
        return [_identity_from_row(row) for row in rows]

    def get_persona_identity(self, user_hash: bytes) -> PersonaIdentity | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM persona_identities WHERE user_hash = ?", (user_hash,)
            ).fetchone()
        return _identity_from_row(row) if row else None

    # -- device link codes -----------------------------------------------

    def create_link_code(self, code: str, persona_id: bytes, expires_at: float) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO persona_links (code, persona_id, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (code) DO UPDATE SET"
                " persona_id = excluded.persona_id, created_at = excluded.created_at,"
                " expires_at = excluded.expires_at",
                (code, persona_id, time.time(), expires_at),
            )
            self._db.commit()

    def claim_link_code(self, code: str, now: float | None = None) -> bytes | None:
        """Spend a link code. Returns the persona it belonged to, or None.

        The delete and the read are one transaction, so two devices racing on the
        same code cannot both join: the second one finds it spent.
        """
        now = time.time() if now is None else now
        with self._lock:
            try:
                row = self._db.execute(
                    "SELECT persona_id, expires_at FROM persona_links WHERE code = ?", (code,)
                ).fetchone()
                if row is None:
                    self._db.commit()
                    return None
                self._db.execute("DELETE FROM persona_links WHERE code = ?", (code,))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        if row["expires_at"] < now:
            return None
        return row["persona_id"]

    def create_unlink_code(self, code: str, persona_id: bytes, expires_at: float) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO persona_unlinks (code, persona_id, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (code) DO UPDATE SET"
                " persona_id = excluded.persona_id, created_at = excluded.created_at,"
                " expires_at = excluded.expires_at",
                (code, persona_id, time.time(), expires_at),
            )
            self._db.commit()

    def claim_unlink_code(self, code: str, now: float | None = None) -> bytes | None:
        now = time.time() if now is None else now
        with self._lock:
            try:
                row = self._db.execute(
                    "SELECT persona_id, expires_at FROM persona_unlinks WHERE code = ?", (code,)
                ).fetchone()
                if row is None:
                    self._db.commit()
                    return None
                self._db.execute("DELETE FROM persona_unlinks WHERE code = ?", (code,))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        if row["expires_at"] < now:
            return None
        return row["persona_id"]

    def prune_link_codes(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            cursor = self._db.execute("DELETE FROM persona_links WHERE expires_at < ?", (now,))
            self._db.commit()
        return cursor.rowcount

    def prune_unlink_codes(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            cursor = self._db.execute("DELETE FROM persona_unlinks WHERE expires_at < ?", (now,))
            self._db.commit()
        return cursor.rowcount

    def groups_for_member(self, user_hash: bytes) -> list[str]:
        """Groups a device is a member of, so an answer has a source to go out from."""
        with self._lock:
            rows = self._db.execute(
                "SELECT group_id FROM members WHERE user_hash = ? AND role != ? ORDER BY group_id",
                (user_hash, ROLE_BANNED),
            ).fetchall()
        return [row["group_id"] for row in rows]

    # -- shared queue helpers --------------------------------------------

    def _defer(self, table: str, item_id: int, delay: float, count_attempt: bool) -> None:
        if table not in QUEUE_TABLES:
            raise ValueError(f"'{table}' is not a queue table")
        if count_attempt:
            # A transmission happened, so the path was known: forget the graces.
            assignment = "attempts = attempts + 1, graces = 0"
        else:
            assignment = "graces = graces + 1"
        with self._lock:
            self._db.execute(
                f"UPDATE {table} SET {assignment}, next_attempt_at = ? WHERE id = ?",
                (time.time() + delay, item_id),
            )
            self._db.commit()

    # -- flags -----------------------------------------------------------

    def get_flag(self, key: str) -> bool:
        return self._meta_get(f"flag_{key}") == b"1"

    def set_flag(self, key: str, value: bool) -> None:
        self._meta_set(f"flag_{key}", b"1" if value else b"0")

    def _group_from_row(self, row: sqlite3.Row) -> GroupRecord:
        return GroupRecord(
            group_id=row["group_id"],
            display_name=row["display_name"],
            identity_key=self._decode(row["identity_key"]),
            created_at=row["created_at"],
            acl_mode=row["acl_mode"],
        )

    def _message_from_row(self, row: sqlite3.Row) -> MessageRecord:
        return MessageRecord(
            msg_hash=row["msg_hash"],
            group_id=row["group_id"],
            sender_hash=row["sender_hash"],
            timestamp=row["timestamp"],
            payload=self._decode(row["lxmf_payload_blob"]),
            origin=row["origin"],
        )

    # -- retention -------------------------------------------------------

    def prune_messages(self, older_than: float) -> int:
        """Drop aged-out messages and any queue rows that referenced them.

        The egress rows have to go in the same transaction: a row whose message
        is gone can never be delivered, and leaving it behind means the scheduler
        keeps picking it up, spending a slot in every batch until it notices the
        message is missing.
        """
        with self._lock:
            cursor = self._db.execute("DELETE FROM messages WHERE timestamp < ?", (older_than,))
            self._db.execute(
                "DELETE FROM egress_queue WHERE msg_hash NOT IN (SELECT msg_hash FROM messages)"
            )
            self._db.commit()
        return cursor.rowcount


def _persona_from_row(row: sqlite3.Row) -> PersonaRecord:
    return PersonaRecord(
        persona_id=row["persona_id"],
        name=row["name"],
        claimed_at=row["claimed_at"],
        revision=row["revision"],
        updated_at=row["updated_at"],
    )


def _identity_from_row(row: sqlite3.Row) -> PersonaIdentity:
    return PersonaIdentity(
        user_hash=row["user_hash"],
        persona_id=row["persona_id"],
        added_at=row["added_at"],
        removed_at=row["removed_at"],
    )


def _chunks(items: list[bytes], size: int) -> Iterable[list[bytes]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]
