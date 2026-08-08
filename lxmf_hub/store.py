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

CREATE TABLE IF NOT EXISTS egress_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id        TEXT NOT NULL,
    recipient_hash  BLOB NOT NULL,
    msg_hash        BLOB NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
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
            self._db.commit()

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
        with self._lock:
            self._db.execute(
                "UPDATE egress_queue SET attempts = attempts + ?, next_attempt_at = ? WHERE id = ?",
                (1 if count_attempt else 0, time.time() + delay, item_id),
            )
            self._db.commit()

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
        with self._lock:
            cursor = self._db.execute("DELETE FROM messages WHERE timestamp < ?", (older_than,))
            self._db.commit()
        return cursor.rowcount


def _chunks(items: list[bytes], size: int) -> Iterable[list[bytes]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]
