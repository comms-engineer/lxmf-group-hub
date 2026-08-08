# LXMF Federated Group Hub

A headless group chat server for the [Reticulum Network Stack](https://reticulum.network). Each group gets its own RNS identity and its own inbound LXMF delivery destination, announced on a 30 minute interval, so Sideband, NomadNet, and MeshChat see a group as an ordinary contact in their address book. A member sends a normal LXMF message to that destination. The hub verifies the Ed25519 signature RNS already checked while unpacking the message, stores it once, and reflects it to the rest of the group.

No slash commands. No bot syntax. No client patches. Group membership is a list of LXMF destination hashes in a SQLite table, and the only thing that decides whether a message is accepted is whose key signed it.

## Message path

```
     LoRa / RF, 1-5 kbps                        TCP / I2P / WireGuard, 1Mbps+
client ──LXMF──▶ group destination ──▶ store ──▶ egress queue ──▶ client
                        │                │        (token bucket,
                        │                │         propagation node)
                        └── ACL check    └──▶ Merkle epochs ◀──RNS Link/Resource──▶ peer hub
```

The two sides of that diagram get opposite treatment. A client on 915MHz LoRa gets one message every two seconds at the default rate, released from a queue that survives a `kill -9`. A peer hub on TCP gets a 256 message batch in a single RNS Resource.

## Installation

```bash
pip install -e .
```

Python 3.9 or newer, plus `rns`, `lxmf`, and `msgpack`. Development is on rns 1.4.2 and lxmf 1.1.1, and CI runs the suite on Python 3.9 and 3.12. The hub reads the local Reticulum config at `~/.reticulum` unless `reticulum_config_path` says otherwise, so it inherits whatever interfaces the host already has.

## Creating a group and running the daemon

```bash
lxmf-hub --config hub.json create-group ops --name "Ops" --acl invite
lxmf-hub --config hub.json add-member ops <client_lxmf_destination_hash>
lxmf-hub --config hub.json run
```

`create-group` prints three tab-separated columns: the group id, the ACL mode, and the destination hash. That hash is what a member pastes into Sideband as a contact.

Administration is out of band by design, because in-band commands would mean parsing text from unauthenticated senders. Groups, ACLs, and roles live in SQLite; `create-group`, `add-member`, `remove-member`, `set-acl`, `groups`, `members`, and `status` all operate on the database directly and are safe to run while the daemon is up. A running daemon rescans the `groups` table every 30 seconds and attaches anything new, so a group created at 14:02 is announcing by 14:03 without a restart.

Two ACL modes exist. In an `invite` group, a message from a hash that isn't in `members` is logged and dropped. In a `public` group, the first signed message from an unknown hash enrolls that sender as `member`. Roles are `member`, `admin`, and `banned`; a `banned` hash can't post and is skipped during fan-out, so banning takes effect on the next message rather than at the next restart.

## Configuration

Every key is optional. The values below are the built-in defaults.

```json
{
  "storage_path": "~/.lxmf_hub",
  "reticulum_config_path": null,
  "hub_name": "LXMF Group Hub",
  "announce_interval_sec": 1800,
  "announce_jitter_sec": 60,
  "default_acl_mode": "invite",
  "author_field": 253,
  "author_prefix_in_content": true,
  "log_level": 4,
  "at_rest": { "mode": "keyfile", "keyfile": null },
  "egress": {
    "tokens_per_second": 0.5,
    "burst": 4,
    "max_attempts": 10,
    "retry_backoff_sec": 60,
    "retry_backoff_max_sec": 3600,
    "batch_size": 8,
    "prefer_propagation": true,
    "propagation_node": null,
    "stamp_cost": null,
    "path_request_grace_sec": 15
  },
  "federation": {
    "enabled": true,
    "peers": [],
    "sync_interval_sec": 300,
    "epoch_seconds": 3600,
    "merkle_depth": 8,
    "retention_epochs": 168,
    "link_timeout_sec": 30,
    "request_timeout_sec": 20,
    "max_fetch_batch": 256
  }
}
```

Unknown keys raise `ValueError` at load time instead of being ignored, so a typo like `"storaeg_path"` fails on startup rather than silently sending your database somewhere else. `hub.example.json` holds a working file.

## Reflection and author attribution

A reflected message is a new LXMF message from the group destination to one member, not a forwarded copy of the original. Attribution rides in the LXMF fields dictionary under `author_field`, as a three-key dict:

```python
fields[253] = {
    "author": b"\xde\xef\x7e\xab...",  # the original sender's LXMF destination hash
    "group":  "ops",                   # the logical group id, identical on every hub
    "hub":    b"\xb1\x96\xe0\xeb...",  # the group destination this hub reflected from
}
```

The default index is `0xFD`, which LXMF defines as `FIELD_CUSTOM_META`. The original spec for this project called for `Fields[0x01]`, and that index is taken: LXMF assigns `0x01` to `FIELD_EMBEDDED_LXMS`, so a client that honors the spec will try to parse the attribution dict as a list of embedded messages. Set `"author_field": 1` if your clients expect it there anyway.

Clients that render only text still need to know who wrote what, so `author_prefix_in_content` prepends the sender's hash to the body. The prefix is applied when the reflection is built, not when the message is stored, which keeps the stored payload byte-identical to what the author sent and keeps the message hash stable across hubs.

Any value a sender puts in field 253 is stripped before storage. Otherwise a member could hand-craft a message claiming to come from an admin.

## Deduplication

`msg_hash` is the SHA-256 of four concatenated values: the SHA-256 of the group id string, the sender's destination hash, the timestamp packed as an 8-byte big-endian IEEE 754 double, and the msgpack payload blob holding the timestamp, title, content, and fields. It's the `messages` primary key, and inserts run as `INSERT OR IGNORE`, so a replay costs one failed insert and nothing else.

The group id goes into the hash, not the group's destination hash. This matters for federation: three hubs hosting group `ops` each hold a different RNS identity for it, and hashing the identity would give the same message three different ids and break every Merkle comparison. Hashing the string `ops` gives all three hubs the same id for the same message.

The timestamp is part of the identity, so two sends of the same text are two messages. That's deliberate. Dedup exists to make federation ingest idempotent and to absorb replays, not to suppress a member who says "ok" twice.

## Client egress

Nothing is broadcast, and nothing is sent straight from the delivery callback. Fan-out writes one row per recipient into `egress_queue`, keyed `UNIQUE (recipient_hash, msg_hash)`, and a scheduler thread drains it.

Delivery is gated by a token bucket that refills at `tokens_per_second`. At the defaults, 0.5 tokens per second with a burst of 4, one message to a 20 member group takes 32 seconds to clear: 4 deliveries go out on the accumulated burst, the remaining 16 at one every two seconds. On the local testnet a 24 item fan-out configured at 1.0 tokens per second queued in under 3 seconds and delivered over 23. That pacing is the whole point on a shared 915MHz interface.

Where a delivery goes depends on `prefer_propagation`. With a `propagation_node` hash configured, reflections are queued at that `lxmd` instance and the client picks them up when it next syncs, which suits nodes that are powered up for ten minutes a day. Without one, the message goes out as a direct LXMF delivery.

Three failure paths get separate handling:

* No known identity for the recipient. The hub calls `RNS.Transport.request_path` once and defers the item by `path_request_grace_sec`, 15 seconds, without counting an attempt. An unreachable member can't burn through `max_attempts` while their radio is off.
* Delivery failure. The item is deferred by `retry_backoff_sec * 2**attempts`, so retries land at 60s, 120s, 240s, and so on to the 3600 second ceiling, and are abandoned after 10 attempts.
* Daemon death mid-transfer. The item is re-armed in SQLite *before* `handle_outbound` is called, and only the LXMF delivery callback removes it. A `kill -9` between those two points leaves the row queued, and the next start picks it up. Verified on the testnet: queue depth 1, `kill -9`, depth still 1 while down, `Hub running with 1 group(s) and 1 queued delivery item(s)` on restart, delivery completed, depth 0.

## Federation by Merkle anti-entropy

Peer hubs are assumed to sit on TCP, I2P, or WireGuard interfaces at 1Mbps or better, so reconciliation is allowed to be chatty and moves data in bulk.

Every message hash falls into an epoch, `int(timestamp / 3600)` by default, and each epoch gets a Merkle tree. Leaves are buckets of the hash space rather than positions in a sorted list: at `merkle_depth` 8 there are 256 leaves, and bucket `i` holds every hash whose first 8 bits equal `i`. Sorted-list indices would have been cheaper to compute and useless, because leaf 12 on a hub holding 40 messages and leaf 12 on a hub holding 4,000 would cover different messages. Prefix buckets mean index 12 covers the same slice of hash space on every hub in the mesh.

A sync round every `sync_interval_sec` opens an RNS Link, identifies with the hub identity, and runs four requests:

| Path | Request | Response |
| --- | --- | --- |
| `/fed/roots` | protocol version, epoch length, tree depth | per-group, per-epoch Merkle roots, up to 512 epochs |
| `/fed/tree` | group, epoch, level, node indices | node hashes at that level, up to 1024 per request |
| `/fed/bucket` | group, epoch, leaf indices | message hashes in those buckets, up to 64 buckets |
| `/fed/fetch` | group, message hashes | count, then an RNS Resource carrying the batch |

Only epochs whose roots differ are walked, and the walk descends 8 levels asking for the children of nodes that disagree. Missing hashes are fetched in batches of 256 as `RNS.Resource` payloads, never as individual LXMF packets, then ingested with the same `INSERT OR IGNORE` path local messages use and fanned out to local members.

Peering is mutual and explicit. A request from an identity whose federation destination hash isn't in `federation.peers` is refused, and `epoch_seconds` and `merkle_depth` have to match on both sides or the peer returns a null root set and logs that the parameters were rejected. Hubs don't need to share an at-rest encryption key, since hashes are computed over plaintext.

Backfill falls out of the same mechanism. A hub joining a group that already has history holds an empty tree, so every populated epoch diverges at the root and gets pulled in full. On the testnet, hub c started after hub a already held 3 messages, logged `Ingested 3 message(s)`, and delivered all three to its local member.

`retention_epochs` bounds history at both ends: 168 hourly epochs is 7 days, older messages are pruned hourly, and epochs older than the window are skipped during sync so a pruned hub doesn't re-download what it just deleted.

## Encryption at rest

`messages.lxmf_payload_blob` and `groups.identity_key` are encrypted before they reach SQLite, using the AES-256-CBC and HMAC token construct from `RNS.Cryptography`. Group private keys matter as much as the message bodies: whoever holds one can impersonate the group destination.

Three modes:

* `keyfile`, the default. A 64-byte key is generated in `storage_path` on first run and written with mode 0600.
* `passphrase`. The key is derived with HKDF from `LXMF_HUB_DB_KEY` and a per-database salt in the `meta` table, so the key never lands on the same disk as the database.
* `none`. Values are stored as plaintext.

Every encryptable column carries a one byte frame, `0x00` for plaintext and `0x01` for ciphertext, and the `meta` table holds a canary value. Point a `keyfile` daemon at a database written with a different key and it fails at startup instead of returning garbage; point a `none` daemon at an encrypted database and it says so.

This protects a stolen disk, a copied backup, or a decommissioned SD card. It does not protect a live compromised host, because the daemon holds the key in memory for as long as it runs. Root on a running hub reads group traffic either way.

## Crash consistency

SQLite runs with `journal_mode=WAL`, `synchronous=NORMAL`, and `busy_timeout=30000`. Every state transition is committed before it's acted on, which is what makes the egress guarantee above hold: the queue row exists on disk before the message is handed to the router, and the peer sync timestamp is written after the ingest that earned it.

## Tests

```bash
pytest -q      # 57 tests
ruff check .
```

The suite covers WAL mode, dedup, hub-independent hashing, ACL enforcement for all three roles, author-field stripping, token bucket pacing, backoff growth and its ceiling, attempt capping, propagation versus direct method selection, wrong-key detection, exact Merkle traversal against a known missing set, multi-epoch backfill, and peer rejection on mismatched parameters.

`tools/local_testnet.py` runs each role as a separate Reticulum instance over localhost TCP, with its own config directory, its own TCP interface, and `share_instance = No`, so reflection, egress, and federation are exercised over real RNS packets rather than in-process fakes:

```bash
python tools/local_testnet.py hub    --name a --port 4242 --group ops --public
python tools/local_testnet.py client --name bob   --connect 4242
python tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>
```

Hub b joins the federation with `--port 4243 --connect 4242 --peer <hub_a_federation_hash>`, where that hash is printed at hub a's startup. Set `TESTNET_LOGLEVEL=7` for per-message hub and federation output.

## Licence

MIT. See [LICENSE](LICENSE).
