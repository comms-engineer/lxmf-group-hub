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

`status` prints the group count, the egress queue depth, and, when `operator_identity` is set, the control destination hash operators address.

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
  "operator_identity": null,
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
  },
  "failover": {
    "enabled": true,
    "peer_timeout_sec": 1800,
    "check_interval_sec": 60,
    "notify_clients": true,
    "notify_isolation": true
  },
  "directory": {
    "enabled": true,
    "min_reply_interval_sec": 60
  }
}
```

Unknown keys raise `ValueError` at load time instead of being ignored, so a typo like `"storaeg_path"` fails on startup rather than silently sending your database somewhere else. `hub.example.json` holds a working file.

## Operator control over LXMF

`operator_identity` takes an LXMF destination hash, or a list of them, and brings up a control destination on the hub identity. It's a separate destination from every group, so group traffic never carries commands and members never see an admin surface. Authorisation is the same Ed25519 signature check the group path uses, against a fixed list of hashes. No password, no token, no session.

```json
{ "operator_identity": ["8f1c0d7a4b2e6f9081c3d5a7b9e1f3c5"] }
```

Commands are the CLI verbs, sent as ordinary message text from an allowed hash:

```
groups                          ->  ops   invite   3 member(s)   b196e0eb...
create-group nets --acl public  ->  nets  public   7d41c9a2...
add-member ops 8f1c0d7a...      ->  8f1c0d7a... is member in ops
status                          ->  groups 2, egress_queue 0, notice_queue 0, control 707a7f49...
peers                           ->  9d2f0c81... last answered 4m ago   3 member(s) known
                                      ops   Standby Hub   7d41c9a2...
```

`create-group`, `groups`, `set-acl`, `add-member`, `remove-member`, `members`, `status`, and `peers` are reachable. `run` is not, and anything outside that set comes back as a list of what is. Argument errors, unknown groups, and malformed hashes are answered as text instead of raising, because there's no terminal on the other end to read a traceback. Commands write to SQLite and the daemon hot-loads them, so a group created from a phone is announcing within 30 seconds.

A message on the control destination from a hash that isn't an operator, or one whose signature didn't validate, is logged at notice level and dropped with no reply. Replies go out directly rather than through the client egress queue, since two packets to one operator shouldn't spend tokens meant for keeping group reflections off a saturated RF interface.

The control hash comes from `lxmf-hub status` or the startup log line `Operator control on <707a7f49...>`.

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

Groups don't propagate with the peering. A hub reconciles only the group ids it already hosts locally, and records for anything else are dropped on ingest, so a group an operator creates on one hub stays there until an operator on the other hub creates the same id. A hub added to an existing federation starts empty and pulls history only for the groups its own operator asked for. Peering isn't transitive either: naming hub B doesn't federate you with B's peers, because B's peers check their own lists and don't have you on them.

The pairing is by RNS identity, but group identity is the group id string, so two operators who both call a group `ops` and later peer with each other for some other group would reconcile both. Peering is explicit enough that this takes a deliberate act, and a distinctive id avoids it entirely.

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

## When a hub goes offline

A group's destination hash comes from that hub's own identity, so the same group on two federated hubs has two addresses, and nothing in RNS or LXMF can tell an unmodified client to switch. What's built is the honest version of failover: the surviving hub keeps delivering, and tells the human where to post.

Each sync round now also exchanges `/fed/state`, where a hub reports its name, the groups it hosts, their destination hashes, and their member hashes. Liveness is the last round a peer actually answered, not the last one this hub tried, since a hub records every attempt including the failures. A peer silent for `peer_timeout_sec`, 1800 seconds or six sync intervals, is treated as down from this hub's point of view. That's local evidence, not a claim about the rest of the network.

Three things then happen, all of them queued in SQLite and paced by the same token bucket as reflections, so adopting 40 members doesn't dump 40 messages onto an RF interface:

* **Adoption.** For groups it hosts too, the surviving hub starts delivering to the silent peer's members and sends each one a line naming the address to post to. Their posts are accepted even in an invite-only group, because a member of the group on a peer is a member of the group; a locally banned hash stays banned. They keep receiving either way, so the switch only matters when they want to send.

  ```
  ops: your hub (Home Hub) has not answered this hub for 30m. Standby Hub is
  serving ops in the meantime. To post, add this contact: 7d41c9a2....
  You keep receiving messages here either way.
  ```

* **Hand-back.** The peer answers again, adoption rows are released, and the same members are told the original address is live. Adoption state lives in SQLite, so a restart in the middle of an outage neither re-notifies nor forgets: for the first `peer_timeout_sec` after startup a silent peer is neither up nor down, because this hub hasn't yet had as long to reach it as it gives itself before calling a peer dead. Nothing is adopted or released in that window.

* **Isolation.** When a hub can reach none of its peers, its own members are told that local traffic still works but may not be crossing to the other hubs, with the other hubs' addresses for that group and how long ago each was seen. Both directions of that transition are announced once, not once per check.

The overlap is worth stating plainly: while two hubs are serving the same member, a message can arrive twice, because dedup is per hub on ingest and neither hub dedups on the client's behalf. A member who adds the standby and keeps the original contact will see duplicates for the length of the outage.

## Endpoint directory

An announce carries one destination and says nothing about the others, so there's a separate LXMF destination that answers any signed message with the endpoints this hub knows about. It runs on its own identity, since the hub identity's delivery destination is already the operator control channel.

```
ops     invite  Example Hub  b196e0eb...  here
ops     invite  Standby Hub  7d41c9a2...  seen 5m ago
nets    public  Example Hub  9c2f4a10...  here
```

Peer lines come from `/fed/state` gossip, so the age is when this hub last heard that hub say so. It isn't a liveness check, and a listed address can be dead. Most clients have a ping or path tool, which settles that against the hash in the listing better than this hub can.

Answers are queued and paced like any other client egress, and repeat queries from the same hash inside `min_reply_interval_sec` are dropped, so the directory can't be used to make a hub transmit on demand. Unsigned messages are dropped. The listing covers 40 groups.

## What this doesn't do

Failover is a notice, not a redirect. A member has to add the standby contact themselves, and a client with no one at either address just fails in its own outbound queue as before. Transparent failover would need the group's private key on every hub, which trades the group's forward secrecy and blast radius for saving the member one paste; that isn't built.

Adoption also can't help a group only one hub hosts. A hub serves a silent peer's members only for group ids it hosts itself, since it has nowhere to reflect them otherwise.

## Crash consistency

SQLite runs with `journal_mode=WAL`, `synchronous=NORMAL`, and `busy_timeout=30000`. Every state transition is committed before it's acted on, which is what makes the egress guarantee above hold: the queue row exists on disk before the message is handed to the router, and the peer sync timestamp is written after the ingest that earned it.

## Tests

```bash
pytest -q      # 134 tests
ruff check .
```

The suite covers WAL mode, dedup, hub-independent hashing, ACL enforcement for all three roles, author-field stripping, token bucket pacing, backoff growth and its ceiling, attempt capping, propagation versus direct method selection, wrong-key detection, exact Merkle traversal against a known missing set, multi-epoch backfill, peer rejection on mismatched parameters, and the control path including refusal of non-operators, unsigned messages, and verbs outside the remote allowlist.

Failover and the directory add: liveness measured from answers rather than attempts, adoption restricted to locally hosted groups and idempotent across checks, peer members admitted to an invite-only group while banned hashes stay out, member sets withdrawn when a peer drops them, hand-back and both isolation transitions firing once each, notices surviving a reopen of the database, and directory listings, per-requester rate limiting, and unsigned queries.

`tools/local_testnet.py` runs each role as a separate Reticulum instance over localhost TCP, with its own config directory, its own TCP interface, and `share_instance = No`, so reflection, egress, and federation are exercised over real RNS packets rather than in-process fakes:

```bash
python tools/local_testnet.py hub    --name a --port 4242 --group ops --public
python tools/local_testnet.py client --name bob   --connect 4242
python tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>
```

Hub b joins the federation with `--port 4243 --connect 4242 --peer <hub_a_federation_hash>`, where that hash is printed at hub a's startup. Set `TESTNET_LOGLEVEL=7` for per-message hub and federation output.

## To-Do
- More robust operator commands, including help
- Per-user username setting, for message prefixes

## Licence

MIT. See [LICENSE](LICENSE).
