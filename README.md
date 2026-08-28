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

**`<client_lxmf_destination_hash>` must be the member's LXMF address, not their RNS identity hash.** These are two different values a client derives from the same identity, and clients are inconsistent about which one they surface as "address," "identity hash," or "destination hash" in their UI. The hub authorises every inbound message against `message.source_hash`, which is the LXMF delivery destination hash -- the address a client would message the group *from*. An RNS identity hash added by mistake is stored but never matches anything, so the member it was meant to add stays unauthorised with no error to explain why.

The hub itself cannot hand this value back before the member is added: in an `invite` group a non-member's messages, including a `/whoami`, are dropped before authorisation, and the operator control channel only answers senders already on its own fixed list. So collect it from the member's own client -- Sideband, NomadNet, and MeshChat all have a screen showing your own LXMF address/identity -- and only rely on the in-band `/whoami` or `/status` for someone already admitted to a `public` group or already a member elsewhere on this hub.

Administration is out of band by design, because in-band commands would mean parsing text from unauthenticated senders. Groups, ACLs, and roles live in SQLite; `create-group`, `add-member`, `remove-member`, `set-acl`, `groups`, `members`, and `status` all operate on the database directly and are safe to run while the daemon is up. A running daemon rescans the `groups` table every 30 seconds and attaches anything new, so a group created at 14:02 is announcing by 14:03 without a restart.

`status` prints the group count, the egress, notice, and operator answer queue depths, and, when `operator_identity` is set, the control destination hash operators address. `operator_identity` itself takes the same kind of value as `add-member`: an operator's LXMF address, not their RNS identity hash.

Destination hashes are accepted in the shapes clients and RNS actually print them: `<8f1c0d7a...>`, `8f:1c:0d:7a:...`, `0x8f1c...`, or plain hex. A hash of the wrong length is refused rather than stored, since `bytes.fromhex` accepts a truncated paste happily and a member nothing can ever match looks exactly like a member who is offline.

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
    "path_request_grace_sec": 15,
    "delivery_timeout_sec": 600
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
  },
  "commands": {
    "enabled": true,
    "min_reply_interval_sec": 10
  }
}
```

Unknown keys raise `ValueError` at load time instead of being ignored, so a typo like `"storaeg_path"` fails on startup rather than silently sending your database somewhere else. `hub.example.json` holds a working file.

## Operator control over LXMF

`operator_identity` takes an LXMF destination hash, or a list of them, and brings up a control destination on the hub identity. It's a separate destination from every group, so group traffic never carries commands and members never see an admin surface. Authorisation is the same Ed25519 signature check the group path uses, against a fixed list of hashes. No password, no token, no session.

As with `add-member`, this is the operator's LXMF address (their own delivery destination hash), not their RNS identity hash. Get it from the operator's own client, or from `/whoami`/`/status` if they are already a member of a group on this hub -- the control destination itself won't answer them until `operator_identity` already contains their address.

```json
{ "operator_identity": ["8f1c0d7a4b2e6f9081c3d5a7b9e1f3c5"] }
```

Commands are the CLI verbs, sent as ordinary message text from an allowed hash:

```
groups                          ->  ops   invite   3 member(s)   b196e0eb...
create-group nets --acl public  ->  nets  public   7d41c9a2...
add-member ops 8f1c0d7a...      ->  8f1c0d7a... is member in ops
status                          ->  groups 2, egress_queue 0, notice_queue 0, control_queue 0, control 707a7f49...
peers                           ->  9d2f0c81... last answered 4m ago   3 member(s) known
                                      ops   Standby Hub   7d41c9a2...
```

`create-group`, `groups`, `set-acl`, `add-member`, `remove-member`, `members`, `status`, and `peers` are reachable. `run` is not, and anything outside that set comes back as a list of what is. Argument errors, unknown groups, and malformed hashes are answered as text instead of raising, because there's no terminal on the other end to read a traceback. Commands write to SQLite and the daemon hot-loads them, so a group created from a phone is announcing within 30 seconds.

The command line is read the way a phone produces it: the verb is case-insensitive, smart quotes are folded back to plain ones before parsing, and a line over 4096 bytes is refused. `help` lists every reachable verb with the usage argparse itself prints, and `help <command>` or `<command> --help` gives one command in full, so the help can't drift from the arguments the parser accepts.

A message on the control destination from a hash that isn't an operator, or one whose signature didn't validate, is logged at notice level and dropped with no reply. Answers are queued in `control_queue` and drained by the egress scheduler ahead of client traffic, without spending client tokens: an answer to a command that has already changed the database is worth the same retries, path requests, and restart survival as a reflection, and dropping it because the operator's path happened to be unknown that second is what makes the control channel look dead while it is working. Two identical answers are two rows, unlike notices, because two `status` commands deserve two replies.

The control hash comes from `lxmf-hub status` or the startup log line `Operator control on <707a7f49...>`.

## Reflection and author attribution

A reflected message is a new LXMF message from the group destination to one member, not a forwarded copy of the original. Attribution rides in the LXMF fields dictionary under `author_field`, as a four-key dict:

```python
fields[253] = {
    "author": b"\xde\xef\x7e\xab...",  # the original sender's LXMF destination hash
    "group":  "ops",                   # the logical group id, identical on every hub
    "hub":    b"\xb1\x96\xe0\xeb...",  # the group destination this hub reflected from
    "name":   "alice",                 # the sender's username, or None if they have none
}
```

`name` is a convenience, never an identity: it is whatever username the sender's persona holds at reflection time, and `author` stays on the message so a client that verifies authorship verifies a key, not a string. A sender with no username gets `None` and the hash-prefixed body clients already handle.

The default index is `0xFD`, which LXMF defines as `FIELD_CUSTOM_META`. The original spec for this project called for `Fields[0x01]`, and that index is taken: LXMF assigns `0x01` to `FIELD_EMBEDDED_LXMS`, so a client that honors the spec will try to parse the attribution dict as a list of embedded messages. Set `"author_field": 1` if your clients expect it there anyway.

Clients that render only text still need to know who wrote what, so `author_prefix_in_content` prepends the sender's username to the body, falling back to their hash when they have no username. The prefix is applied when the reflection is built, not when the message is stored, which keeps the stored payload byte-identical to what the author sent and keeps the message hash stable across hubs.

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

* No known identity for the recipient. The hub calls `RNS.Transport.request_path` and defers the item without counting an attempt, so an unreachable member can't burn through `max_attempts` while their radio is off. Those uncounted deferrals are counted separately as graces, and the wait doubles with each one from `path_request_grace_sec` up to the retry ceiling: a member who is off for a week is asked for with a growing backoff rather than every 15 seconds for a week.
* Delivery failure. The item is deferred by `retry_backoff_sec * 2**attempts`, so retries land at 60s, 120s, 240s, and so on to the 3600 second ceiling, and are abandoned after 10 attempts.
* Daemon death mid-transfer. The item is re-armed in SQLite *before* `handle_outbound` is called, and only the LXMF delivery callback removes it. A `kill -9` between those two points leaves the row queued, and the next start picks it up. Verified on the testnet: queue depth 1, `kill -9`, depth still 1 while down, `Hub running with 1 group(s) and 1 queued delivery item(s)` on restart, delivery completed, depth 0.

Re-arming before handoff is what makes a `kill -9` safe, and on its own it makes a slow delivery unsafe: LXMF retries a direct delivery five times ten seconds apart on top of link setup, which can outlast the backoff, and the scheduler would then send a second copy of a message still on its way. Rows handed to the router are therefore held in memory until a callback resolves them, for at most `delivery_timeout_sec`; past that they are offered again only once LXMF no longer holds the message, and a `handle_outbound` that raises releases the row immediately rather than waiting out the timeout for callbacks that will never fire. A token spent on a row that turns out to be undeliverable -- pruned message, detached group, attempts exhausted -- is refunded, so a batch of dead rows can't stall the messages behind them.

One delivery milestone is worth reading carefully in the logs. For a direct delivery, LXMF's callback means the recipient has the message. For a propagated one, it means the propagation node accepted it and the client will collect it when it next syncs, which is why those two cases are logged differently: a hub that reports "delivered" for messages sitting on a propagation node is the reason "it says delivered" and "I never got it" can both be true.

## Federation by Merkle anti-entropy

Peer hubs are assumed to sit on TCP, I2P, or WireGuard interfaces at 1Mbps or better, so reconciliation is allowed to be chatty and moves data in bulk.

Every message hash falls into an epoch, `int(timestamp / 3600)` by default, and each epoch gets a Merkle tree. Leaves are buckets of the hash space rather than positions in a sorted list: at `merkle_depth` 8 there are 256 leaves, and bucket `i` holds every hash whose first 8 bits equal `i`. Sorted-list indices would have been cheaper to compute and useless, because leaf 12 on a hub holding 40 messages and leaf 12 on a hub holding 4,000 would cover different messages. Prefix buckets mean index 12 covers the same slice of hash space on every hub in the mesh.

A sync round every `sync_interval_sec` opens an RNS Link, identifies with the hub identity, and runs four requests. The first round runs 15 seconds after startup rather than a full interval in, since a hub that just restarted is exactly the one that doesn't know what it missed. A group whose reconciliation raises is recorded as a sync error by name and skipped for that round only; the groups after it in the same round still reconcile, because a single wedged group stopping all federation is how a backlog becomes permanent.

| Path | Request | Response |
| --- | --- | --- |
| `/fed/roots` | protocol version, epoch length, tree depth | per-group, per-epoch Merkle roots, up to 512 epochs |
| `/fed/tree` | group, epoch, level, node indices | node hashes at that level, up to 1024 per request |
| `/fed/bucket` | group, epoch, leaf indices | message hashes in those buckets, up to 64 buckets |
| `/fed/fetch` | group, message hashes | count, then an RNS Resource carrying the batch |
| `/fed/personas` | protocol version | personas and device links, including unlink tombstones |

Only epochs whose roots differ are walked, and the walk descends 8 levels asking for the children of nodes that disagree. Missing hashes are fetched in batches of 256 as `RNS.Resource` payloads, never as individual LXMF packets, then ingested with the same `INSERT OR IGNORE` path local messages use and fanned out to local members.

Peer entries are validated as 16-byte hex hashes where they're read, so a typo is a startup error rather than a `ValueError` raised inside a federation or failover thread, which would stop that thread for the life of the process.

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

Each sync round now also exchanges `/fed/state`, where a hub reports its name, the groups it hosts, their destination hashes, and their member hashes. Liveness is the last round a peer actually answered, not the last one this hub tried, since a hub records every attempt including the failures. A peer silent for `peer_timeout_sec`, 1800 seconds or six sync intervals, is treated as down from this hub's point of view. That's local evidence, not a claim about the rest of the network. Because only a sync round can refresh liveness, a `peer_timeout_sec` below two `federation.sync_interval_sec` would declare a healthy peer stale between rounds and notify every client, so it is raised to that floor with a warning naming both settings.

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

## Usernames and multi-device personas

A username belongs to a persona, not to a destination hash, because one person is a phone, a node at home, and a laptop. `personas` holds the name, `persona_identities` maps each LXMF destination hash to one persona, and a message from any of those hashes is attributed to the same name on every hub in the federation.

```
/name alice        ->  You are alice on every hub in this federation, from 1 device(s).
/link              ->  Send '/link 4F2K9Q' from your other device within 15m. The code works once.
/link 4F2K9Q       ->  This device is now alice, 2 device(s) in total.
/whoami            ->  alice (persona 9c2f...)
                         8f1c0d7a...  <- this device
                         b3e07741...
/unlink b3e07741   ->  b3e07741... is no longer alice, 1 device(s) left.
```

Names are unique per federation, compared with `str.casefold()` and displayed as typed, so `Alice` and `alice` are one name and the capitalisation the owner chose survives. A device belongs to at most one persona at a time, and the last device of a named persona can't be unlinked, since a name nobody can post under is a name nobody can release either.

Link codes never leave the hub that minted them. They are six characters from an alphabet with no `0/O` or `1/I`, single-use, and expire in 15 minutes; the second device proves nothing but possession of the code, which is the same trust model as pairing a device by reading a number off a screen.

Linking a device also carries over whatever groups the persona already belongs to: the new device gets the same role (member or admin, never a ban) in every group where an existing device of that persona has one, so a member adding their laptop to an invite-only group they're already in doesn't need the operator to `add-member` it by hand. Membership on the linking device's own hash is untouched by this -- unlink drops the roles it was given the same way any member's departure would, via `remove-member`.

Every sync round also runs `/fed/personas`, which returns the persona rows and the device rows, tombstones included. A tombstone is why an unlink sticks: a peer that still remembers the link would otherwise re-add the device on the next round, and "my old phone keeps posting as me" is not a bug a member can work around. Rows merge on `(revision, updated_at)`, and the exchange is wrapped so a peer that doesn't answer the path -- an older hub -- costs nothing but a log line while message reconciliation continues.

Two hubs partitioned from each other can both hand out `alice`. When they meet, the earlier `(claimed_at, persona_id)` keeps the name and the later one loses it, which every hub computes identically from the rows themselves, so the mesh converges without a coordinator or a clock they both trust. The loser keeps its devices and its persona and is told, in the group, that the name went to an earlier claim.

## In-band commands

An unmodified LXMF client has no UI for a hub, so a member's only channel is a message to the group. A message whose first token is a known verb is consumed and answered instead of reflected; everything else is a message, including anything that merely starts with a slash, so `/etc/hosts is the file` still posts. Verbs are case-insensitive and a line over 1024 bytes isn't a command.

```
/help    /status    /name    /whoami    /link    /unlink    /who    /names
```

`/help` lists those with usage. Sent by an operator it also lists the control commands, generated from the same argparse definitions the control channel answers with, and says they go to the control address rather than the group -- the operator surface stays off the group either way.

`/status` is the situational-awareness answer, and deliberately reports what failover acts on rather than a second opinion computed differently:

```
Example Hub: up 3d 4h, 2 group(s), 1 peer hub(s)
you: alice, 2 device(s), posting from 8f1c0d7a...
ops (invite): 7 member(s) here, 3 adopted, 5 named
  b196e0eb...  this hub
  7d41c9a2...  Standby Hub, answered 4m ago, 3 of its member(s) served here
federation: 1/1 peer(s) answering, sync every 5m, a peer counts as down after 10m
queues: 4 message(s), 0 notice(s), 1 answer(s) waiting to go out
operator: 0 control answer(s) queued, 5/6 persona(s) named, egress 0.5/s burst 4
```

The peer age is the last round that peer actually answered, and the down threshold is the same clamped `peer_timeout_sec` failover uses, so a member reading `/status` and a hub deciding to adopt members can't disagree. The local address is read from the live destination rather than derived, so it is the address to post to and not the address the config implies. A malformed peer entry is reported as no peers instead of failing the command, because an operator's typo shouldn't take `/status` down with it.

Answers go on the durable user queue: they survive an unknown path, a failed delivery, and a restart, are paced by the same token bucket as reflections, and are rate-limited per sender by `commands.min_reply_interval_sec`. A repeat inside that window is still swallowed -- answering it would be a hub that can be made to transmit on demand, and reflecting it would put a member's `/status` flood into the group. Command interception happens after the ACL check, so a banned hash gets no answer and no reflection. Every failure path returns text, including argument errors and malformed hashes, because a member with no answer can't tell a rejected command from a hub that stopped listening.

## What this doesn't do

Failover is a notice, not a redirect. A member has to add the standby contact themselves, and a client with no one at either address just fails in its own outbound queue as before. Transparent failover would need the group's private key on every hub, which trades the group's forward secrecy and blast radius for saving the member one paste; that isn't built.

Adoption also can't help a group only one hub hosts. A hub serves a silent peer's members only for group ids it hosts itself, since it has nowhere to reflect them otherwise.

## Crash consistency

SQLite runs with `journal_mode=WAL`, `synchronous=NORMAL`, and `busy_timeout=30000`. Every state transition is committed before it's acted on, which is what makes the egress guarantee above hold: the queue row exists on disk before the message is handed to the router, and the peer sync timestamp is written after the ingest that earned it.

Storing a message and fanning it out are one transaction, because the store is also what dedup and federation read: a crash between the two would leave a message that every hub agrees exists, that nobody is queued to receive, and that the sender's retry can no longer replace, since the retry arrives as a duplicate. Either the message is unknown and the client's retry works, or it is known and queued for everyone. Pruning removes the queue rows of messages it deletes in the same transaction, for the same reason in the other direction.

## Tests

```bash
pytest -q      # 239 tests
ruff check .
```

The suite covers atomic store-and-fan-out including rollback, in-flight suppression of a duplicate send and its recovery once LXMF drops the message, grace counting separate from delivery attempts, the durable operator answer queue, opening a database written before the `graces` column existed, WAL mode, dedup, hub-independent hashing, ACL enforcement for all three roles, author-field stripping, token bucket pacing, backoff growth and its ceiling, attempt capping, propagation versus direct method selection, wrong-key detection, exact Merkle traversal against a known missing set, multi-epoch backfill, peer rejection on mismatched parameters, and the control path including refusal of non-operators, unsigned messages, and verbs outside the remote allowlist.

Failover and the directory add: liveness measured from answers rather than attempts, adoption restricted to locally hosted groups and idempotent across checks, peer members admitted to an invite-only group while banned hashes stay out, member sets withdrawn when a peer drops them, hand-back and both isolation transitions firing once each, notices surviving a reopen of the database, and directory listings, per-requester rate limiting, and unsigned queries.

`tools/local_testnet.py` runs each role as a separate Reticulum instance over localhost TCP, with its own config directory, its own TCP interface, and `share_instance = No`, so reflection, egress, and federation are exercised over real RNS packets rather than in-process fakes:

```bash
python tools/local_testnet.py hub    --name a --port 4242 --group ops --public
python tools/local_testnet.py client --name bob   --connect 4242
python tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>
```

Hub b joins the federation with `--port 4243 --connect 4242 --peer <hub_a_federation_hash>`, where that hash is printed at hub a's startup. Set `TESTNET_LOGLEVEL=7` for per-message hub and federation output.

Personas and commands add: claiming, renaming and case-folded uniqueness, multi-device linking with one-time and expired codes, unlink tombstones surviving a federation round, deterministic convergence of two conflicting claims across two merge rounds, persona-name attribution alongside the author hash, known verbs consumed while a slash-prefixed message is reflected, a banned sender getting no answer, durable answers across a failed delivery, and opening a database written before the persona tables existed.

## To-Do
- Operators should automatically join a group they complete with their operator identity. If they don't want to, have the option to set a flag (--no-join?).
- Look into stamp settings to balance efficiency and anti-spam/DoS
- An authorized user using the /link function to associate another identity to their username shouldn't have to have the identity manually added by the operator, it should be automatic.
- Look into a way to make creation of member identities for multiple groups faster. Maybe copying usernames/associated identities as specified by the operator?
- Names of groups should probably be private, only visible to members. All others should just see the identity.
- Create a method of generating and sharing a key that allows identities to join a group without operator involvement.
- Verify that usernames are hub-wide, not per-group

## Licence

MIT. See [LICENSE](LICENSE).
