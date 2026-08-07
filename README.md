# LXMF Federated Group Hub

A headless group messaging service for the [Reticulum Network Stack](https://reticulum.network).
Unmodified LXMF clients (Sideband, NomadNet, MeshChat) join group chats by
messaging an ordinary LXMF contact: the hub instantiates a dedicated RNS
destination per group, announces it so it shows up in client directories, and
reflects each authorised message to the other members.

There are no slash commands and no bot syntax. Identity and authorisation come
solely from the Ed25519 signature RNS already verifies on every message.

## Design

```
     LoRa / RF, 1-5 kbps                        TCP / I2P / WireGuard, 1Mbps+
client ──LXMF──▶ group destination ──▶ store ──▶ egress queue ──▶ client
                        │                │        (token bucket,
                        │                │         propagation node)
                        └── ACL check    └──▶ Merkle epochs ◀──RNS Link/Resource──▶ peer hub
```

* **Virtual destinations.** Each group holds its own RNS identity and inbound
  LXMF delivery destination, announced periodically. Groups added to the
  database while the daemon runs are hot-loaded.
* **Reflection.** An inbound message is verified, checked against the group ACL,
  stored once and queued for the other members. The original author's hash
  travels in the LXMF fields dictionary of the reflection, so clients can keep
  thread context, and is also prefixed to the content for clients that only
  render text.
* **Conservative client egress.** Nothing is broadcast. Deliveries live in
  SQLite and are released by a token bucket, either through an LXMF propagation
  node (`lxmd`) or as direct RNS deliveries, so a busy group cannot saturate a
  local RF interface. A restart resumes the queue where it left off.
* **Federation by anti-entropy.** Message hashes are bucketed into epochs; each
  epoch has a Merkle root over a fixed partition of the hash space. Peers
  exchange roots over an RNS Link, walk the tree down through the branches that
  disagree, and transfer whatever is missing in bulk as RNS Resources -- never as
  individual LXMF packets.
* **Crash consistency.** SQLite in WAL mode, with every state transition
  committed before it is acted on.
* **Encryption at rest.** Message payloads and group private keys are encrypted
  in the database with AES-256-CBC + HMAC (RNS's token construct). This protects
  a stolen database or backup, not a live compromised host, since the daemon
  holds the key while it runs.

## Install

```bash
pip install -e .
```

Requires Python 3.9+, `rns`, `lxmf` and `msgpack`. The hub uses the local
Reticulum configuration (`~/.reticulum` by default).

## Run

```bash
lxmf-hub --config hub.json create-group ops --name "Ops" --acl invite
lxmf-hub --config hub.json add-member ops <client_lxmf_destination_hash>
lxmf-hub --config hub.json run
```

`create-group` prints the group's destination hash -- that is what members add as
a contact. Other operator commands: `groups`, `members`, `set-acl`,
`remove-member`, `status`. All of them are safe to run against a live daemon.

Roles are `member`, `admin` and `banned`. In `public` groups the first message
from an unknown sender enrols them; in `invite` groups it is dropped.

## Configuration

Every key is optional; the defaults below are the built-in ones.

```json
{
  "storage_path": "~/.lxmf_hub",
  "reticulum_config_path": null,
  "hub_name": "LXMF Group Hub",
  "announce_interval_sec": 1800,
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
    "stamp_cost": null
  },
  "federation": {
    "enabled": true,
    "peers": [],
    "sync_interval_sec": 300,
    "epoch_seconds": 3600,
    "merkle_depth": 8,
    "retention_epochs": 168,
    "link_timeout_sec": 30,
    "max_fetch_batch": 256
  }
}
```

Notes:

* `egress.propagation_node` is the hex hash of an `lxmd` propagation
  destination. With `prefer_propagation` set, reflections are queued there
  instead of being pushed directly at clients -- the friendliest option for
  intermittently reachable RF nodes.
* `at_rest.mode` is `keyfile` (a key generated in the storage directory),
  `passphrase` (derived from `LXMF_HUB_DB_KEY`) or `none`. Hubs do not need to
  share this key: message hashes are computed over plaintext, so deduplication
  and federation are unaffected.
* `author_field` is the LXMF field index carrying author attribution. The
  default is `0xFD` (`FIELD_CUSTOM_META`) rather than `0x01`, which the LXMF
  spec assigns to `FIELD_EMBEDDED_LXMS`; set it to `1` if your clients expect
  the author there.
* `federation.peers` holds the hex hashes of peer hubs' federation
  destinations (printed at hub startup). Peering is mutual: each side must list
  the other, and `epoch_seconds` and `merkle_depth` must match or roots never
  agree.
* `federation.retention_epochs` also bounds history: older messages are pruned.

## Federation protocol

Hub-to-hub requests, all over an RNS Link with both sides identified:

| Path | Request | Response |
| --- | --- | --- |
| `/fed/roots` | version, epoch length, tree depth | per-group, per-epoch Merkle roots |
| `/fed/tree` | group, epoch, level, node indices | node hashes at that level |
| `/fed/bucket` | group, epoch, leaf indices | message hashes in those buckets |
| `/fed/fetch` | group, message hashes | count, followed by an RNS Resource with the messages |

## Testing

```bash
pytest -q
ruff check .
```

`tools/local_testnet.py` runs hubs and clients as separate Reticulum instances
over localhost TCP, for exercising reflection, egress and federation end to end:

```bash
python tools/local_testnet.py hub --name a --port 4242 --group ops --public
python tools/local_testnet.py client --name bob --connect 4242
python tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>
```

## Licence

MIT
