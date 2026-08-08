---
name: testing-lxmf-group-hub
description: How to end-to-end test the headless LXMF/Reticulum group hub daemon on one machine (local TCP testnet, log capture, SQLite/CLI inspection, federation timing).
---

# Testing the LXMF group hub on a local RNS testnet

Headless daemon: no GUI, no web UI. All testing is process-level — run several real Reticulum
instances over localhost TCP, capture logs to files, inspect SQLite. Do not record the desktop
except to screenshot terminal log output as evidence.

## Setup

```bash
pip install -e ".[dev]"      # deps: rns, lxmf, msgpack (+ pytest, ruff)
pytest -q && ruff check .     # fast sanity gate, not proof of the feature
```

`tools/local_testnet.py` writes `~/.lxmf_hub_testnet/<name>/reticulum/config` per role with its own
TCP interface and `share_instance = No`, so every role is a separate Reticulum instance.
Wipe `rm -rf ~/.lxmf_hub_testnet` between scenarios. There is no auth/secret of any kind.

## Non-obvious things that will waste your time

1. **Always run harness roles with `PYTHONUNBUFFERED=1`.** The harness prints
   `[name] received: …` / `[name] sent: …` without `flush=True`, so with stdout redirected to a
   file the log looks empty and it appears nothing was delivered. This may be fixed upstream; if
   logs look empty, suspect buffering before suspecting the daemon.
2. **Many interesting log lines are `RNS.LOG_DEBUG`** (`Dropping duplicate LXM`,
   `Delivered group '…' message to`, `Epoch N of group '…': N message(s) to fetch`,
   `Pushing N message(s) … as resource`). Default `log_level` is 4 (INFO) and the harness may not
   expose a flag — set `"log_level": 6` in a hub JSON config and run the real daemon
   (`python -m lxmf_hub.cli --config cfg.json run`), or temporarily add a log level knob to
   `tools/local_testnet.py` (revert it afterwards).
3. **Use absolute paths in hub JSON configs.** `reticulum_config_path` may not be
   `expanduser`-ed; a `~/...` value can create a literal `~` directory and silently fall back to a
   default Reticulum config (no TCP interfaces → clients get `Connection refused`). If a client
   logs `Connection refused`, grep the hub log for
   `Could not load config file, creating default configuration file`.
4. **The harness `run_hub` may not call `HubDaemon.run()`** (it does `start()` + its own announce
   loop), so group hot-loading and pruning aren't exercised and a group created with
   `create-group` against a running harness hub never attaches. Use the real entrypoint
   `python -m lxmf_hub.cli --config cfg.json run` for anything involving hot-load, SIGKILL/restart
   or supervision. The harness writes the Reticulum config, so boot the harness hub once to
   create the config + group, then switch to the real daemon on the same storage dir.
5. **`pkill -f 'local_testnet'` will kill your own shell** (the pattern matches the shell's own
   command line). Anchor it: `pkill -f '^python3 tools/local_testnet.py client --name m5'`.
6. **Sending the same text twice is not a duplicate.** `msg_hash` =
   sha256(group_hash|sender|timestamp|payload) and LXMF stamps a fresh timestamp per message. To
   exercise dedup you must send two LXMessages with an explicitly equal `message.timestamp`.
   Even then the hub's store-level dedup log may not fire: `LXMRouter.lxmf_delivery` drops
   retransmits first via `locally_delivered_transient_ids` (`LXMRouter.py`, `has_message`), so the
   hub delivery callback is never invoked twice. Assert the observable instead (stored once, not
   re-reflected), and exercise store dedup through repeated federation sync rounds.

## Useful commands

```bash
# hub / client roles (each in its own background process, logs to files)
PYTHONUNBUFFERED=1 python3 tools/local_testnet.py hub    --name a --port 4242 --group ops --public
PYTHONUNBUFFERED=1 python3 tools/local_testnet.py client --name bob --connect 4242
PYTHONUNBUFFERED=1 python3 tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>

# operator CLI (safe against a live daemon; WAL)
python3 -m lxmf_hub.cli --config cfg.json groups|members <gid>|add-member <gid> <hash>|status
```

Payloads are encrypted at rest, so read content through `Store`, not raw SQL. A read-only
inspector is the fastest evidence generator:

```python
from lxmf_hub.config import HubConfig; from lxmf_hub.store import Store
from lxmf_hub.hub import unpack_payload
cfg = HubConfig.from_dict({"storage_path": "/home/ubuntu/.lxmf_hub_testnet/a/hub"})
store = Store(cfg.database_path); store.bind_cipher(cfg.at_rest.mode, cfg.at_rest_keyfile)
# store.list_groups(), store.list_members(gid, include_banned=True),
# store.group_history(gid), store.egress_depth(), store.due_egress(100, now=time.time()+1e9)
```
To prove at-rest encryption, read `messages.lxmf_payload_blob` with plain `sqlite3`: it must start
with framing byte `0x01` and contain no plaintext.

## Timing / choreography that matters

* Group announces every `announce_interval_sec` (harness: 20 s); a sending client polls
  `RNS.Identity.recall` for up to 30 s, so allow ~30-40 s per send round trip.
* Egress is token-bucketed (harness: 1.0/s, burst 2). To *prove* pacing rather than guess, queue
  ~20+ items (N messages × M members) and compare the span of `Delivered …` timestamps against
  `items / rate`; a broken bucket empties the queue in under a second.
* Members must exist **before** fan-out — `add-member` first, then send. Public groups enrol the
  sender on first message; the author is always excluded from fan-out.
* Federation: `FederationEngine._run` sleeps `sync_interval_sec` *before* the first round (harness:
  15 s), so wait ≥2 intervals. Both hubs must list each other via `--peer <federation endpoint
  hash>` — `_peer_allowed` rejects unconfigured peers. `epoch_seconds` and `merkle_depth` must
  match on both sides or you get `peer rejected sync parameters`.
* Get each hub's `federation endpoint:` hash by booting it once (`timeout 12 python3
  tools/local_testnet.py hub …`), killing it, then restarting with `--peer`. Identity and DB
  persist across restarts, so hashes stay stable.
* Good durability test: make one member offline before fan-out so its item stays queued, read
  `status` (`egress_queue`), `kill -9` the hub, read `status` again while it is down, restart and
  confirm `Hub running with … N queued delivery item(s)`, then bring the member back and watch the
  delivery land.
* Good backfill test: seed hub A while peer hub C is *down* (register C's member in C's DB
  meanwhile), then start C and expect `Ingested N message(s)` plus N deliveries — proves
  anti-entropy rather than live-only propagation.

## Devin Secrets Needed

None — everything runs locally with self-generated RNS identities.
