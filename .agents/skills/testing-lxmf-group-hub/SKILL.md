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
5. **Any `pkill -f <pattern>` whose pattern appears in your own command line kills your own shell.**
   This bites for `local_testnet`, and also for config paths (`pkill -f 'config /tmp/x/hub-a.json'`
   matches the `bash -c` wrapper that contains that string). Safest: `pgrep -af 'lxmf_hub.cli
   --config'` in one call, then `kill -9 <pid>` by number in the next call.
6. **Failover and the directory only tick in `HubDaemon.supervise()`**, and the harness hardcodes
   its own `failover`/`directory` blocks, so use the real daemon with a hand-written JSON config
   for any failover/directory work (see the choreography section below).
7. **Sending the same text twice is not a duplicate.** `msg_hash` =
   sha256(group_hash|sender|timestamp|payload) and LXMF stamps a fresh timestamp per message. To
   exercise dedup you must send two LXMessages with an explicitly equal `message.timestamp`.
   Even then the hub's store-level dedup log may not fire: `LXMRouter.lxmf_delivery` drops
   retransmits first via `locally_delivered_transient_ids` (`LXMRouter.py`, `has_message`), so the
   hub delivery callback is never invoked twice. Assert the observable instead (stored once, not
   re-reflected), and exercise store dedup through repeated federation sync rounds.

## Failover / directory / notice-queue testing (PR #4 onwards)

Minimum viable topology: hub `a` (TCPServer 4242, transport) + hub `b` (4243, connects to 4242),
each listing the other's `/fed` hash in `federation.peers`, group id `ops` **invite-only on both**,
and **all clients connected to 4242 only** so killing `b` does not remove any client's network
path. Give `a` two local members, `b` one peer-only member (the adoption subject), and one hash
that is a member on `b` but `banned` on `a` (proves ban beats adoption).

Use short timeouts or an outage takes 30 minutes:

```json
"failover": {"enabled": true, "peer_timeout_sec": 60, "check_interval_sec": 5,
             "notify_clients": true, "notify_isolation": true},
"directory": {"enabled": true, "min_reply_interval_sec": 60}
```

* **Gossip is the precondition for everything.** A peer's group destination and member set arrive
  only via a successful `/fed/state` round, so wait for `cli peers` to show the peer with
  `last answered <N>s ago` plus an indented `ops <hub_name> <dest hash>` line **before** killing it.
* **Liveness vs sync are different columns.** `peers.last_sync_at` advances on *failed* rounds
  (with `last_error`); only `peer_liveness.last_success_at` records an answer. Sample both from
  SQLite during an outage — `peer_liveness` frozen while `peers` advances is the assertion.
* **`FailoverEngine.peer_reference()` returns `max(last_success, started_at)`**, so a daemon
  restart mid-outage makes a still-dead peer look freshly alive: expect a spurious
  `Peer <x> answered again, releasing N adopted member(s)` + `connectivity restored` within seconds
  of restart, adoption rows deleted, `flag_isolated` reset, then re-adoption one timeout later and
  a second notice to every client. Always test "kill -9 the surviving hub while the peer is still
  down" — it is the case unit tests cannot see. (Posting by the affected member still works,
  because authorisation reads `peer_members`, which gossip persists independently of `adoptions`.)
* **Exactly-once notices** are enforced by `notice_queue`'s `UNIQUE (recipient_hash, body)`, so
  count *client-side* receipts across many check intervals, not queue rows.
* **Directory pacing**: the reply is enqueued, and with a normal bucket it can drain in <2 s, so a
  2 s poll will never see `notice_queue > 0`. Set `egress.tokens_per_second` to ~0.2 / `burst` 1 and
  fire three queries from three clients at once, then poll `notice_queue` once per second: 3 → 2 →
  1 → 0 at ~5 s spacing is the proof that replies are queued and token-bucketed, not inline.
* **Directory identity** lives at `<storage_path>/directory_identity`; ratchet state lives under
  `<storage_path>/lxmf/ratchets/<dest hash>.ratchets`. The `Directory on <hash>` log line must be
  byte-identical across restarts even with ratchets enabled.
* **LXMF reads attributes off any delivery destination** (`stamp_cost`, ratchets) on every inbound
  message and announce. If a hand-built `RNS.Destination` is missing them, the daemon survives but
  logs `Hub supervision error: 'Destination' object has no attribute 'stamp_cost'` once a second
  and **the failover check never runs in that iteration**. Always grep hub logs for
  `supervision error|AttributeError` and treat a non-zero count as a failure even when the feature
  under test looks fine.
* **Boot-into-outage**: a hub whose peer never answers must isolate one `peer_timeout_sec` after
  *its own start* (not at t=0, not never), with `peer_liveness` empty. Adoption cannot be tested
  for a never-seen peer — member sets only arrive by gossip.

## Useful commands

```bash
# hub / client roles (each in its own background process, logs to files)
PYTHONUNBUFFERED=1 python3 tools/local_testnet.py hub    --name a --port 4242 --group ops --public
PYTHONUNBUFFERED=1 python3 tools/local_testnet.py client --name bob --connect 4242
PYTHONUNBUFFERED=1 python3 tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>

# operator CLI (safe against a live daemon; WAL)
python3 -m lxmf_hub.cli --config cfg.json groups|members <gid>|add-member <gid> <hash>|status
python3 -m lxmf_hub.cli --config cfg.json peers      # per-peer last-answer age + gossiped groups
python3 -m lxmf_hub.cli --config cfg.json add-member ops <hash> --role banned

# unencrypted failover/directory state is readable with plain sqlite3:
#   peers, peer_liveness, peer_groups, peer_members, adoptions, notice_queue,
#   meta (key 'flag_isolated')
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

## Screenshot evidence on a headless box

There is no xterm/gnome-terminal; `konsole` is available on `DISPLAY=:0`. Write the evidence into
a shell script first, then:

```bash
export DISPLAY=:0
(nohup konsole --hide-menubar -e bash -c "bash /tmp/ev.sh; sleep 600" >/dev/null 2>&1 &)
sleep 8; wmctrl -a Konsole; wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz
```

Each new konsole opens un-maximized and `wmctrl -a` may not raise it above Chrome — click its
taskbar button, then re-issue the maximize, then screenshot.

## Devin Secrets Needed

None — everything runs locally with self-generated RNS identities.
