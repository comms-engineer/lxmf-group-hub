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

The editable install can fail with `backend does not implement build_editable`; there is no
`setup.py` to fall back on. Install the dependencies directly instead and run the suite from the
repository root: `pip install rns lxmf msgpack pytest ruff`.

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

7. **`sqlite3` the CLI binary may not be installed** even though the Python `sqlite3` module is.
   Read queue depths with a one-liner instead:
   `python3 -c "import sqlite3;print(sqlite3.connect('<db>').execute('select count(*) from control_queue').fetchone())"`.
   Schema names to expect: `messages.msg_hash` (not `message_id`), `peer_members(peer_hash,
   group_id, user_hash, updated_at)`, `adoptions(peer_hash, group_id, user_hash, adopted_at)` —
   `pragma table_info(<table>)` first rather than guessing column names.
8. **A harness client that reads its outbox by byte offset breaks if you overwrite the file.**
   Append commands (`>> outbox`), never `> outbox`: with a monotonic read offset a truncating write
   makes the client seek into the middle of the new line and log `bad destination …`.
9. **Testing invalid-config startup failures needs its own `reticulum_config_path`.** Reusing a
   running hub's Reticulum dir makes the throwaway run die with `OSError: [Errno 98] Address
   already in use` from the TCPServer interface, which masks the config `ValueError` you are
   asserting. Point the bad-config runs at a client-only Reticulum config (single TCPClient) and
   assert both a non-zero exit and zero `Hub running with` lines in the captured output.
10. **`/tmp` does not survive a box restart, but `~/.lxmf_hub_testnet` does.** Keep hub JSON
   configs and the client harness under `~` (or re-generate them), because the RNS identities,
   group keys and hub DBs persist — all destination hashes (group, control, federation, clients)
   stay stable across a restart, so only the configs/logs need rebuilding. Copy logs you want to
   keep out of `/tmp` before finishing.

## Failover / directory / notice-queue testing (PR #4 onwards)

Minimum viable topology: hub `a` (TCPServer 4242, transport) + hub `b` (4243, connects to 4242),
each listing the other's `/fed` hash in `federation.peers`, group id `ops` **invite-only on both**,
and **all clients connected to 4242 only** so killing `b` does not remove any client's network
path. Give `a` two local members, `b` one peer-only member (the adoption subject), and one hash
that is a member on `b` but `banned` on `a` (proves ban beats adoption).

Use short timeouts or an outage takes 30 minutes:

```json
"federation": {"sync_interval_sec": 15},
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
  message and announce. If a hand-built `RNS.Destination` is missing them, the daemon logs
  `Hub supervision error during <task>: …` once a second. Each supervision task is now guarded
  separately, so an announce failure no longer suppresses the failover check or the prune in that
  iteration — but still grep hub logs for `supervision error|AttributeError` and treat a non-zero
  count as a failure even when the feature under test looks fine, and check *which* task is named.
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
* Federation: `FederationEngine._run` sleeps `min(15 s, sync_interval_sec)` before the first round
  and `sync_interval_sec` thereafter, so a restarted hub backfills within ~15 s; still wait
  ≥2 intervals before calling a missing message a bug. Both hubs must list each other via
  `--peer <federation endpoint hash>` — `_peer_allowed` rejects unconfigured peers, and a peer
  entry that is not 16 bytes of hex now fails at startup. `epoch_seconds` and `merkle_depth` must
  match on both sides or you get `peer rejected sync parameters`.
* Get each hub's `federation endpoint:` hash by booting it once (`timeout 12 python3
  tools/local_testnet.py hub …`), killing it, then restarting with `--peer`. Identity and DB
  persist across restarts, so hashes stay stable.
* Good durability test: make one member offline before fan-out so its item stays queued, read
  `status` (`egress_queue`), `kill -9` the hub, read `status` again while it is down, restart and
  confirm `Hub running with … N queued delivery item(s)`, then bring the member back and watch the
  delivery land.
* Good operator-answer durability test: answers live in `control_queue` (visible as `control_queue`
  in `status`), not in an inline send. Queue one for an operator hash with no path (send a command
  from a client whose identity the hub cannot recall, or enqueue via `Store.enqueue_control`),
  `kill -9` the hub, confirm the depth survives, then bring the operator up and watch the answer
  land. Answers are drained ahead of client traffic and spend no egress tokens, so a deep client
  backlog must not delay a `status` reply.
* A row handed to the router is held in memory until a callback resolves it, for at most
  `egress.delivery_timeout_sec` (default 600 s). When testing retries, drive them with delivery
  *failures* rather than by waiting out that timeout, and remember a propagated delivery's callback
  means the propagation node accepted the message — the log says "handed to the propagation node
  for", not "delivered to", and the client still has to sync.
* **Capturing a `control_queue` row before the scheduler drains it** takes a freeze, not a poll: the
  answer is enqueued and sent within ~1-3 s. Loop on the hub log for the
  `Operator <hash> sent: <verb>` line, `kill -STOP <hub pid>` the instant it appears, read the
  depth from SQLite, then `kill -9` to prove durability across a crash. Content is a bonus
  assertion: an answer generated before the kill still carries the pre-kill `egress_queue` value
  when it is delivered after the restart.
* **Client-side propagation sync must be driven explicitly** in a test client:
  `router.set_outbound_propagation_node(hash)` then `router.request_messages_from_propagation_node(identity)`
  every ~20 s. Received propagated messages arrive with `message.method == 3`
  (`LXMF.LXMessage.PROPAGATED`), direct ones with `2`. Members who never sync legitimately never
  see the message even though the hub row completed — do not read that as a lost delivery.
* **Grace vs attempt semantics are directly observable**: add a member hash whose identity can
  never be recalled, send one message, and sample
  `select attempts, graces from egress_queue` every ~15 s. `graces` must climb (1, 2, 3 …) while
  `attempts` stays 0, with the sampling interval stretching as the grace backoff doubles.
* **`failover.peer_timeout_sec` is silently raised to two `federation.sync_interval_sec`** when it
  is lower, since only a sync round refreshes liveness — otherwise a healthy peer goes stale between
  rounds and its clients get adoption notices. So shortening a failover test means shortening
  `sync_interval_sec` too; check the startup warning naming both settings, and remember the
  *effective* timeout (`FailoverEngine.peer_timeout`, echoed in the adoption notice) may not be the
  configured one when computing how long an outage must last.
* Repeated *texts* across runs are separate messages: after federation ingest a client can log the
  same text twice legitimately. Count `messages` rows (`select hex(msg_hash), timestamp`) and match
  the total against `Ingested N message(s)` before calling anything a duplicate delivery.
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
