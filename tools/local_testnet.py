"""Local test harness: run hubs and clients on one machine over TCP.

Each role gets its own Reticulum config directory with a single TCP interface, so
hubs, peer hubs and clients are genuinely separate Reticulum instances talking
over localhost rather than sharing process state.

Phase 1 and 2 (store, reflect, rate-limited egress)::

    python tools/local_testnet.py hub    --name a --port 4242 --group ops --public
    python tools/local_testnet.py client --name alice --connect 4242 --send-to <group_hash>
    python tools/local_testnet.py client --name bob   --connect 4242

Phase 3 (federation): start a second hub that peers with the first, then send to
one hub and watch the message appear on the other::

    python tools/local_testnet.py hub --name b --port 4243 --connect 4242 \\
        --group ops --public --peer <hub_a_federation_hash>

Set ``TESTNET_LOGLEVEL=7`` for per-message hub and federation debug output. All
role output is line-flushed, so redirecting stdout to a log file works.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import LXMF  # noqa: E402
import RNS  # noqa: E402

from lxmf_hub.config import HubConfig  # noqa: E402
from lxmf_hub.daemon import HubDaemon  # noqa: E402
from lxmf_hub.destinations import group_destination_hash  # noqa: E402
from lxmf_hub.store import ACL_INVITE, ACL_PUBLIC  # noqa: E402

BASE = os.path.expanduser("~/.lxmf_hub_testnet")

# Raise with TESTNET_LOGLEVEL=7 to see per-message hub and federation debug output.
LOGLEVEL = int(os.environ.get("TESTNET_LOGLEVEL", "4"))

CONFIG_TEMPLATE = """
[reticulum]
  enable_transport = {transport}
  share_instance = No
  instance_name = {name}

[logging]
  loglevel = {loglevel}

[interfaces]
{interfaces}
"""

SERVER_INTERFACE = """
  [[TCPServer]]
    type = TCPServerInterface
    interface_enabled = True
    listen_ip = 127.0.0.1
    listen_port = {port}
"""

CLIENT_INTERFACE = """
  [[TCPClient{port}]]
    type = TCPClientInterface
    interface_enabled = True
    target_host = 127.0.0.1
    target_port = {port}
"""


def write_reticulum_config(name: str, port: int | None, connect: list[int], transport: bool) -> str:
    config_dir = os.path.join(BASE, name, "reticulum")
    os.makedirs(config_dir, exist_ok=True)
    interfaces = ""
    if port:
        interfaces += SERVER_INTERFACE.format(port=port)
    for target in connect:
        interfaces += CLIENT_INTERFACE.format(port=target)
    with open(os.path.join(config_dir, "config"), "w") as config_file:
        config_file.write(
            CONFIG_TEMPLATE.format(
                name=name,
                interfaces=interfaces,
                transport="Yes" if transport else "No",
                loglevel=LOGLEVEL,
            )
        )
    return config_dir


def run_hub(args: argparse.Namespace) -> int:
    storage = os.path.join(BASE, args.name, "hub")
    config = HubConfig.from_dict(
        {
            "storage_path": storage,
            "reticulum_config_path": write_reticulum_config(
                args.name, args.port, args.connect, transport=True
            ),
            "hub_name": f"testnet-{args.name}",
            "log_level": LOGLEVEL,
            "announce_interval_sec": 20,
            "announce_jitter_sec": 0,
            "operator_identity": args.operator or None,
            "egress": {"tokens_per_second": 1.0, "burst": 2, "retry_backoff_sec": 10},
            "federation": {
                "peers": args.peer,
                "sync_interval_sec": 15,
                "epoch_seconds": 3600,
                "merkle_depth": 8,
            },
        }
    )

    daemon = HubDaemon(config)
    daemon.start()

    if args.group and daemon.store.get_group(args.group) is None:
        group = daemon.hub.create_group(
            args.group, args.group, ACL_PUBLIC if args.public else ACL_INVITE
        )
        print(
            f"group {group.group_id}: {group_destination_hash(group.identity_key).hex()}",
            flush=True,
        )
    for member in args.member:
        daemon.store.add_member(args.group, bytes.fromhex(member))

    for group in daemon.store.list_groups():
        print(
            f"group {group.group_id}: {group_destination_hash(group.identity_key).hex()}",
            flush=True,
        )
    if daemon.federation is not None:
        print(f"federation endpoint: {daemon.federation.destination.hash.hex()}", flush=True)
    if daemon.control is not None and daemon.control.destination is not None:
        print(f"control endpoint: {daemon.control.destination.hash.hex()}", flush=True)

    # Same supervision loop as the real daemon, so hot-loading and pruning are
    # exercised by the harness too.
    daemon.supervise()
    return 0


def run_client(args: argparse.Namespace) -> int:
    storage = os.path.join(BASE, args.name, "client")
    os.makedirs(storage, exist_ok=True)
    RNS.Reticulum(
        configdir=write_reticulum_config(args.name, None, args.connect, transport=False),
        loglevel=LOGLEVEL,
    )

    identity_path = os.path.join(storage, "identity")
    identity = (
        RNS.Identity.from_file(identity_path) if os.path.isfile(identity_path) else RNS.Identity()
    )
    identity.to_file(identity_path)

    router = LXMF.LXMRouter(identity=identity, storagepath=storage)
    destination = router.register_delivery_identity(identity, display_name=args.name)
    router.register_delivery_callback(
        lambda message: print(
            f"[{args.name}] received: {message.content_as_string()}"
            f" fields={ {key: value for key, value in (message.fields or {}).items()} }",
            flush=True,
        )
    )
    router.announce(destination.hash)
    print(f"client {args.name}: {destination.hash.hex()}", flush=True)

    if args.send_to:
        group_hash = bytes.fromhex(args.send_to)
        deadline = time.time() + 30
        while RNS.Identity.recall(group_hash) is None and time.time() < deadline:
            if not RNS.Transport.has_path(group_hash):
                RNS.Transport.request_path(group_hash)
            time.sleep(1)
        group_identity = RNS.Identity.recall(group_hash)
        if group_identity is None:
            print(f"[{args.name}] no path to group {args.send_to}", file=sys.stderr, flush=True)
            return 1
        group_destination = RNS.Destination(
            group_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, LXMF.APP_NAME, "delivery"
        )
        message = LXMF.LXMessage(
            group_destination, destination, content=args.message, title="", fields={}
        )
        message.desired_method = LXMF.LXMessage.DIRECT
        router.handle_outbound(message)
        print(f"[{args.name}] sent: {args.message}", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        router.exit_handler()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Local RNS testnet for the LXMF group hub")
    subparsers = parser.add_subparsers(dest="role", required=True)

    hub = subparsers.add_parser("hub")
    hub.add_argument("--name", required=True)
    hub.add_argument("--port", type=int, help="TCP port to listen on")
    hub.add_argument("--connect", type=int, nargs="*", default=[], help="TCP ports to connect to")
    hub.add_argument("--group", help="group id to create if missing")
    hub.add_argument("--public", action="store_true", help="create the group with a public ACL")
    hub.add_argument("--member", nargs="*", default=[], help="member hashes to authorise")
    hub.add_argument("--peer", nargs="*", default=[], help="federation hashes of peer hubs")
    hub.add_argument("--operator", nargs="*", default=[], help="operator hashes for LXMF control")

    client = subparsers.add_parser("client")
    client.add_argument("--name", required=True)
    client.add_argument("--connect", type=int, nargs="*", default=[])
    client.add_argument("--send-to", help="group destination hash to send a message to")
    client.add_argument("--message", default="hello from the testnet")

    args = parser.parse_args()
    return run_hub(args) if args.role == "hub" else run_client(args)


if __name__ == "__main__":
    raise SystemExit(main())
