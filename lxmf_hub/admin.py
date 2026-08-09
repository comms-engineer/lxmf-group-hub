"""Administrative commands, shared by the CLI and the LXMF control channel.

Nothing here starts or touches a live daemon. Every verb reads or writes SQLite
and returns text, so the same code answers an operator at a shell and an operator
sending an LXMF message; a running daemon picks the changes up on its next
reload.
"""

from __future__ import annotations

import argparse
import os
import time

import LXMF
import RNS

from .config import HubConfig
from .crypto import MODE_NONE
from .destinations import group_destination_hash
from .failover import format_age
from .store import (
    ACL_INVITE,
    ACL_PUBLIC,
    ROLE_ADMIN,
    ROLE_BANNED,
    ROLE_MEMBER,
    Store,
)


class CommandError(Exception):
    """Raised instead of exiting when a command cannot be parsed or run."""


class TextParser(argparse.ArgumentParser):
    """Argument parser that reports failures to its caller.

    ``argparse`` writes to stderr and calls ``sys.exit``, which is fine for a
    shell and useless for a command that arrived in an LXMF message. Usage and
    help text are collected and raised as ``CommandError`` instead.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._collected: list[str] = []

    def _print_message(self, message, file=None) -> None:
        if message:
            self._collected.append(message)

    def error(self, message) -> None:
        raise CommandError(f"{message}\n\n{self.format_usage()}".strip())

    def exit(self, status=0, message=None) -> None:
        text = "".join(self._collected) or message or ""
        raise CommandError(text.strip())


def control_destination_hash(config: HubConfig) -> bytes | None:
    """Destination hash an operator addresses, or None before the first run."""
    if not os.path.isfile(config.identity_path):
        return None
    identity = RNS.Identity.from_file(config.identity_path)
    if identity is None:
        return None
    return RNS.Destination.hash(identity, LXMF.APP_NAME, "delivery")


def open_store(config: HubConfig) -> Store:
    store = Store(config.database_path)
    if config.at_rest.mode != MODE_NONE:
        store.bind_cipher(config.at_rest.mode, config.at_rest_keyfile)
    return store


def build_parser() -> TextParser:
    parser = TextParser(prog="lxmf-hub", description="LXMF federated group hub")
    parser.add_argument("--config", help="path to a hub configuration JSON file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="run the hub daemon")

    create = subparsers.add_parser("create-group", help="create a group and its RNS identity")
    create.add_argument("group_id")
    create.add_argument("--name", help="display name announced to clients")
    create.add_argument("--acl", choices=[ACL_PUBLIC, ACL_INVITE], help="ACL mode")

    subparsers.add_parser("groups", help="list groups and their destination hashes")

    acl = subparsers.add_parser("set-acl", help="change the ACL mode of a group")
    acl.add_argument("group_id")
    acl.add_argument("acl", choices=[ACL_PUBLIC, ACL_INVITE])

    add = subparsers.add_parser("add-member", help="authorise an LXMF destination hash")
    add.add_argument("group_id")
    add.add_argument("user_hash")
    add.add_argument("--role", choices=[ROLE_MEMBER, ROLE_ADMIN, ROLE_BANNED], default=ROLE_MEMBER)

    remove = subparsers.add_parser("remove-member", help="remove a member from a group")
    remove.add_argument("group_id")
    remove.add_argument("user_hash")

    members = subparsers.add_parser("members", help="list the members of a group")
    members.add_argument("group_id")

    subparsers.add_parser("status", help="show queue depth and group counts")

    subparsers.add_parser("peers", help="show peer hubs, their endpoints and last contact")
    return parser


def administer(args: argparse.Namespace, config: HubConfig, store: Store) -> str:
    """Run one administrative command and return what it has to say."""
    if args.command == "create-group":
        if store.get_group(args.group_id) is not None:
            raise CommandError(f"Group '{args.group_id}' already exists")
        identity = RNS.Identity()
        group = store.create_group(
            group_id=args.group_id,
            display_name=args.name or args.group_id,
            identity_key=identity.get_private_key(),
            acl_mode=args.acl or config.default_acl_mode,
        )
        destination = group_destination_hash(group.identity_key).hex()
        return f"{group.group_id}\t{group.acl_mode}\t{destination}"

    if args.command == "groups":
        lines = []
        for group in store.list_groups():
            destination = group_destination_hash(group.identity_key).hex()
            members = len(store.list_members(group.group_id))
            lines.append(f"{group.group_id}\t{group.acl_mode}\t{members} member(s)\t{destination}")
        return "\n".join(lines) or "no groups"

    if args.command == "set-acl":
        if store.get_group(args.group_id) is None:
            raise CommandError(f"No such group: {args.group_id}")
        store.set_acl_mode(args.group_id, args.acl)
        return f"{args.group_id} is now {args.acl}"

    if args.command == "add-member":
        if store.get_group(args.group_id) is None:
            raise CommandError(f"No such group: {args.group_id}")
        store.add_member(args.group_id, user_hash(args.user_hash), args.role)
        return f"{args.user_hash} is {args.role} in {args.group_id}"

    if args.command == "remove-member":
        store.remove_member(args.group_id, user_hash(args.user_hash))
        return f"{args.user_hash} removed from {args.group_id}"

    if args.command == "members":
        lines = [
            f"{member.hex()}\t{role}"
            for member, role in store.list_members(args.group_id, include_banned=True)
        ]
        return "\n".join(lines) or "no members"

    if args.command == "peers":
        now = time.time()
        lines = []
        for peer in config.federation.peers:
            peer_hash = bytes.fromhex(peer)
            last = store.peer_last_success(peer_hash)
            seen = f"{format_age(now - last)} ago" if last else "never"
            adopted = sum(
                len(store.list_peer_members(peer_hash, group.group_id))
                for group in store.list_groups()
            )
            lines.append(f"{peer}\tlast answered {seen}\t{adopted} member(s) known")
            for entry in store.list_peer_groups():
                if entry.peer_hash == peer_hash:
                    lines.append(
                        f"  {entry.group_id}\t{entry.hub_name}\t{entry.destination_hash.hex()}"
                    )
        return "\n".join(lines) or "no peers configured"

    if args.command == "status":
        lines = [
            f"groups\t{len(store.list_groups())}",
            f"egress_queue\t{store.egress_depth()}",
            f"notice_queue\t{store.notice_depth()}",
        ]
        control = control_destination_hash(config) if config.operator_hashes else None
        if control is not None:
            lines.append(f"control\t{control.hex()}")
        return "\n".join(lines)

    raise CommandError(f"Unsupported command: {args.command}")


def user_hash(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exception:
        raise CommandError(f"'{value}' is not a hex destination hash") from exception
