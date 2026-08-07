"""Operator CLI: run the daemon and administer groups and members.

Administration is intentionally out-of-band. Groups, ACLs and roles live in the
database, and a running daemon hot-loads changes, so no in-band slash commands
are needed and no command parsing is exposed to clients.
"""

from __future__ import annotations

import argparse
import sys

import LXMF
import RNS

from .config import HubConfig
from .crypto import MODE_NONE
from .daemon import HubDaemon
from .destinations import identity_from_key
from .store import (
    ACL_INVITE,
    ACL_PUBLIC,
    ROLE_ADMIN,
    ROLE_BANNED,
    ROLE_MEMBER,
    Store,
)


def group_destination_hash(identity_key: bytes) -> bytes:
    """Destination hash a client would address, derived without touching RNS."""
    identity = identity_from_key(identity_key)
    return RNS.Destination.hash(identity, LXMF.APP_NAME, "delivery")


def open_store(config: HubConfig) -> Store:
    store = Store(config.database_path)
    if config.at_rest.mode != MODE_NONE:
        store.bind_cipher(config.at_rest.mode, config.at_rest_keyfile)
    return store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lxmf-hub", description="LXMF federated group hub")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = HubConfig.load(args.config)

    if args.command == "run":
        HubDaemon(config).run()
        return 0

    store = open_store(config)
    try:
        return _administer(args, config, store)
    finally:
        store.close()


def _administer(args: argparse.Namespace, config: HubConfig, store: Store) -> int:
    if args.command == "create-group":
        if store.get_group(args.group_id) is not None:
            print(f"Group '{args.group_id}' already exists", file=sys.stderr)
            return 1
        identity = RNS.Identity()
        group = store.create_group(
            group_id=args.group_id,
            display_name=args.name or args.group_id,
            identity_key=identity.get_private_key(),
            acl_mode=args.acl or config.default_acl_mode,
        )
        print(f"{group.group_id}\t{group.acl_mode}\t{group_destination_hash(group.identity_key).hex()}")
        return 0

    if args.command == "groups":
        for group in store.list_groups():
            destination = group_destination_hash(group.identity_key).hex()
            members = len(store.list_members(group.group_id))
            print(f"{group.group_id}\t{group.acl_mode}\t{members} member(s)\t{destination}")
        return 0

    if args.command == "set-acl":
        if store.get_group(args.group_id) is None:
            print(f"No such group: {args.group_id}", file=sys.stderr)
            return 1
        store.set_acl_mode(args.group_id, args.acl)
        return 0

    if args.command == "add-member":
        if store.get_group(args.group_id) is None:
            print(f"No such group: {args.group_id}", file=sys.stderr)
            return 1
        store.add_member(args.group_id, bytes.fromhex(args.user_hash), args.role)
        return 0

    if args.command == "remove-member":
        store.remove_member(args.group_id, bytes.fromhex(args.user_hash))
        return 0

    if args.command == "members":
        for user_hash, role in store.list_members(args.group_id, include_banned=True):
            print(f"{user_hash.hex()}\t{role}")
        return 0

    if args.command == "status":
        print(f"groups\t{len(store.list_groups())}")
        print(f"egress_queue\t{store.egress_depth()}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
