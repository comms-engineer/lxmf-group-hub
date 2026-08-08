"""Operator CLI: run the daemon and administer groups and members.

Administration never happens in band with group traffic. Group destinations
carry chat and nothing else, so no command parsing is exposed to members. The
verbs live in ``admin.py`` and act on the database, which a running daemon
hot-loads; the same verbs are reachable over signed LXMF from
``operator_identity`` through ``control.py``.
"""

from __future__ import annotations

import sys

from .admin import CommandError, administer, build_parser, open_store
from .config import HubConfig
from .daemon import HubDaemon


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except CommandError as exception:
        print(exception, file=sys.stderr)
        return 2

    config = HubConfig.load(args.config)

    if args.command == "run":
        HubDaemon(config).run()
        return 0

    store = open_store(config)
    try:
        output = administer(args, config, store)
    except CommandError as exception:
        print(exception, file=sys.stderr)
        return 1
    finally:
        store.close()

    if output:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
