"""Hub administration over LXMF.

An operator is not a special member: the control channel is its own LXMF
delivery destination on the hub identity, separate from every group destination,
and it accepts commands from the hashes in ``operator_identity`` and nobody else.
Authorisation is the Ed25519 signature RNS verified while unpacking the message,
so there is no password, token or session to steal.

Commands are the CLI verbs, sent as plain message text:

    add-member ops 8f1c...  ->  "8f1c... is member in ops"
    groups                  ->  one line per group with its destination hash

State changes land in SQLite, and the daemon hot-loads them within
``GROUP_RELOAD_INTERVAL``, so a group created over LXMF starts announcing
without a restart.
"""

from __future__ import annotations

import shlex
import time

import LXMF
import RNS

from .admin import CommandError, administer, build_parser
from .config import HubConfig
from .store import Store

# Verbs an operator may drive remotely. "run" is deliberately absent: starting a
# daemon is not something a message can ask for.
REMOTE_COMMANDS = frozenset(
    {
        "create-group",
        "groups",
        "set-acl",
        "add-member",
        "remove-member",
        "members",
        "status",
    }
)

HELP_TOKENS = frozenset({"help", "-h", "--help", "?"})


class ControlChannel:
    """LXMF destination that executes administrative commands for operators."""

    def __init__(self, config: HubConfig, store: Store, router: LXMF.LXMRouter):
        self.config = config
        self.store = store
        self.router = router
        self.operators = config.operator_hashes
        self.destination: RNS.Destination | None = None
        self._next_announce = 0.0

    # -- lifecycle -------------------------------------------------------

    def start(self) -> RNS.Destination | None:
        """Bring up the control destination. Returns None with no operators."""
        if not self.operators:
            return None
        self.destination = self.router.register_delivery_identity(
            self.router.identity, display_name=f"{self.config.hub_name} control"
        )
        if self.destination is None:
            RNS.log("Could not register the operator control destination", RNS.LOG_ERROR)
            return None
        RNS.log(
            f"Operator control on {RNS.prettyhexrep(self.destination.hash)}"
            f" for {len(self.operators)} operator(s)",
            RNS.LOG_NOTICE,
        )
        return self.destination

    def owns(self, destination_hash: bytes) -> bool:
        return self.destination is not None and destination_hash == self.destination.hash

    def announce_due(self) -> bool:
        if self.destination is None or time.time() < self._next_announce:
            return False
        self.router.announce(self.destination.hash)
        self._next_announce = time.time() + self.config.announce_interval_sec
        return True

    # -- inbound ---------------------------------------------------------

    def handle(self, message: LXMF.LXMessage) -> None:
        if not message.signature_validated:
            RNS.log("Dropping unverified message on the control destination", RNS.LOG_NOTICE)
            return
        if message.source_hash not in self.operators:
            RNS.log(
                "Dropping control message from non-operator"
                f" {RNS.prettyhexrep(message.source_hash)}",
                RNS.LOG_NOTICE,
            )
            return

        command = _text(message.content)
        RNS.log(
            f"Operator {RNS.prettyhexrep(message.source_hash)} sent: {command}",
            RNS.LOG_NOTICE,
        )
        self.reply(message.source_hash, self.execute(command))

    def execute(self, command: str) -> str:
        """Run one operator command line and return the text to send back."""
        try:
            tokens = shlex.split(command)
        except ValueError as exception:
            return f"Could not parse that command: {exception}"

        if not tokens or tokens[0].lower() in HELP_TOKENS:
            return self.help()
        if tokens[0] not in REMOTE_COMMANDS:
            return f"'{tokens[0]}' is not an operator command.\n\n{self.help()}"

        try:
            args = build_parser().parse_args(tokens)
            return administer(args, self.config, self.store) or "done"
        except CommandError as exception:
            return str(exception) or self.help()
        except Exception as exception:
            RNS.log(f"Operator command '{command}' failed: {exception}", RNS.LOG_ERROR)
            RNS.trace_exception(exception)
            return f"Command failed: {exception}"

    def help(self) -> str:
        return "Commands: " + ", ".join(sorted(REMOTE_COMMANDS))

    # -- outbound --------------------------------------------------------

    def reply(self, operator_hash: bytes, text: str) -> None:
        """Answer an operator directly, outside the client egress queue.

        Control traffic is a couple of packets per command and only ever goes to
        an operator, so it does not consume egress tokens meant for keeping group
        reflections off a saturated RF interface.
        """
        if self.destination is None:
            return
        identity = RNS.Identity.recall(operator_hash)
        if identity is None:
            RNS.Transport.request_path(operator_hash)
            RNS.log(
                f"No identity for operator {RNS.prettyhexrep(operator_hash)},"
                " dropping the reply",
                RNS.LOG_WARNING,
            )
            return

        target = RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE, LXMF.APP_NAME, "delivery"
        )
        message = LXMF.LXMessage(
            target,
            self.destination,
            content=text.encode("utf-8"),
            title=b"",
            desired_method=self._desired_method(),
        )
        self.router.handle_outbound(message)

    def _desired_method(self) -> int:
        if self.config.egress.prefer_propagation and self.router.get_outbound_propagation_node():
            return LXMF.LXMessage.PROPAGATED
        return LXMF.LXMessage.DIRECT


def _text(content: bytes | str | None) -> str:
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace").strip()
    return (content or "").strip()
