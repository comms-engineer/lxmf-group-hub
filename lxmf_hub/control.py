"""Hub administration over LXMF.

An operator is not a special member: the control channel is its own LXMF
delivery destination on the hub identity, separate from every group destination,
and it accepts commands from the hashes in ``operator_identity`` and nobody else.
Authorisation is the Ed25519 signature RNS verified while unpacking the message,
so there is no password, token or session to steal.

Commands are the CLI verbs, sent as plain message text:

    add-member ops 8f1c...  ->  "8f1c... is member in ops"
    groups                  ->  one line per group with its destination hash

Every hash a command takes is an LXMF address -- a delivery destination hash,
which is what ``message.source_hash`` gives the hub for every inbound message --
never the sender's RNS identity hash. The two are different values derived from
the same identity, and a hub given an identity hash instead can never match it
against anything, so the member it was meant to authorise stays a stranger. In
an invite-only group a prospective member's messages are dropped before they
are a member, so there is no in-band command that can hand their address back;
it has to come from their own client (its address/identity screen), or from
'/whoami'/'/status' once they are already admitted somewhere on this hub.

State changes land in SQLite, and the daemon hot-loads them within
``GROUP_RELOAD_INTERVAL``, so a group created over LXMF starts announcing
without a restart.
"""

from __future__ import annotations

import shlex
import time

import LXMF
import RNS

from .admin import CommandError, administer, build_parser, command_usage
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
        "peers",
    }
)

HELP_TOKENS = frozenset({"help", "-h", "--help", "?"})

# An operator types a command on a phone keyboard, so a stray autocapitalised
# verb or a smart-quoted hash is a typing artefact rather than a different
# command. The bytes an operator can send are bounded so a large message cannot
# be turned into a large parse.
MAX_COMMAND_BYTES = 4096


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
        try:
            answer = self.execute(command)
            RNS.log(f"Operator command produced: {answer!r}", RNS.LOG_NOTICE)
            self.reply(message.source_hash, answer)
            RNS.log("Operator reply queued", RNS.LOG_NOTICE)
        except Exception as exception:
            RNS.log(f"Control handling blew up: {exception}", RNS.LOG_ERROR)
            RNS.trace_exception(exception)

    def execute(self, command: str) -> str:
        """Run one operator command line and return the text to send back.

        Every path returns text. A command that cannot be parsed, is not
        allowlisted, or raises anything at all still produces an answer, because
        an operator with no reply cannot tell a refused command from a hub that
        has stopped listening.
        """
        if len(command.encode("utf-8", "replace")) > MAX_COMMAND_BYTES:
            return f"That command is too long (limit {MAX_COMMAND_BYTES} bytes)."

        try:
            tokens = shlex.split(_normalise(command))
        except ValueError as exception:
            return f"Could not parse that command: {exception}\n\n{self.help()}"

        if not tokens or tokens[0].lower() in HELP_TOKENS:
            return self.help(tokens[1] if len(tokens) > 1 else None)

        verb = tokens[0].lower()
        if verb not in REMOTE_COMMANDS:
            return f"'{tokens[0]}' is not an operator command.\n\n{self.help()}"
        if len(tokens) > 1 and tokens[1].lower() in HELP_TOKENS:
            return self.help(verb)
        tokens[0] = verb

        try:
            args = build_parser().parse_args(tokens)
            return administer(args, self.config, self.store) or "done"
        except CommandError as exception:
            return str(exception) or self.help(verb)
        except Exception as exception:
            RNS.log(f"Operator command '{command}' failed: {exception}", RNS.LOG_ERROR)
            RNS.trace_exception(exception)
            return f"Command failed: {exception}"

    def help(self, verb: str | None = None) -> str:
        """Usage text taken from the parser, so it cannot drift from the verbs."""
        return operator_help(verb)

    # -- outbound --------------------------------------------------------

    def reply(self, operator_hash: bytes, text: str) -> None:
        """Queue an answer for an operator.

        Queued rather than handed straight to the router: the answer to a command
        that has already changed the database is not something to drop because
        the operator's path happens to be unknown this second, or because the
        first delivery attempt failed. The egress scheduler drains these ahead of
        client traffic and without spending client tokens, retrying with the same
        backoff as everything else, so an answer survives a restart.
        """
        if self.destination is None:
            return
        self.store.enqueue_control(operator_hash, text)

    def build_reply(self, recipient_identity: RNS.Identity, body: str) -> LXMF.LXMessage:
        """Build one queued answer, for the egress scheduler to send."""
        if self.destination is None:
            raise ValueError("The control destination is not running")
        target = RNS.Destination(
            recipient_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            LXMF.APP_NAME,
            "delivery",
        )
        return LXMF.LXMessage(
            target,
            self.destination,
            content=body.encode("utf-8"),
            title=b"",
        )


def operator_help(verb: str | None = None) -> str:
    """Operator usage text, taken from the parser so it cannot drift.

    Module level because an operator also asks for it with ``/help`` inside a
    group, where there is no control channel instance to ask.
    """
    if verb is not None and verb.lower() in REMOTE_COMMANDS:
        return build_parser().subcommands[verb.lower()].format_help().strip()

    parser = build_parser()
    lines = ["Commands:"]
    for name in sorted(REMOTE_COMMANDS):
        lines.append(f"  {command_usage(name)}")
        lines.append(f"      {parser.summaries[name]}")
    lines.append("Send 'help <command>' for one command in detail.")
    lines.append("Hashes may be pasted as <a1b2..>, a1:b2:.. or plain hex.")
    lines.append(
        "add-member/remove-member want a member's LXMF address (delivery"
        " destination hash), not their RNS identity hash. For an invite-only"
        " group get it from the member's own client -- their address is"
        " dropped before '/whoami' could ever answer, since they aren't a"
        " member yet."
    )
    return "\n".join(lines)


def _normalise(command: str) -> str:
    """Undo what a phone keyboard does to a command line.

    Smart quotes are the common one: a client that substitutes them turns a
    quoted display name into an unparseable line, and the operator sees a parse
    error for something they typed correctly.
    """
    for fancy, plain in (("\u201c", '"'), ("\u201d", '"'), ("\u2018", "'"), ("\u2019", "'")):
        command = command.replace(fancy, plain)
    return command.strip()


def _text(content: bytes | str | None) -> str:
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace").strip()
    return (content or "").strip()
