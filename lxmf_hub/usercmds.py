"""Commands a member can send inside a group.

Unmodified LXMF clients have no UI for a hub: the only channel a member has is a
message to the group. So a message whose first token is one of the verbs below is
consumed by the hub and answered instead of being reflected. Everything else is a
message, including anything that merely starts with a slash, so a path in a chat
still posts.

Answers use the durable user queue: an answer outlives an unknown path, a failed
delivery and a restart, and is paced by the same token bucket as reflections, so
a member cannot make the hub transmit faster by asking more often. A per-sender
interval bounds it further.

``/status`` is the situational-awareness command: it names the groups this hub
carries and their addresses, every peer hub with the age of its last answer and
whether its members are currently being served here, the queue depths, and who
the reader is. That is deliberately the same data failover acts on, computed with
the same effective timeout, so a member reading it and the hub adopting members
can never disagree.
"""

from __future__ import annotations

import time

import RNS

from .admin import CommandError, user_hash
from .config import HubConfig
from .control import operator_help
from .destinations import VirtualDestinationManager, group_destination_hash
from .failover import effective_peer_timeout, format_age
from .personas import PersonaError, PersonaRegistry
from .store import Store

VERB_HELP = "/help"
VERB_STATUS = "/status"
VERB_NAME = "/name"
VERB_WHOAMI = "/whoami"
VERB_LINK = "/link"
VERB_UNLINK = "/unlink"
VERB_WHO = "/who"
VERB_NAMES = "/names"

USAGE = (
    (VERB_HELP, "this list"),
    (VERB_STATUS, "groups, hubs, queues and who you are"),
    (f"{VERB_NAME} <username>", "claim or change your username"),
    (VERB_WHOAMI, "your username and linked devices"),
    (VERB_LINK, "get a one-time code to add another device"),
    (f"{VERB_LINK} <code>", "join this device to that persona"),
    (f"{VERB_UNLINK} <hash>", "drop one of your own devices"),
    (f"{VERB_WHO} <username>", "which devices a username is"),
    (VERB_NAMES, "usernames known to this hub"),
)

VERBS = frozenset(
    {
        VERB_HELP,
        VERB_STATUS,
        VERB_NAME,
        VERB_WHOAMI,
        VERB_LINK,
        VERB_UNLINK,
        VERB_WHO,
        VERB_NAMES,
    }
)

MAX_COMMAND_BYTES = 1024
MAX_NAMES_LISTED = 40


def verb_of(text: str) -> str | None:
    """The command a message is, or None if it is an ordinary message."""
    stripped = text.strip()
    if not stripped.startswith("/"):
        return None
    if len(stripped.encode("utf-8", "replace")) > MAX_COMMAND_BYTES:
        return None
    verb = stripped.split(maxsplit=1)[0].lower()
    return verb if verb in VERBS else None


class UserCommands:
    """Executes the in-band member commands and rate-limits the answers."""

    def __init__(
        self,
        config: HubConfig,
        store: Store,
        registry: PersonaRegistry,
        destinations: VirtualDestinationManager | None = None,
        started_at: float | None = None,
    ):
        self.config = config
        self.store = store
        self.registry = registry
        self.destinations = destinations
        self.started_at = time.time() if started_at is None else started_at
        self._answered: dict[bytes, float] = {}

    # -- dispatch --------------------------------------------------------

    def handle(self, group_id: str, sender_hash: bytes, text: str) -> bool:
        """Take a command off a group.

        Returns whether the message was a command, which is what tells the hub not
        to reflect it. A command that arrives inside the per-sender interval is
        still a command and is still swallowed -- otherwise a member hammering
        '/status' would see the flood land in the group as ordinary messages.
        """
        if not self.config.commands.enabled:
            return False
        verb = verb_of(text)
        if verb is None:
            return False
        now = time.time()
        last = self._answered.get(sender_hash, 0.0)
        if now - last < self.config.commands.min_reply_interval_sec:
            RNS.log(
                f"Dropping repeat command '{verb}' from {RNS.prettyhexrep(sender_hash)}",
                RNS.LOG_DEBUG,
            )
            return True
        self._prune_senders(now)
        self._answered[sender_hash] = now
        self.store.enqueue_user(group_id, sender_hash, self.execute(sender_hash, text))
        return True

    def _prune_senders(self, now: float) -> None:
        """Forget senders whose interval has elapsed, so the map cannot grow."""
        interval = self.config.commands.min_reply_interval_sec
        self._answered = {
            sender: when for sender, when in self._answered.items() if now - when < interval
        }

    def execute(self, sender_hash: bytes, text: str) -> str:
        """Run one command and return the text to answer with.

        Every path returns text, including every failure: a member with no answer
        cannot tell a rejected command from a hub that stopped listening.
        """
        tokens = text.strip().split()
        verb = tokens[0].lower()
        argument = tokens[1] if len(tokens) > 1 else None
        try:
            if verb == VERB_HELP:
                return self.help(sender_hash)
            if verb == VERB_STATUS:
                return self.status(sender_hash)
            if verb == VERB_NAME:
                return self._name(sender_hash, argument)
            if verb == VERB_WHOAMI:
                return self._whoami(sender_hash)
            if verb == VERB_LINK:
                return self._link(sender_hash, argument)
            if verb == VERB_UNLINK:
                return self._unlink(sender_hash, argument)
            if verb == VERB_WHO:
                return self._who(argument)
            if verb == VERB_NAMES:
                return self._names()
        except PersonaError as exception:
            return str(exception)
        except Exception as exception:
            RNS.log(f"Member command '{text}' failed: {exception}", RNS.LOG_ERROR)
            RNS.trace_exception(exception)
            return f"That command failed: {exception}"
        return self.help(sender_hash)

    # -- help ------------------------------------------------------------

    def help(self, sender_hash: bytes) -> str:
        width = max(len(usage) for usage, _summary in USAGE)
        lines = ["What you can send here:"]
        lines.extend(f"  {usage.ljust(width)}  {summary}" for usage, summary in USAGE)
        lines.append("Anything else is posted to the group.")
        if self._is_operator(sender_hash):
            # An operator's commands go to the control destination, not here, so
            # the listing says where as well as what.
            lines.append("")
            lines.append("You are an operator. Sent to the control address:")
            lines.extend(f"  {line}" for line in operator_help().splitlines()[1:])
        return "\n".join(lines)

    # -- status ----------------------------------------------------------

    def status(self, sender_hash: bytes) -> str:
        now = time.time()
        lines = [self._header(now), self._identity_line(sender_hash)]
        lines.extend(self._group_lines(now))
        lines.append(self._federation_line(now))
        lines.append(self._queue_line())
        if self._is_operator(sender_hash):
            lines.append(self._operator_line())
        return "\n".join(lines)

    def _header(self, now: float) -> str:
        groups = self.store.list_groups()
        peers = self._peers()
        return (
            f"{self.config.hub_name}: up {format_age(now - self.started_at)},"
            f" {len(groups)} group(s), {len(peers)} peer hub(s)"
        )

    def _identity_line(self, sender_hash: bytes) -> str:
        persona = self.registry.persona_for(sender_hash)
        if persona is None:
            return (
                f"you: {sender_hash.hex()}, no username yet"
                f" -- send '{VERB_NAME} <username>' to claim one"
            )
        devices = self.registry.devices(persona.persona_id)
        name = persona.name or "no username yet"
        return f"you: {name}, {len(devices)} device(s), posting from {sender_hash.hex()}"

    def _group_lines(self, now: float) -> list[str]:
        lines = []
        for group in self.store.list_groups():
            members = self.store.list_members(group.group_id)
            adopted = self.store.list_adopted(group.group_id)
            named = sum(
                1
                for user_hash, _role in members
                if self.store.display_name_for(user_hash) is not None
            )
            lines.append(
                f"{group.group_id} ({group.acl_mode}): {len(members)} member(s) here,"
                f" {len(adopted)} adopted, {named} named"
            )
            lines.append(f"  {self._local_address(group.group_id, group.identity_key)}  this hub")
            for entry in self.store.list_peer_groups(group.group_id):
                lines.append(
                    f"  {entry.destination_hash.hex()}  {entry.hub_name},"
                    f" {self._peer_state(entry.peer_hash, group.group_id, now)}"
                )
        if not lines:
            lines.append("This hub carries no groups yet.")
        return lines

    def _local_address(self, group_id: str, identity_key: bytes) -> str:
        """The address a client posts to, from the live destination where there is one."""
        if self.destinations is not None:
            destination = self.destinations.destination_for(group_id)
            if destination is not None:
                return destination.hash.hex()
        return group_destination_hash(identity_key).hex()

    def _peer_state(self, peer_hash: bytes, group_id: str, now: float) -> str:
        """What this hub can say about one peer, in the words failover would use."""
        adopted = self.store.adopted_for_peer(peer_hash, group_id)
        last = self.store.peer_last_success(peer_hash)
        if last is None:
            state = "never answered"
        elif now - last <= effective_peer_timeout(self.config):
            state = f"answered {format_age(now - last)} ago"
        else:
            state = f"silent for {format_age(now - last)}"
        if adopted:
            return f"{state}, {len(adopted)} of its member(s) served here"
        return state

    def _federation_line(self, now: float) -> str:
        if not self.config.federation.enabled:
            return "federation: off, this hub stands alone"
        peers = self._peers()
        if not peers:
            return "federation: on, no peers configured"
        timeout = effective_peer_timeout(self.config)
        live = 0
        for peer_hash in peers:
            last = self.store.peer_last_success(peer_hash)
            if last is not None and now - last <= timeout:
                live += 1
        return (
            f"federation: {live}/{len(peers)} peer(s) answering,"
            f" sync every {format_age(self.config.federation.sync_interval_sec)},"
            f" a peer counts as down after {format_age(timeout)}"
        )

    def _queue_line(self) -> str:
        return (
            f"queues: {self.store.egress_depth()} message(s),"
            f" {self.store.notice_depth()} notice(s),"
            f" {self.store.user_depth()} answer(s) waiting to go out"
        )

    def _operator_line(self) -> str:
        personas = self.store.list_personas()
        named = sum(1 for persona in personas if persona.name)
        return (
            f"operator: {self.store.control_depth()} control answer(s) queued,"
            f" {named}/{len(personas)} persona(s) named,"
            f" egress {self.config.egress.tokens_per_second}/s burst"
            f" {self.config.egress.burst}"
        )

    # -- persona commands ------------------------------------------------

    def _name(self, sender_hash: bytes, argument: str | None) -> str:
        if argument is None:
            persona = self.registry.persona_for(sender_hash)
            current = persona.name if persona is not None and persona.name else "nothing yet"
            return f"You are {current}. Send '{VERB_NAME} <username>' to change it."
        persona = self.registry.claim(sender_hash, argument)
        devices = self.registry.devices(persona.persona_id)
        return (
            f"You are {persona.name} on every hub in this federation,"
            f" from {len(devices)} device(s)."
        )

    def _whoami(self, sender_hash: bytes) -> str:
        persona = self.registry.persona_for(sender_hash)
        if persona is None:
            return (
                f"{sender_hash.hex()} has no persona."
                f" Send '{VERB_NAME} <username>' to claim a username."
            )
        lines = [
            f"{persona.name or 'no username yet'} (persona {persona.persona_id.hex()})",
        ]
        for device in self.registry.devices(persona.persona_id):
            marker = " <- this device" if device.user_hash == sender_hash else ""
            lines.append(f"  {device.user_hash.hex()}{marker}")
        return "\n".join(lines)

    def _link(self, sender_hash: bytes, argument: str | None) -> str:
        if argument is None:
            code, expires_at = self.registry.mint_code(sender_hash)
            return (
                f"Send '{VERB_LINK} {code}' from your other device within"
                f" {format_age(expires_at - time.time())}."
                " The code works once."
            )
        persona = self.registry.join(sender_hash, argument)
        devices = self.registry.devices(persona.persona_id)
        return (
            f"This device is now {persona.name or 'your persona'},"
            f" {len(devices)} device(s) in total."
        )

    def _unlink(self, sender_hash: bytes, argument: str | None) -> str:
        if argument is None:
            return f"Send '{VERB_UNLINK} <hash>' with the device to drop."
        target = _device_hash(argument)
        persona = self.registry.unlink(sender_hash, target)
        devices = self.registry.devices(persona.persona_id)
        return (
            f"{target.hex()} is no longer {persona.name or 'your persona'},"
            f" {len(devices)} device(s) left."
        )

    def _who(self, argument: str | None) -> str:
        if argument is None:
            return f"Send '{VERB_WHO} <username>'."
        persona = self.store.persona_by_name(argument)
        if persona is None:
            return f"Nobody here is called {argument}."
        devices = self.registry.devices(persona.persona_id)
        lines = [f"{persona.name} is {len(devices)} device(s):"]
        lines.extend(f"  {device.user_hash.hex()}" for device in devices)
        return "\n".join(lines)

    def _names(self) -> str:
        named = [persona for persona in self.store.list_personas() if persona.name]
        if not named:
            return "Nobody has claimed a username yet."
        lines = [f"{len(named)} username(s):"]
        for persona in named[:MAX_NAMES_LISTED]:
            devices = self.registry.devices(persona.persona_id)
            lines.append(f"  {persona.name}\t{len(devices)} device(s)")
        if len(named) > MAX_NAMES_LISTED:
            lines.append(f"  ... and {len(named) - MAX_NAMES_LISTED} more")
        return "\n".join(lines)

    # -- helpers ---------------------------------------------------------

    def notify_name_lost(self, persona_id: bytes, name: str) -> int:
        """Tell a persona's devices their name went to an earlier claim elsewhere.

        Sent into a group each device is a member of, because a group destination
        is the only address an unmodified client already holds.
        """
        queued = 0
        body = (
            f"The username '{name}' went to an earlier claim on another hub, so it is"
            f" no longer yours. Send '{VERB_NAME} <username>' to pick another."
        )
        for device in self.store.persona_devices(persona_id):
            groups = self.store.groups_for_member(device.user_hash)
            if not groups:
                continue
            self.store.enqueue_user(groups[0], device.user_hash, body)
            queued += 1
        return queued

    def _peers(self) -> list[bytes]:
        try:
            return self.config.federation.peer_hashes
        except ValueError:
            # A misconfigured peer entry is the operator's problem, not something
            # to turn a member's /status into an error.
            return []

    def _is_operator(self, sender_hash: bytes) -> bool:
        try:
            return sender_hash in self.config.operator_hashes
        except ValueError:
            return False


def _device_hash(value: str) -> bytes:
    """Parse a device hash the way an operator's is parsed, worded for a member."""
    try:
        return user_hash(value)
    except CommandError as exception:
        raise PersonaError(str(exception)) from exception
