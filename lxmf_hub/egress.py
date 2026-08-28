"""Client-facing egress.

Clients sit behind slow RF links, so reflections are never broadcast and never
sent in a burst. Every delivery is a queued item in SQLite -- so a restart
resumes exactly where the daemon left off -- released by a token bucket, and
handed either to an LXMF propagation node or to a direct RNS delivery.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import LXMF
import RNS

from .config import HubConfig
from .destinations import VirtualDestinationManager
from .directory import DirectoryChannel
from .hub import GroupHub
from .store import (
    SOURCE_DIRECTORY,
    SOURCE_GROUP,
    ControlItem,
    EgressItem,
    NoticeItem,
    Store,
    UserItem,
)
from .tickets import ScopedTickets

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from .control import ControlChannel

KIND_EGRESS = "egress"
KIND_NOTICE = "notice"
KIND_CONTROL = "control"
KIND_USER = "user"


class TokenBucket:
    """Rate limiter bounding how much the hub may put on local interfaces."""

    def __init__(self, rate: float, burst: float):
        self.rate = max(rate, 0.0)
        self.burst = max(burst, 1.0)
        self._tokens = self.burst
        self._updated = time.time()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
            self._updated = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def refund(self, tokens: float = 1.0) -> None:
        """Give back a token that bought no airtime.

        A queue row that turns out to be undeliverable -- its message pruned, its
        attempts spent, its group detached -- costs nothing on air, so charging it
        would let a batch of dead rows stall the messages behind them.
        """
        with self._lock:
            self._tokens = min(self.burst, self._tokens + tokens)

    def time_until(self, tokens: float = 1.0) -> float:
        with self._lock:
            if self.rate <= 0:
                return 60.0
            deficit = tokens - self._tokens
            return max(0.0, deficit / self.rate)


class EgressScheduler:
    """Drains the persistent egress queue at a bounded rate."""

    def __init__(
        self,
        config: HubConfig,
        store: Store,
        hub: GroupHub,
        router: LXMF.LXMRouter,
        destinations: VirtualDestinationManager,
        tickets: ScopedTickets,
        directory: DirectoryChannel | None = None,
        control: ControlChannel | None = None,
    ):
        self.config = config
        self.store = store
        self.hub = hub
        self.router = router
        self.destinations = destinations
        self.tickets = tickets
        self.directory = directory
        self.control = control
        self.bucket = TokenBucket(config.egress.tokens_per_second, config.egress.burst)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Rows handed to the router and not yet resolved by a callback, with the
        # message each one produced. Queue rows are re-armed before handoff so a
        # killed daemon retries them, but LXMF can legitimately spend longer
        # delivering one message than that backoff, and without this the scheduler
        # would pick the row up again and send the same message a second time --
        # while also counting an attempt against it.
        self._inflight: dict[tuple[str, int], tuple[float, LXMF.LXMessage]] = {}
        self._inflight_lock = threading.Lock()

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="egress", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                idle = self.tick()
            except Exception as exception:  # keep the scheduler alive
                RNS.log(f"Egress scheduler error: {exception}", RNS.LOG_ERROR)
                RNS.trace_exception(exception)
                idle = 5.0
            self._stop.wait(idle)

    def tick(self) -> float:
        """Send what is due and allowed. Returns how long to sleep next.

        Operator answers go first and are not paced: there are only ever a
        handful of them, an operator is waiting on each one, and letting a large
        client backlog delay the answer to ``status`` is exactly what makes the
        control channel look broken.

        Notices come next. They are short, they say where a group moved, and they
        are worthless once the reflections they explain have already arrived.
        They spend the same tokens as reflections, so an adoption of 40 members
        cannot dump 40 messages onto an RF interface at once.
        """
        replies = self.store.due_control(self.config.egress.batch_size)
        for reply in replies:
            if self._stop.is_set():
                return 0.5
            try:
                self.send_control(reply)
            except Exception as exception:
                RNS.log(
                    f"Control reply {reply.item_id} to"
                    f" {RNS.prettyhexrep(reply.recipient_hash)} failed: {exception}",
                    RNS.LOG_ERROR,
                )
                RNS.trace_exception(exception)
                self._release(KIND_CONTROL, reply.item_id)
                self.store.defer_control(reply.item_id, self._backoff(reply.attempts))

        answers = self.store.due_user(self.config.egress.batch_size)
        notices = self.store.due_notices(self.config.egress.batch_size)
        items = self.store.due_egress(self.config.egress.batch_size)
        if not answers and not notices and not items:
            return 0.5 if replies else 2.0

        for answer in answers:
            if self._stop.is_set():
                return 0.5
            if not self.bucket.consume():
                return max(0.5, self.bucket.time_until())
            if not self.send_user(answer):
                self.bucket.refund()

        for notice in notices:
            if self._stop.is_set():
                return 0.5
            if not self.bucket.consume():
                return max(0.5, self.bucket.time_until())
            if not self.send_notice(notice):
                self.bucket.refund()

        for item in items:
            if self._stop.is_set():
                break
            if not self.bucket.consume():
                return max(0.5, self.bucket.time_until())
            if not self.send(item):
                self.bucket.refund()
        return 0.5

    # -- in-flight bookkeeping -------------------------------------------

    def _in_flight(self, kind: str, item_id: int) -> bool:
        with self._inflight_lock:
            entry = self._inflight.get((kind, item_id))
            if entry is None:
                return False
            deadline, message = entry
            if deadline > time.time():
                return True
            if self._router_holds(message):
                # Past the timeout, but LXMF is still carrying the message: sending
                # it again would put a duplicate on air for a delivery that has not
                # finished. Wait another timeout instead.
                self._inflight[(kind, item_id)] = self._deadline(message)
                return True
            # The router is done with it and called neither callback. Treat it as
            # lost and let the row be retried.
            del self._inflight[(kind, item_id)]
            return False

    def _mark_in_flight(self, kind: str, item_id: int, message: LXMF.LXMessage) -> None:
        with self._inflight_lock:
            self._inflight[(kind, item_id)] = self._deadline(message)

    def _deadline(self, message: LXMF.LXMessage) -> tuple[float, LXMF.LXMessage]:
        return (time.time() + self.config.egress.delivery_timeout_sec, message)

    def _router_holds(self, message: LXMF.LXMessage) -> bool:
        """Whether LXMF still has this message queued for delivery."""
        return any(queued is message for queued in self.router.pending_outbound)

    def _release(self, kind: str, item_id: int) -> None:
        with self._inflight_lock:
            self._inflight.pop((kind, item_id), None)

    # -- delivery --------------------------------------------------------

    def send(self, item: EgressItem) -> bool:
        """Deliver one queue row. Returns whether anything went on air."""
        if self._in_flight(KIND_EGRESS, item.item_id):
            return False

        record = self.store.get_message(item.msg_hash)
        if record is None:
            # Message aged out of retention before it could be delivered.
            self.store.complete_egress(item.item_id)
            return False

        if item.attempts >= self.config.egress.max_attempts:
            RNS.log(
                f"Giving up on delivery to {RNS.prettyhexrep(item.recipient_hash)}"
                f" after {item.attempts} attempts",
                RNS.LOG_WARNING,
            )
            self.store.complete_egress(item.item_id)
            return False

        if self.destinations.destination_for(item.group_id) is None:
            # The group is not attached (yet): nothing can be built, so this is
            # not an attempt.
            self.store.defer_egress(
                item.item_id, self.config.egress.retry_backoff_sec, count_attempt=False
            )
            return False

        identity = RNS.Identity.recall(item.recipient_hash)
        if identity is None:
            # No known identity yet: ask the network, then come back to it with a
            # growing wait so an absent member is not asked for every grace.
            if not RNS.Transport.has_path(item.recipient_hash):
                RNS.Transport.request_path(item.recipient_hash)
            self.store.defer_egress(
                item.item_id, self._grace(item.graces), count_attempt=False
            )
            return True

        try:
            message = self.hub.build_reflection(record, identity)
        except Exception as exception:
            RNS.log(f"Could not build reflection: {exception}", RNS.LOG_ERROR)
            self.store.defer_egress(item.item_id, self._backoff(item.attempts))
            return False

        message.desired_method = self._desired_method()
        message.register_delivery_callback(self._delivered(item))
        message.register_failed_callback(self._failed(item))

        # Re-arm before handing off: if the daemon dies mid-transfer, the item is
        # still queued and simply retried after the backoff.
        self.store.defer_egress(item.item_id, self._backoff(item.attempts))
        self._mark_in_flight(KIND_EGRESS, item.item_id, message)
        self.tickets.seed(self.router, message)
        try:
            self.router.handle_outbound(message)
        except Exception as exception:
            # Neither callback will fire, so the row has to be released here or it
            # would sit in flight until the delivery timeout for nothing.
            self._release(KIND_EGRESS, item.item_id)
            RNS.log(
                f"Outbound handling failed for {RNS.prettyhexrep(item.recipient_hash)}:"
                f" {exception}",
                RNS.LOG_ERROR,
            )
        return True

    def send_notice(self, notice: NoticeItem) -> bool:
        """Send one notice. Returns whether anything went on air."""
        if self._in_flight(KIND_NOTICE, notice.item_id):
            return False

        if notice.attempts >= self.config.egress.max_attempts:
            RNS.log(
                f"Giving up on notice to {RNS.prettyhexrep(notice.recipient_hash)}"
                f" after {notice.attempts} attempts",
                RNS.LOG_WARNING,
            )
            self.store.complete_notice(notice.item_id)
            return False

        if notice.source == SOURCE_GROUP:
            if self.destinations.destination_for(notice.group_id) is None:
                # The group is gone or not attached yet. Try again later.
                self.store.defer_notice(
                    notice.item_id, self.config.egress.retry_backoff_sec, count_attempt=False
                )
                return False
        elif self.directory is None:
            # A directory answer queued before the directory was switched off.
            self.store.complete_notice(notice.item_id)
            return False

        identity = RNS.Identity.recall(notice.recipient_hash)
        if identity is None:
            if not RNS.Transport.has_path(notice.recipient_hash):
                RNS.Transport.request_path(notice.recipient_hash)
            self.store.defer_notice(
                notice.item_id, self._grace(notice.graces), count_attempt=False
            )
            return True

        try:
            message = self._build_notice(notice, identity)
        except Exception as exception:
            RNS.log(f"Could not build notice: {exception}", RNS.LOG_ERROR)
            self.store.defer_notice(notice.item_id, self._backoff(notice.attempts))
            return False

        message.desired_method = self._desired_method()
        message.register_delivery_callback(self._notice_delivered(notice))
        message.register_failed_callback(self._notice_failed(notice))
        self.store.defer_notice(notice.item_id, self._backoff(notice.attempts))
        self._mark_in_flight(KIND_NOTICE, notice.item_id, message)
        self.tickets.seed(self.router, message)
        try:
            self.router.handle_outbound(message)
        except Exception as exception:
            self._release(KIND_NOTICE, notice.item_id)
            RNS.log(
                f"Outbound handling failed for notice to"
                f" {RNS.prettyhexrep(notice.recipient_hash)}: {exception}",
                RNS.LOG_ERROR,
            )
        return True

    def send_user(self, answer: UserItem) -> bool:
        """Send one answer to a member's command. Returns whether it went on air.

        Paced with client tokens rather than jumping the queue like an operator
        answer: a member asking for status is not more urgent than the messages
        the group is waiting on, and a hub with many members could otherwise be
        made to spend all of its airtime answering questions.
        """
        if self._in_flight(KIND_USER, answer.item_id):
            return False

        if answer.attempts >= self.config.egress.max_attempts:
            RNS.log(
                f"Giving up on the answer to {RNS.prettyhexrep(answer.recipient_hash)}"
                f" after {answer.attempts} attempts",
                RNS.LOG_WARNING,
            )
            self.store.complete_user(answer.item_id)
            return False

        if self.destinations.destination_for(answer.group_id) is None:
            self.store.defer_user(
                answer.item_id, self.config.egress.retry_backoff_sec, count_attempt=False
            )
            return False

        identity = RNS.Identity.recall(answer.recipient_hash)
        if identity is None:
            if not RNS.Transport.has_path(answer.recipient_hash):
                RNS.Transport.request_path(answer.recipient_hash)
            self.store.defer_user(answer.item_id, self._grace(answer.graces), count_attempt=False)
            return True

        try:
            message = self.hub.build_notice(answer.group_id, identity, answer.body)
        except Exception as exception:
            RNS.log(f"Could not build the answer: {exception}", RNS.LOG_ERROR)
            self.store.defer_user(answer.item_id, self._backoff(answer.attempts))
            return False

        message.desired_method = self._desired_method()
        message.register_delivery_callback(lambda _message: self._user_done(answer, True))
        message.register_failed_callback(lambda _message: self._user_done(answer, False))
        self.store.defer_user(answer.item_id, self._backoff(answer.attempts))
        self._mark_in_flight(KIND_USER, answer.item_id, message)
        self.tickets.seed(self.router, message)
        try:
            self.router.handle_outbound(message)
        except Exception as exception:
            self._release(KIND_USER, answer.item_id)
            RNS.log(
                f"Outbound handling failed for the answer to"
                f" {RNS.prettyhexrep(answer.recipient_hash)}: {exception}",
                RNS.LOG_ERROR,
            )
        return True

    def send_control(self, reply: ControlItem) -> None:
        """Send one queued answer to an operator command."""
        if self._in_flight(KIND_CONTROL, reply.item_id):
            return

        if self.control is None:
            # Queued by a previous run that had operators configured.
            self.store.complete_control(reply.item_id)
            return

        if reply.attempts >= self.config.egress.max_attempts:
            RNS.log(
                f"Giving up on the answer to {RNS.prettyhexrep(reply.recipient_hash)}"
                f" after {reply.attempts} attempts",
                RNS.LOG_WARNING,
            )
            self.store.complete_control(reply.item_id)
            return

        identity = RNS.Identity.recall(reply.recipient_hash)
        if identity is None:
            if not RNS.Transport.has_path(reply.recipient_hash):
                RNS.Transport.request_path(reply.recipient_hash)
            self.store.defer_control(
                reply.item_id, self._grace(reply.graces), count_attempt=False
            )
            return

        try:
            message = self.control.build_reply(identity, reply.body)
        except Exception as exception:
            RNS.log(f"Could not build the operator answer: {exception}", RNS.LOG_ERROR)
            self.store.defer_control(reply.item_id, self._backoff(reply.attempts))
            return

        message.desired_method = self._control_method(reply)
        message.register_delivery_callback(
            lambda _message: self._control_done(reply, delivered=True)
        )
        message.register_failed_callback(
            lambda _message: self._control_done(reply, delivered=False)
        )
        self.store.defer_control(reply.item_id, self._backoff(reply.attempts))
        self._mark_in_flight(KIND_CONTROL, reply.item_id, message)
        self.tickets.seed(self.router, message)
        try:
            self.router.handle_outbound(message)
        except Exception as exception:
            self._release(KIND_CONTROL, reply.item_id)
            RNS.log(
                f"Outbound handling failed for the answer to"
                f" {RNS.prettyhexrep(reply.recipient_hash)}: {exception}",
                RNS.LOG_ERROR,
            )

    def _build_notice(self, notice: NoticeItem, identity: RNS.Identity) -> LXMF.LXMessage:
        if notice.source == SOURCE_DIRECTORY:
            if self.directory is None:
                raise ValueError("The directory is not running")
            return self.directory.build_reply(identity, notice.body)
        return self.hub.build_notice(notice.group_id, identity, notice.body)

    def _desired_method(self) -> int:
        if self.config.egress.prefer_propagation and self.router.get_outbound_propagation_node():
            return LXMF.LXMessage.PROPAGATED
        return LXMF.LXMessage.DIRECT

    def _control_method(self, reply: ControlItem) -> int:
        """Operator replies try a direct link first, regardless of the
        propagation preference, and only fall back once that attempt has
        failed -- direct delivery needs no PN round trip and is preferable
        whenever the operator is actually reachable.
        """
        if reply.attempts == 0 and self.router.get_outbound_propagation_node():
            return LXMF.LXMessage.DIRECT
        return self._desired_method()

    def _delivered(self, item: EgressItem):
        def callback(message: LXMF.LXMessage) -> None:
            self._release(KIND_EGRESS, item.item_id)
            self.store.complete_egress(item.item_id)
            RNS.log(
                f"Group '{item.group_id}' message {_milestone(message)}"
                f" {RNS.prettyhexrep(item.recipient_hash)}",
                RNS.LOG_DEBUG,
            )

        return callback

    def _failed(self, item: EgressItem):
        def callback(message: LXMF.LXMessage) -> None:
            # The row was re-armed before handoff, so releasing it is enough to
            # make the next tick after the backoff retry it.
            self._release(KIND_EGRESS, item.item_id)
            RNS.log(
                f"Delivery to {RNS.prettyhexrep(item.recipient_hash)} failed,"
                " leaving it queued for retry",
                RNS.LOG_DEBUG,
            )

        return callback

    def _notice_delivered(self, notice: NoticeItem):
        def callback(message: LXMF.LXMessage) -> None:
            self._release(KIND_NOTICE, notice.item_id)
            self.store.complete_notice(notice.item_id)

        return callback

    def _notice_failed(self, notice: NoticeItem):
        def callback(message: LXMF.LXMessage) -> None:
            self._release(KIND_NOTICE, notice.item_id)

        return callback

    def _user_done(self, answer: UserItem, delivered: bool) -> None:
        self._release(KIND_USER, answer.item_id)
        if delivered:
            self.store.complete_user(answer.item_id)

    def _control_done(self, reply: ControlItem, delivered: bool) -> None:
        self._release(KIND_CONTROL, reply.item_id)
        if delivered:
            self.store.complete_control(reply.item_id)
            return
        RNS.log(
            f"Answer to {RNS.prettyhexrep(reply.recipient_hash)} failed,"
            " leaving it queued for retry",
            RNS.LOG_DEBUG,
        )

    def _backoff(self, attempts: int) -> float:
        backoff = self.config.egress.retry_backoff_sec * (2**attempts)
        return min(backoff, self.config.egress.retry_backoff_max_sec)

    def _grace(self, graces: int) -> float:
        """How long to wait after asking the network for a recipient's path.

        A member who is simply offline should not be asked for once per grace
        interval forever, so the wait grows with each fruitless grace while
        staying under the retry ceiling.
        """
        grace = self.config.egress.path_request_grace_sec * (2 ** min(graces, 16))
        return min(grace, self.config.egress.retry_backoff_max_sec)


def _milestone(message: LXMF.LXMessage) -> str:
    """What a completed queue row actually achieved.

    A propagated message calls the delivery callback once the propagation node
    accepted it, which is the last thing LXMF can tell us: the client collects it
    later, on its own schedule. Logging both cases as "delivered" is what makes a
    hub look like it delivered messages nobody ever received.
    """
    if message.method == LXMF.LXMessage.PROPAGATED:
        return "handed to the propagation node for"
    return "delivered to"
