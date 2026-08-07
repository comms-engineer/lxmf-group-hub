"""Client-facing egress.

Clients sit behind slow RF links, so reflections are never broadcast and never
sent in a burst. Every delivery is a queued item in SQLite -- so a restart
resumes exactly where the daemon left off -- released by a token bucket, and
handed either to an LXMF propagation node or to a direct RNS delivery.
"""

from __future__ import annotations

import threading
import time

import LXMF
import RNS

from .config import HubConfig
from .destinations import VirtualDestinationManager
from .hub import GroupHub
from .store import EgressItem, Store


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
    ):
        self.config = config
        self.store = store
        self.hub = hub
        self.router = router
        self.destinations = destinations
        self.bucket = TokenBucket(config.egress.tokens_per_second, config.egress.burst)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

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
        """Send what is due and allowed. Returns how long to sleep next."""
        items = self.store.due_egress(self.config.egress.batch_size)
        if not items:
            return 2.0

        for item in items:
            if self._stop.is_set():
                break
            if not self.bucket.consume():
                return max(0.5, self.bucket.time_until())
            self.send(item)
        return 0.5

    # -- delivery --------------------------------------------------------

    def send(self, item: EgressItem) -> None:
        record = self.store.get_message(item.msg_hash)
        if record is None:
            # Message aged out of retention before it could be delivered.
            self.store.complete_egress(item.item_id)
            return

        if item.attempts >= self.config.egress.max_attempts:
            RNS.log(
                f"Giving up on delivery to {RNS.prettyhexrep(item.recipient_hash)}"
                f" after {item.attempts} attempts",
                RNS.LOG_WARNING,
            )
            self.store.complete_egress(item.item_id)
            return

        if self.destinations.destination_for(item.group_id) is None:
            self.store.defer_egress(item.item_id, self.config.egress.retry_backoff_sec)
            return

        identity = RNS.Identity.recall(item.recipient_hash)
        if identity is None:
            # No known identity yet: ask the network once, then come back to it.
            if not RNS.Transport.has_path(item.recipient_hash):
                RNS.Transport.request_path(item.recipient_hash)
            self.store.defer_egress(
                item.item_id, self.config.egress.path_request_grace_sec, count_attempt=False
            )
            return

        try:
            message = self.hub.build_reflection(record, identity)
        except Exception as exception:
            RNS.log(f"Could not build reflection: {exception}", RNS.LOG_ERROR)
            self.store.defer_egress(item.item_id, self._backoff(item.attempts))
            return

        message.desired_method = self._desired_method()
        message.register_delivery_callback(self._delivered(item))
        message.register_failed_callback(self._failed(item))

        # Re-arm before handing off: if the daemon dies mid-transfer, the item is
        # still queued and simply retried after the backoff.
        self.store.defer_egress(item.item_id, self._backoff(item.attempts))
        try:
            self.router.handle_outbound(message)
        except Exception as exception:
            RNS.log(
                f"Outbound handling failed for {RNS.prettyhexrep(item.recipient_hash)}:"
                f" {exception}",
                RNS.LOG_ERROR,
            )

    def _desired_method(self) -> int:
        if self.config.egress.prefer_propagation and self.router.get_outbound_propagation_node():
            return LXMF.LXMessage.PROPAGATED
        return LXMF.LXMessage.DIRECT

    def _delivered(self, item: EgressItem):
        def callback(message: LXMF.LXMessage) -> None:
            self.store.complete_egress(item.item_id)
            RNS.log(
                f"Delivered group '{item.group_id}' message to"
                f" {RNS.prettyhexrep(item.recipient_hash)}",
                RNS.LOG_DEBUG,
            )

        return callback

    def _failed(self, item: EgressItem):
        def callback(message: LXMF.LXMessage) -> None:
            RNS.log(
                f"Delivery to {RNS.prettyhexrep(item.recipient_hash)} failed,"
                " leaving it queued for retry",
                RNS.LOG_DEBUG,
            )

        return callback

    def _backoff(self, attempts: int) -> float:
        backoff = self.config.egress.retry_backoff_sec * (2**attempts)
        return min(backoff, self.config.egress.retry_backoff_max_sec)
