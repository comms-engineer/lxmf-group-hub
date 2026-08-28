"""Per-destination outbound ticket cache.

``LXMRouter.available_tickets["outbound"]`` is keyed only by remote peer hash,
with no awareness of which local destination is talking to them. A hub
registers many local destinations (control, directory, one per group) under a
single router/identity, so a remote peer conversing with more than one of them
has its tickets collide: a ticket scoped to a reply from one destination
silently overwrites a still-valid one scoped to another, and
``handle_outbound()`` bakes whatever is cached into the stamp before the
sender can tell it was for the wrong conversation. The remote side then drops
the message for an invalid stamp, with no failure signal back to the sender.

This tracks tickets per ``(local_destination_hash, remote_peer_hash)`` pair
instead, and reseeds the router's single-slot cache immediately before each
send so ``handle_outbound()`` picks up the ticket meant for that destination,
or none at all rather than a wrong one.
"""

from __future__ import annotations

import threading
import time

import LXMF


class ScopedTickets:
    """Tracks outbound tickets per (local destination, remote peer) pair."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tickets: dict[tuple[bytes, bytes], list] = {}

    def remember(self, message: LXMF.LXMessage) -> None:
        """Record a ticket carried on a signature-validated inbound message."""
        if not message.signature_validated:
            return
        ticket_entry = message.fields.get(LXMF.FIELD_TICKET)
        if not isinstance(ticket_entry, list) or len(ticket_entry) < 2:
            return
        expires, ticket = ticket_entry[0], ticket_entry[1]
        if not isinstance(ticket, bytes) or not isinstance(expires, (int, float)):
            return
        key = (message.destination_hash, message.source_hash)
        with self._lock:
            self._tickets[key] = [expires, ticket]

    def seed(self, router: LXMF.LXMRouter, message: LXMF.LXMessage) -> None:
        """Point the router's cache at the ticket scoped to this send, or
        clear it so a wrongly-scoped leftover can't be picked up instead."""
        key = (message.source_hash, message.destination_hash)
        with self._lock:
            entry = self._tickets.get(key)
            if entry is not None and entry[0] <= time.time():
                del self._tickets[key]
                entry = None
        outbound = router.available_tickets.setdefault("outbound", {})
        if entry is None:
            outbound.pop(message.destination_hash, None)
        else:
            outbound[message.destination_hash] = list(entry)

    def clean(self) -> int:
        """Drop expired entries. Returns how many were removed."""
        now = time.time()
        with self._lock:
            expired = [key for key, entry in self._tickets.items() if entry[0] <= now]
            for key in expired:
                del self._tickets[key]
        return len(expired)
