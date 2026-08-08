"""Headless hub daemon.

Brings up Reticulum, the LXMF router, the group destinations, the egress
scheduler and the federation engine, then supervises them: announcing groups,
hot-loading groups added while running, and pruning expired history.
"""

from __future__ import annotations

import os
import signal
import threading
import time

import LXMF
import RNS

from .config import HubConfig
from .crypto import MODE_NONE
from .destinations import VirtualDestinationManager
from .egress import EgressScheduler
from .federation import FederationEngine
from .hub import GroupHub
from .store import Store

GROUP_RELOAD_INTERVAL = 30.0
PRUNE_INTERVAL = 3600.0


def load_hub_identity(path: str) -> RNS.Identity:
    if os.path.isfile(path):
        identity = RNS.Identity.from_file(path)
        if identity is not None:
            return identity
        raise ValueError(f"Could not load hub identity from {path}")
    identity = RNS.Identity()
    identity.to_file(path)
    RNS.log(f"Generated new hub identity at {path}", RNS.LOG_NOTICE)
    return identity


class HubDaemon:
    def __init__(self, config: HubConfig):
        self.config = config
        self.store: Store | None = None
        self.router: LXMF.LXMRouter | None = None
        self.hub: GroupHub | None = None
        self.destinations: VirtualDestinationManager | None = None
        self.egress: EgressScheduler | None = None
        self.federation: FederationEngine | None = None
        self._stop = threading.Event()

    # -- startup ---------------------------------------------------------

    def start(self) -> None:
        storage = self.config.resolved_storage_path
        os.makedirs(storage, exist_ok=True)

        RNS.Reticulum(
            configdir=self.config.resolved_reticulum_config_path,
            loglevel=self.config.log_level,
        )

        self.store = Store(self.config.database_path)
        if self.config.at_rest.mode != MODE_NONE:
            self.store.bind_cipher(self.config.at_rest.mode, self.config.at_rest_keyfile)

        identity = load_hub_identity(self.config.identity_path)
        self.router = LXMF.LXMRouter(
            identity=identity, storagepath=storage, name=self.config.hub_name
        )
        os.makedirs(self.router.ratchetpath, exist_ok=True)

        self.destinations = VirtualDestinationManager(self.router, self.store, self.config)
        self.hub = GroupHub(self.config, self.store, self.router, self.destinations)
        self.router.register_delivery_callback(self.hub.handle_inbound)

        propagation_node = self.config.egress.propagation_node
        if propagation_node:
            self.router.set_outbound_propagation_node(bytes.fromhex(propagation_node))
            RNS.log(
                f"Queueing client egress via propagation node {propagation_node}", RNS.LOG_NOTICE
            )

        self.destinations.load_groups()

        self.egress = EgressScheduler(
            self.config, self.store, self.hub, self.router, self.destinations
        )
        self.egress.start()

        if self.config.federation.enabled:
            self.federation = FederationEngine(self.config, self.store, self.hub, identity)
            self.federation.start()
            self.federation.announce()

        RNS.log(
            f"Hub running with {len(self.destinations.attached_groups())} group(s)"
            f" and {self.store.egress_depth()} queued delivery item(s)",
            RNS.LOG_NOTICE,
        )

    # -- supervision -----------------------------------------------------

    def run(self) -> None:
        self.start()
        self.supervise()

    def supervise(self) -> None:
        """Supervision loop for an already started daemon."""
        signal.signal(signal.SIGINT, self._signal)
        signal.signal(signal.SIGTERM, self._signal)

        last_reload = 0.0
        last_prune = time.time()
        while not self._stop.is_set():
            now = time.time()
            try:
                if now - last_reload >= GROUP_RELOAD_INTERVAL:
                    last_reload = now
                    for group_id in self.destinations.load_groups():
                        RNS.log(f"Hot-loaded group '{group_id}'", RNS.LOG_NOTICE)
                self.destinations.announce_due()
                if now - last_prune >= PRUNE_INTERVAL:
                    last_prune = now
                    pruned = self.hub.prune()
                    if pruned:
                        RNS.log(f"Pruned {pruned} expired message(s)", RNS.LOG_NOTICE)
            except Exception as exception:
                RNS.log(f"Hub supervision error: {exception}", RNS.LOG_ERROR)
                RNS.trace_exception(exception)
            self._stop.wait(1.0)

        self.shutdown()

    def _signal(self, signum, frame) -> None:
        RNS.log("Shutting down hub", RNS.LOG_NOTICE)
        self._stop.set()

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        if self.egress is not None:
            self.egress.stop()
        if self.federation is not None:
            self.federation.stop()
        if self.router is not None:
            self.router.exit_handler()
        if self.store is not None:
            self.store.close()
