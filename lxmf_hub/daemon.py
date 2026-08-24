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
from functools import partial

import LXMF
import RNS

from .config import HubConfig
from .control import ControlChannel
from .crypto import MODE_NONE
from .destinations import VirtualDestinationManager
from .directory import DirectoryChannel
from .egress import EgressScheduler
from .failover import FailoverEngine
from .federation import FederationEngine
from .hub import GroupHub
from .personas import PersonaRegistry
from .store import Store
from .usercmds import UserCommands

GROUP_RELOAD_INTERVAL = 30.0
PRUNE_INTERVAL = 3600.0

# RNS truncates destination hashes to 128 bits.
DESTINATION_HASH_LENGTH = 16


def _destination_hash(value: str) -> bytes:
    """Parse a configured destination hash with an error naming the setting."""
    try:
        parsed = bytes.fromhex(value.strip())
    except ValueError as exception:
        raise ValueError(f"egress.propagation_node '{value}' is not hex") from exception
    if len(parsed) != DESTINATION_HASH_LENGTH:
        raise ValueError(
            f"egress.propagation_node '{value}' is not a"
            f" {DESTINATION_HASH_LENGTH}-byte destination hash"
        )
    return parsed


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
        self.registry: PersonaRegistry | None = None
        self.commands: UserCommands | None = None
        self.destinations: VirtualDestinationManager | None = None
        self.egress: EgressScheduler | None = None
        self.federation: FederationEngine | None = None
        self.control: ControlChannel | None = None
        self.directory: DirectoryChannel | None = None
        self.failover: FailoverEngine | None = None
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
        self.registry = PersonaRegistry(self.store)
        self.commands = UserCommands(
            self.config, self.store, self.registry, self.destinations
        )
        self.hub = GroupHub(
            self.config, self.store, self.router, self.destinations, self.commands
        )
        self.router.register_delivery_callback(self.deliver)

        # Before load_groups: LXMRouter.register_delivery_identity refuses to run
        # once any delivery destination is registered.
        self.control = ControlChannel(self.config, self.store, self.router)
        self.control.start()

        propagation_node = self.config.egress.propagation_node
        if propagation_node:
            self.router.set_outbound_propagation_node(_destination_hash(propagation_node))
            RNS.log(
                f"Queueing client egress via propagation node {propagation_node}", RNS.LOG_NOTICE
            )

        self.directory = DirectoryChannel(self.config, self.store, self.router)
        self.directory.start()

        self.destinations.load_groups()

        self.egress = EgressScheduler(
            self.config,
            self.store,
            self.hub,
            self.router,
            self.destinations,
            self.directory,
            self.control,
        )
        self.egress.start()

        if self.config.federation.enabled:
            self.federation = FederationEngine(
                self.config, self.store, self.hub, identity, self.registry, self.commands
            )
            self.federation.start()
            self.federation.announce()
            if self.config.failover.enabled:
                self.failover = FailoverEngine(self.config, self.store, self.hub)

        RNS.log(
            f"Hub running with {len(self.destinations.attached_groups())} group(s)"
            f" and {self.store.egress_depth()} queued delivery item(s)",
            RNS.LOG_NOTICE,
        )

    # -- delivery --------------------------------------------------------

    def deliver(self, message: LXMF.LXMessage) -> None:
        """Route an inbound LXMF message to the control channel or a group."""
        try:
            if self.control is not None and self.control.owns(message.destination_hash):
                self.control.handle(message)
                return
            if self.directory is not None and self.directory.owns(message.destination_hash):
                self.directory.handle(message)
                return
            self.hub.handle_inbound(message)
        except Exception as exception:
            RNS.log(f"Delivery handling failed: {exception}", RNS.LOG_ERROR)
            RNS.trace_exception(exception)

    # -- supervision -----------------------------------------------------

    def run(self) -> None:
        import faulthandler
        import signal
        faulthandler.register(signal.SIGUSR1, all_threads=True)
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
            # Each task is guarded on its own. Sharing one try block means a
            # failure in an early task -- a group whose identity will not load,
            # say -- silently skips failover checks and pruning for as long as it
            # keeps failing, which is exactly when they are needed.
            if now - last_reload >= GROUP_RELOAD_INTERVAL:
                last_reload = now
                self._guard("group hot-load", self._reload_groups)
            self._guard("group announce", self.destinations.announce_due)
            if self.control is not None:
                self._guard("control announce", self.control.announce_due)
            if self.directory is not None:
                self._guard("directory announce", self.directory.announce_due)
            if self.failover is not None:
                self._guard("failover check", partial(self.failover.check_due, now))
            if now - last_prune >= PRUNE_INTERVAL:
                last_prune = now
                self._guard("prune", self._prune)
            self._stop.wait(1.0)

        self.shutdown()

    def _guard(self, task: str, action) -> None:
        try:
            action()
        except Exception as exception:
            RNS.log(f"Hub supervision error during {task}: {exception}", RNS.LOG_ERROR)
            RNS.trace_exception(exception)

    def _reload_groups(self) -> None:
        for group_id in self.destinations.load_groups():
            RNS.log(f"Hot-loaded group '{group_id}'", RNS.LOG_NOTICE)

    def _prune(self) -> None:
        pruned = self.hub.prune()
        if pruned:
            RNS.log(f"Pruned {pruned} expired message(s)", RNS.LOG_NOTICE)
        # Spent and expired device codes are dead weight and, kept around, a
        # window for guessing one.
        self.store.prune_link_codes()

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
