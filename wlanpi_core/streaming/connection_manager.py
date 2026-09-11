import asyncio
import json
import math
import re
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from fastapi import WebSocket

from wlanpi_core.constants import DUMPCAP_FILE, IW_FILE
from wlanpi_core.core.logging import get_logger
from wlanpi_core.utils import network_config
from wlanpi_core.utils.general import run_command_async, terminate_process_async
from wlanpi_core.utils.validation import validate_namespace_name
from wlanpi_core.wlan.scan import iter_adapters
from wlanpi_core.streaming.models import (
    CaptureInterfaceConfig,
    CaptureStart,
    validate_capture_frequency,
    validate_capture_interface,
    validate_capture_width,
)

log = get_logger(__name__)
_IW_TIMEOUT_SEC = 5
#: Why a capture stopped, sent as data.reason on CAPTURE_STOPPED so a client
#: can tell a timer from a user stop without parsing the message.
_STOP_MESSAGES = {
    "OWNER_STOP": "Capture stopped.",
    "OWNER_DISCONNECT": "Capture stopped: owner disconnected.",
    "DURATION_ELAPSED": "Capture stopped: duration elapsed.",
    "NO_LISTENERS": "Capture stopped: no listeners remained.",
}
#: How long a detached bounded capture may run with nobody attached before it
#: is stopped. Covers "start, fork a saver, exit" racing the child's subscribe,
#: and a quick reconnect, without leaving a radio hopping into nowhere.
ORPHAN_GRACE_SEC = 15


class ConnectionManager:
    def __init__(self):
        self.clients: Dict[WebSocket, Dict[str, Any]] = {}
        self.interface_owners: Dict[str, WebSocket] = {}
        # Running captures by session id -> owning WebSocket. Sessions exist
        # so other authenticated principals can subscribe read-only (#141).
        self.sessions: Dict[str, WebSocket] = {}
        # Monotonic clock for session lifetime. An attribute so tests inject a
        # fake instead of patching `time` (AGENTS #7: that is process-global).
        self._clock = time.monotonic
        # Same reason: the duration timer sleeps through this, so a test can
        # release it on an event instead of waiting out the wall clock.
        self._sleep = asyncio.sleep

    async def connect(self, websocket: WebSocket) -> None:
        self.clients[websocket] = {
            "configs": {},
            "proc": None,
            "task": None,
            "channel_tasks": {},
            "interfaces": set(),
            "did": None,
            "session_id": None,
            "session_config": None,
            "started_mono": None,
            "duration_sec": None,
            "deadline_task": None,
            "stop_reason": None,
            # False once a bounded capture's owner socket has gone away; the
            # record then lives on as the session until it ends (P6.4).
            "owner_attached": True,
            "orphan_task": None,
            "namespace": None,
            "subscribers": set(),
            "subscribed_to": None,
        }
        await websocket.accept()

    def authenticate(self, websocket: WebSocket, did: str) -> None:
        """Record the verified principal for this socket. Commands are only
        dispatched after this is set (first-message auth in the endpoint)."""
        client = self.clients.get(websocket)
        if client is not None:
            client["did"] = did

    def is_authenticated(self, websocket: WebSocket) -> bool:
        client = self.clients.get(websocket)
        return bool(client and client.get("did"))

    def _claim_interfaces(
        self, websocket: WebSocket, interfaces: list[str]
    ) -> list[str]:
        """Atomically claim capture interfaces for one WebSocket client."""
        conflicts = sorted(
            iface
            for iface in interfaces
            if (owner := self.interface_owners.get(iface)) is not None
            and owner is not websocket
        )
        if conflicts:
            return conflicts

        client = self.clients[websocket]
        claimed = set(interfaces)
        for iface in claimed:
            self.interface_owners[iface] = websocket
        client["interfaces"] = claimed
        return []

    def _release_interfaces(self, websocket: WebSocket) -> None:
        client = self.clients.get(websocket)
        if not client:
            return
        for iface in client.get("interfaces", set()):
            if self.interface_owners.get(iface) is websocket:
                self.interface_owners.pop(iface, None)
        client["interfaces"] = set()

    def _detach_subscriber(self, websocket: WebSocket) -> None:
        client = self.clients.get(websocket)
        if not client:
            return
        session_id = client.get("subscribed_to")
        client["subscribed_to"] = None
        if not session_id:
            return
        owner_ws = self.sessions.get(session_id)
        if owner_ws is not None:
            owner_client = self.clients.get(owner_ws)
            if owner_client:
                owner_client["subscribers"].discard(websocket)
                self._arm_orphan_if_unattended(owner_ws, owner_client)

    # -- Detached bounded captures (P6.4) ---------------------------------
    #
    # A bounded capture belongs to a did, not a socket. When its owner's socket
    # goes away it keeps running - detached - until its deadline, an explicit
    # stop from the owner's did, or a grace period with nobody listening. A
    # perpetual capture still dies with its owner: nobody else could stop or
    # retune it, so nothing may keep it alive.

    @staticmethod
    def _is_detachable(client: Dict[str, Any]) -> bool:
        return client.get("duration_sec") is not None

    def _detached_holder(
        self, websocket: WebSocket, interfaces
    ) -> Optional[Tuple[WebSocket, Dict[str, Any], str]]:
        """If any named interface is held by a detached session this socket
        does not own as the attached owner, return that session. Used to
        refuse configure/start: detach is listen/stop only."""
        for iface in interfaces:
            owner_ws = self.interface_owners.get(iface)
            if owner_ws is None or owner_ws is websocket:
                continue
            owner_client = self.clients.get(owner_ws) or {}
            session_id = owner_client.get("session_id")
            if session_id and not owner_client.get("owner_attached", True):
                return owner_ws, owner_client, session_id
        return None

    async def _reject_control_of_detached(
        self, websocket: WebSocket, interfaces
    ) -> bool:
        """Refuse configure/start on interfaces a detached session holds.

        Returns True after sending CONTROL_NOT_ALLOWED. Regain control only
        by stopping that session and starting a new capture.
        """
        held = self._detached_holder(websocket, interfaces)
        if held is None:
            return False
        _, owner_client, session_id = held
        requester_did = (self.clients.get(websocket) or {}).get("did")
        same_owner = (
            requester_did is not None and requester_did == owner_client.get("did")
        )
        allowed = ["subscribe", "list_sessions"]
        if same_owner:
            allowed.append("stop")
            message = (
                f"Session {session_id} is detached; no control except stop. "
                "Subscribe to listen, or list_sessions. To change the radio, "
                f'stop it with {{"command": "stop", "session_id": "{session_id}"}} '
                "and start a new capture."
            )
        else:
            message = (
                f"Session {session_id} is detached; only its owner may stop it. "
                "Subscribe to listen, or list_sessions."
            )
        await self.send_event(
            websocket,
            "error",
            "CONTROL_NOT_ALLOWED",
            {
                "message": message,
                "session_id": session_id,
                "owner_attached": False,
                "allowed": allowed,
            },
        )
        return True

    def _detach_owner(self, owner_ws: WebSocket, client: Dict[str, Any]) -> None:
        client["owner_attached"] = False
        self._arm_orphan_if_unattended(owner_ws, client)

    def _arm_orphan_if_unattended(
        self, owner_ws: WebSocket, client: Dict[str, Any]
    ) -> None:
        if client.get("owner_attached", True) or client.get("subscribers"):
            return
        if not client.get("session_id") or client.get("orphan_task") is not None:
            return
        client["orphan_task"] = asyncio.create_task(self._orphan_watch(owner_ws))

    def _cancel_orphan(self, client: Dict[str, Any]) -> None:
        task = client.get("orphan_task")
        client["orphan_task"] = None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _orphan_watch(self, owner_ws: WebSocket) -> None:
        await self._sleep(ORPHAN_GRACE_SEC)
        client = self.clients.get(owner_ws)
        if client is None or client.get("orphan_task") is not asyncio.current_task():
            return
        client["orphan_task"] = None
        if client.get("owner_attached", True) or client.get("subscribers"):
            return  # someone attached during the grace; the session goes on
        await self.stop_streaming(owner_ws, notify=False, reason="NO_LISTENERS")

    def _drop_if_detached(self, owner_ws: WebSocket, client: Dict[str, Any]) -> None:
        """A detached owner's record only existed to carry the session; once
        the session has ended there is no socket left to serve."""
        if not client.get("owner_attached", True):
            self.clients.pop(owner_ws, None)

    async def stop_session(
        self, websocket: WebSocket, session_id: Optional[str]
    ) -> None:
        """`stop`: without a session_id, stop this socket's attached capture.
        A reconnecting socket is not the attached owner, so a bare stop is
        `STOP_REQUIRES_SESSION` (never a fake CAPTURE_STOPPED). With a
        session_id, stop that session if this socket owns it or shares the
        owner's did.
        """
        if session_id is None:
            client = self.clients.get(websocket)
            if (
                client
                and self._is_capturing(client)
                and client.get("owner_attached", True)
            ):
                await self.stop_streaming(websocket)
                return
            did = (client or {}).get("did")
            owned = sorted(
                sid
                for sid, owner_ws in self.sessions.items()
                if did
                and (self.clients.get(owner_ws) or {}).get("did") == did
            )
            if len(owned) == 1:
                message = (
                    "This connection has no attached capture. Stop a detached "
                    f'session with {{"command": "stop", "session_id": "{owned[0]}"}}.'
                )
            elif owned:
                message = (
                    "This connection has no attached capture. Stop a session "
                    'with {"command": "stop", "session_id": "<id>"}.'
                )
            else:
                message = "This connection has no attached capture to stop."
            await self.send_event(
                websocket,
                "error",
                "STOP_REQUIRES_SESSION",
                {"message": message, "sessions": owned},
            )
            return
        owner_ws = self.sessions.get(session_id)
        if owner_ws is None:
            await self.send_message_event(
                websocket,
                "error",
                "SESSION_NOT_FOUND",
                f"No running capture session: {session_id}",
            )
            return
        if owner_ws is websocket:
            await self.stop_streaming(websocket)
            return
        requester_did = (self.clients.get(websocket) or {}).get("did")
        owner_did = (self.clients.get(owner_ws) or {}).get("did")
        if requester_did is None or requester_did != owner_did:
            await self.send_message_event(
                websocket,
                "error",
                "SESSION_NOT_OWNED",
                "Only the principal that owns a capture may stop it.",
            )
            return
        # Fan-out already notifies subscribers. Ack the requester only when
        # they would otherwise hear nothing (they were not subscribed).
        was_subscriber = (
            (self.clients.get(websocket) or {}).get("subscribed_to") == session_id
        )
        await self.stop_streaming(owner_ws, reason="OWNER_STOP")
        if not was_subscriber:
            await self.send_event(
                websocket,
                "status",
                "CAPTURE_STOPPED",
                {
                    "message": _STOP_MESSAGES["OWNER_STOP"],
                    "reason": "OWNER_STOP",
                    "session_id": session_id,
                },
            )

    def _cancel_deadline(self, client: Dict[str, Any]) -> None:
        """Disarm a bounded capture's timer. Never cancels the current task:
        when the timer itself is the one stopping the capture, cancelling it
        would abort that very teardown at its next await."""
        task = client.get("deadline_task")
        client["deadline_task"] = None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _expire_after(self, websocket: WebSocket, duration_sec: int) -> None:
        await self._sleep(duration_sec)
        client = self.clients.get(websocket)
        if client is None or client.get("deadline_task") is not asyncio.current_task():
            return  # already stopped by another path; nothing to do
        await self.stop_streaming(websocket, reason="DURATION_ELAPSED")

    async def _end_session(
        self, client: Dict[str, Any], code: str, message: str, reason: str
    ) -> None:
        """Unregister a finished capture and notify/detach its subscribers.
        Idempotent: safe to call from both stream teardown and stop paths."""
        self._cancel_deadline(client)
        self._cancel_orphan(client)
        session_id = client.get("session_id")
        client["session_id"] = None
        client["session_config"] = None
        client["started_mono"] = None
        client["duration_sec"] = None
        client["stop_reason"] = None
        client["namespace"] = None
        if session_id:
            self.sessions.pop(session_id, None)
        for subscriber in list(client.get("subscribers", set())):
            sub_client = self.clients.get(subscriber)
            if sub_client:
                sub_client["subscribed_to"] = None
            client["subscribers"].discard(subscriber)
            await self.send_event(
                subscriber, "status", code, {"message": message, "reason": reason}
            )

    def _lifetime_fields(self, client: Dict[str, Any]) -> dict:
        """How long the capture has run and, when it is bounded, how long is
        left. Computed at send time from the monotonic clock, as integer
        seconds. A perpetual capture reports null duration/remaining rather
        than inventing an end it does not have."""
        started = client.get("started_mono")
        duration = client.get("duration_sec")
        elapsed = remaining = None
        if started is not None:
            now = self._clock()
            elapsed = max(0, int(now - started))
            if duration is not None:
                # Ceiling, so a capture that has just started says "60 left",
                # not 59, and elapsed + remaining add up to the duration.
                remaining = max(0, math.ceil(started + duration - now))
        return {
            "elapsed_sec": elapsed,
            "duration_sec": duration,
            "remaining_sec": remaining,
        }

    def _session_descriptor(self, session_id: str, owner_ws: WebSocket) -> dict:
        """Public description of a running capture: who owns it, the exact
        config it is running (channels/width/dwell per interface + filter) and
        how long it has been running, so a subscriber is never blind to what
        it is receiving."""
        owner_client = self.clients.get(owner_ws, {})
        return {
            "session_id": session_id,
            "owner": owner_client.get("did"),
            "interfaces": sorted(owner_client.get("interfaces", set())),
            "namespace": owner_client.get("namespace"),
            "config": owner_client.get("session_config"),
            **self._lifetime_fields(owner_client),
            "owner_attached": owner_client.get("owner_attached", True),
            "subscriber_count": len(owner_client.get("subscribers", ())),
        }

    async def subscribe(self, websocket: WebSocket, session_id: Optional[str]) -> None:
        """Attach this socket as a read-only listener on a running capture.

        Any authenticated principal on the device may listen. Configure is
        only the attached owner's socket; stop is that socket or any socket
        of the same did (by session_id). A detached session is listen/stop
        only — there is no way to reclaim configure without stopping it.
        """
        client = self.clients.get(websocket)
        if client is None:
            return
        owner_ws = self.sessions.get(session_id) if session_id else None
        if owner_ws is None:
            await self.send_message_event(
                websocket, "error", "SESSION_NOT_FOUND",
                f"No running capture session: {session_id}",
            )
            return
        if owner_ws is websocket:
            await self.send_message_event(
                websocket, "error", "SESSION_IS_OWN",
                "This socket owns that capture; it already receives its stream.",
            )
            return
        self._detach_subscriber(websocket)
        owner_client = self.clients[owner_ws]
        owner_client["subscribers"].add(websocket)
        self._cancel_orphan(owner_client)
        client["subscribed_to"] = session_id
        await self.send_event(
            websocket, "status", "SUBSCRIBED",
            self._session_descriptor(session_id, owner_ws),
        )

    async def unsubscribe(self, websocket: WebSocket) -> None:
        session_id = (self.clients.get(websocket) or {}).get("subscribed_to")
        self._detach_subscriber(websocket)
        await self.send_event(
            websocket, "status", "UNSUBSCRIBED", {"session_id": session_id}
        )

    async def send_session_list(self, websocket: WebSocket) -> None:
        sessions = [
            self._session_descriptor(session_id, owner_ws)
            for session_id, owner_ws in self.sessions.items()
        ]
        await self.send_event(websocket, "status", "SESSIONS", {"sessions": sessions})

    async def _broadcast_chunk(
        self, owner_ws: WebSocket, client: Dict[str, Any], chunk: bytes
    ) -> None:
        # A failing subscriber is dropped without disturbing the capture. A
        # failing owner ends a perpetual capture (as before) but only detaches
        # from a bounded one, which lives on for its listeners.
        if client.get("owner_attached", True):
            try:
                await owner_ws.send_bytes(chunk)
            except Exception:
                if not self._is_detachable(client):
                    raise
                self._detach_owner(owner_ws, client)
        for subscriber in list(client.get("subscribers", set())):
            try:
                await subscriber.send_bytes(chunk)
            except Exception:
                self._detach_subscriber(subscriber)

    def _start_channel_task(self, websocket: WebSocket, iface: str) -> None:
        """Spawn the hop task for one interface from its stored config.

        A config with no channels gets no task: the radio keeps whatever
        channel it is on, which is how a client parks a hopping capture.
        """
        client = self.clients[websocket]
        config = client["configs"].get(iface)
        if not config:
            return
        channels = config.get("channels", [])
        if not channels:
            return
        client["channel_tasks"][iface] = asyncio.create_task(
            self._hop_channels(
                websocket, iface, channels, config.get("dwell_time", 100)
            )
        )

    async def _restart_channel_task(self, websocket: WebSocket, iface: str) -> None:
        """Swap one interface's hop plan without touching the capture process."""
        client = self.clients[websocket]
        task = client.get("channel_tasks", {}).pop(iface, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log.debug("Channel hopping task restart failed: %s", exc)
        self._start_channel_task(websocket, iface)

    async def _stop_channel_tasks(self, client: Dict[str, Any]) -> None:
        channel_tasks = list(client.get("channel_tasks", {}).values())
        client["channel_tasks"] = {}
        for channel_task in channel_tasks:
            channel_task.cancel()
        for channel_task in channel_tasks:
            try:
                await channel_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log.debug("Channel hopping task shutdown failed: %s", exc)

    def configure(self, websocket: WebSocket, iface: str, config: Any) -> None:
        if websocket in self.clients:
            iface = validate_capture_interface(iface)
            validated = CaptureInterfaceConfig.model_validate(config)
            self.clients[websocket]["configs"][iface] = validated.model_dump()

    @staticmethod
    def _is_capturing(client: Dict[str, Any]) -> bool:
        task = client.get("task")
        proc = client.get("proc")
        return bool((task and not task.done()) or (proc and proc.returncode is None))

    @staticmethod
    def _config_applied_message(applied_live: list, deferred: list) -> str:
        parts = []
        if applied_live:
            parts.append(f"live on {', '.join(applied_live)}")
        if deferred:
            parts.append(f"stored for next start: {', '.join(deferred)}")
        if not parts:
            return "Configured."
        return f"Configured ({'; '.join(parts)})."

    def _refresh_session_config(self, client: Dict[str, Any]) -> None:
        """Re-snapshot the running config so list_sessions and SUBSCRIBED keep
        describing what the capture is actually doing after a live retune."""
        session_config = client.get("session_config")
        if not session_config:
            return
        session_config["interfaces"] = {
            iface: client["configs"].get(iface, {})
            for iface in session_config["interfaces"]
        }

    async def _notify_subscribers(
        self, client: Dict[str, Any], code: str, data: dict
    ) -> None:
        for subscriber in list(client.get("subscribers", set())):
            await self.send_event(subscriber, "status", code, data)

    async def apply_configuration(
        self, websocket: WebSocket, configs: Dict[str, CaptureInterfaceConfig]
    ) -> None:
        """Store a `configure` payload, applying it live where it can be.

        An interface that belongs to a capture already running for this client
        is retuned in place: only its hop task is swapped, so dumpcap keeps
        reading the same interface and the byte stream, the session id and the
        subscriber set all survive. Everything else is stored for the next
        `start`. The reply says which interfaces got which treatment, because a
        blanket "applied" on a config that only takes effect later is worse
        than no acknowledgement at all.
        """
        client = self.clients.get(websocket)
        if client is None:
            return

        if await self._reject_control_of_detached(websocket, list(configs)):
            return

        for iface, config in configs.items():
            self.configure(websocket, iface, config)

        running = (
            client.get("interfaces", set()) if self._is_capturing(client) else set()
        )
        applied_live = sorted(iface for iface in configs if iface in running)
        deferred = sorted(iface for iface in configs if iface not in running)

        for iface in applied_live:
            await self._restart_channel_task(websocket, iface)

        if applied_live:
            self._refresh_session_config(client)
            session_id = client.get("session_id")
            if session_id:
                await self._notify_subscribers(
                    client,
                    "CONFIG_CHANGED",
                    self._session_descriptor(session_id, websocket),
                )

        await self.send_event(
            websocket,
            "config",
            "CONFIG_APPLIED",
            {
                "message": self._config_applied_message(applied_live, deferred),
                "applied_live": applied_live,
                "deferred": deferred,
                "session_id": client.get("session_id"),
            },
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        self._detach_subscriber(websocket)
        client = self.clients.get(websocket)
        if client and self._is_capturing(client) and self._is_detachable(client):
            # Bounded: the session outlives this socket. Keep the record; it
            # is dropped when the session ends.
            self._detach_owner(websocket, client)
            return
        try:
            await self.stop_streaming(websocket, reason="OWNER_DISCONNECT")
        except Exception as e:
            log.warning(f"disconnect() failed: {e!r}")
        self.clients.pop(websocket, None)

    async def send_event(
        self, websocket: WebSocket, event_type: str, code: str, data: dict
    ) -> None:
        client = self.clients.get(websocket)
        if client is not None and not client.get("owner_attached", True):
            return  # detached owner: there is no socket behind this record
        try:
            await websocket.send_text(
                json.dumps(
                    {"type": "event", "event": event_type, "code": code, "data": data}
                )
            )
        except RuntimeError:
            pass
        except Exception as e:
            log.debug(f"send_event() failed: {e!r}")

    async def send_message_event(
        self, websocket: WebSocket, event_type: str, code: str, message: str
    ) -> None:
        await self.send_event(websocket, event_type, code, {"message": message})

    async def send_supported_frequencies(self, websocket: WebSocket) -> None:
        try:
            # Discover capture adapters across all namespaces via core's own
            # enumeration, then query each phy inside its namespace, so a
            # namespaced adapter is not invisible here.
            from wlanpi_core.adapters.interface import get_interface_info

            status = await asyncio.to_thread(network_config.status)
            adapters = [
                a for a in iter_adapters(status) if a["iface"].startswith("wlanpi")
            ]

            freqs_by_iface = {}
            for adapter in adapters:
                iface = adapter["iface"]
                namespace = adapter["namespace"]
                try:
                    info = await asyncio.to_thread(
                        get_interface_info, iface, namespace
                    )
                    phy = (info or {}).get("phy")
                    if not phy:
                        freqs_by_iface[iface] = []
                        continue
                    chan_output = (
                        await run_command_async(
                            self._ns_prefix(namespace)
                            + [IW_FILE, "phy", phy, "channels"],
                            timeout=_IW_TIMEOUT_SEC,
                        )
                    ).stdout

                    freqs = []
                    for line in chan_output.splitlines():
                        line = line.strip()
                        if "(disabled)" in line:
                            continue
                        match = re.match(r"\* (\d+) MHz", line)
                        if match:
                            freqs.append(int(match.group(1)))

                    freqs_by_iface[iface] = sorted(freqs)
                except Exception:
                    freqs_by_iface[iface] = []

            await self.send_event(
                websocket, "frequencies", "SUPPORTED_FREQUENCIES", freqs_by_iface
            )
        except Exception as e:
            await self.send_message_event(
                websocket,
                "error",
                "FREQ_FETCH_FAILED",
                f"Failed to fetch supported frequencies: {e}",
            )

    @staticmethod
    def _ns_prefix(namespace: Optional[str]) -> list:
        """Command prefix to run in a network namespace. Empty for root.

        wlanpi-core runs as root, so `ip netns exec` needs no sudo. The whole
        phy moves into a namespace together, so all vifs on it share one ns.
        """
        if not namespace:
            return []
        return ["ip", "netns", "exec", validate_namespace_name(namespace)]

    async def _resolve_namespace(
        self, interfaces: list[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Find the namespace the capture interfaces live in, via core's own
        adapter enumeration (network_config.status) - never a bespoke iw call.

        Returns (namespace, error). namespace is None for root. error is a
        short reason string when the interfaces are missing or split across
        namespaces (dumpcap cannot span netns).
        """
        status = await asyncio.to_thread(network_config.status)
        adapters = iter_adapters(status)
        by_name: Dict[str, list] = {}
        for a in adapters:
            by_name.setdefault(a["iface"], []).append(a)

        namespaces = set()
        for iface in interfaces:
            records = by_name.get(iface)
            if not records:
                return None, f"interface not found on this device: {iface}"
            namespaces.update(r["namespace"] for r in records)
        if len(namespaces) > 1:
            return None, (
                "capture interfaces span multiple namespaces "
                f"({sorted(str(n) for n in namespaces)}); one capture cannot"
            )
        return (namespaces.pop() if namespaces else None), None

    async def start_streaming(
        self,
        websocket: WebSocket,
        interfaces: list[str],
        pcap_filter: str,
        duration_sec: Optional[int] = None,
    ) -> None:
        client = self.clients.get(websocket)
        if not client:
            await self.send_message_event(
                websocket,
                "error",
                "CLIENT_NOT_FOUND",
                "WebSocket client not registered.",
            )
            return

        try:
            start = CaptureStart(
                interfaces=interfaces,
                pcap_filter=pcap_filter,
                duration_sec=duration_sec,
            )
        except ValueError:
            await self.send_message_event(
                websocket,
                "error",
                "CAPTURE_CONFIG_INVALID",
                "Invalid capture start configuration.",
            )
            return
        interfaces = start.interfaces
        pcap_filter = start.pcap_filter

        if self._is_capturing(client):
            await self.send_message_event(
                websocket,
                "error",
                "CAPTURE_ALREADY_RUNNING",
                "A capture is already running for this client.",
            )
            return

        if client["task"] or client["proc"] or client["channel_tasks"]:
            await self.stop_streaming(websocket, notify=False)

        missing = [i for i in interfaces if i not in client["configs"]]
        if missing:
            await self.send_message_event(
                websocket,
                "error",
                "CONFIG_MISSING",
                f"No config for: {', '.join(missing)}",
            )
            return

        conflicts = self._claim_interfaces(websocket, interfaces)
        if conflicts:
            if await self._reject_control_of_detached(websocket, conflicts):
                return
            await self.send_message_event(
                websocket,
                "error",
                "INTERFACE_IN_USE",
                f"Capture interface already in use: {', '.join(conflicts)}",
            )
            return

        namespace, ns_error = await self._resolve_namespace(interfaces)
        if ns_error:
            self._release_interfaces(websocket)
            await self.send_message_event(
                websocket, "error", "INTERFACE_NOT_AVAILABLE", ns_error
            )
            return
        client["namespace"] = namespace

        for iface in interfaces:
            config = client["configs"].get(iface)
            if not config:
                continue
            channels = config.get("channels", [])
            if channels:
                first = channels[0]
                freq = first.get("freq")
                width = first.get("width")
                if freq and width:
                    error = await self._set_channel(iface, freq, width, namespace)
                    if error:
                        # Warn but continue: capture on whatever channel the
                        # radio is currently on rather than aborting. This is
                        # what keeps single-radio devices usable when the
                        # managed vif briefly holds the phy (see the busy retry
                        # in _set_channel). Do not turn this into a hard abort.
                        await self.send_message_event(
                            websocket,
                            "error",
                            "CHANNEL_SET_FAILED",
                            f"Could not set initial channel for {iface}: {error}",
                        )

        args = self._ns_prefix(namespace) + [DUMPCAP_FILE]
        for iface in interfaces:
            args += ["-i", iface]
        if pcap_filter:
            args += ["-f", pcap_filter]
        args += ["-q", "-t", "-w", "-"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as e:
            self._release_interfaces(websocket)
            log.warning(f"Failed to start capture process: {e!r}")
            await self.send_message_event(
                websocket, "error", "CAPTURE_START_FAILED", "Failed to start capture."
            )
            return

        async def stream() -> None:
            try:
                while True:
                    chunk = await proc.stdout.read(4096)
                    if not chunk:
                        break
                    await self._broadcast_chunk(websocket, client, chunk)
                if client.get("owner_attached", True):
                    await self.send_event(
                        websocket,
                        "status",
                        "CAPTURE_ENDED",
                        {"message": "Capture ended.", "reason": "PROCESS_EXITED"},
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self.send_message_event(
                    websocket,
                    "error",
                    "CAPTURE_STREAM_ERROR",
                    "Error while streaming capture data.",
                )
            finally:
                await terminate_process_async(proc)
                await self._stop_channel_tasks(client)
                self._release_interfaces(websocket)
                # A stop path cancels this task before the process has exited;
                # it records why, so subscribers hear CAPTURE_STOPPED with that
                # reason rather than a misleading CAPTURE_ENDED.
                stop_reason = client.get("stop_reason")
                if stop_reason:
                    await self._end_session(
                        client,
                        "CAPTURE_STOPPED",
                        _STOP_MESSAGES.get(stop_reason, "Capture stopped."),
                        stop_reason,
                    )
                else:
                    await self._end_session(
                        client, "CAPTURE_ENDED", "Capture ended.", "PROCESS_EXITED"
                    )
                if client.get("proc") is proc:
                    client["proc"] = None
                if client.get("task") is asyncio.current_task():
                    client["task"] = None
                self._drop_if_detached(websocket, client)

        client["proc"] = proc
        client["task"] = asyncio.create_task(stream())
        client["channel_tasks"] = {}

        for iface in interfaces:
            self._start_channel_task(websocket, iface)

        session_id = f"cap_{secrets.token_hex(4)}"
        client["session_id"] = session_id
        client["started_mono"] = self._clock()
        client["owner_attached"] = True
        client["duration_sec"] = start.duration_sec
        if start.duration_sec is not None:
            # Core keeps the deadline so it holds even if the owner never
            # sends stop; the timer goes through the normal stop path.
            client["deadline_task"] = asyncio.create_task(
                self._expire_after(websocket, start.duration_sec)
            )
        # Snapshot the exact running config so list_sessions / SUBSCRIBED can
        # report it to subscribers (who otherwise only see raw frames).
        client["session_config"] = {
            "interfaces": {
                iface: client["configs"].get(iface, {}) for iface in interfaces
            },
            "pcap_filter": pcap_filter,
        }
        self.sessions[session_id] = websocket

        await self.send_event(
            websocket,
            "status",
            "CAPTURE_STARTED",
            {
                **self._session_descriptor(session_id, websocket),
                "message": f"Started capture on {', '.join(interfaces)}",
            },
        )

    async def stop_streaming(
        self,
        websocket: WebSocket,
        notify: bool = True,
        reason: str = "OWNER_STOP",
    ) -> None:
        client = self.clients.get(websocket)
        if not client:
            return

        self._cancel_deadline(client)
        task = client.get("task")
        proc = client.get("proc")
        if task:
            client["stop_reason"] = reason
            task.cancel()

        if task:
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.debug(f"Capture streaming task shutdown failed: {e}")

        if proc:
            await terminate_process_async(proc)

        await self._stop_channel_tasks(client)
        self._release_interfaces(websocket)
        message = _STOP_MESSAGES.get(reason, "Capture stopped.")
        await self._end_session(client, "CAPTURE_STOPPED", message, reason)

        client["task"] = None
        client["proc"] = None

        if notify and client.get("owner_attached", True):
            try:
                await self.send_event(
                    websocket,
                    "status",
                    "CAPTURE_STOPPED",
                    {"message": message, "reason": reason},
                )
            except Exception:
                pass
        self._drop_if_detached(websocket, client)

    async def shutdown_all(self) -> None:
        """Stop every capture and discard all client state during app shutdown."""
        for websocket in list(self.clients):
            try:
                await self.stop_streaming(websocket, notify=False)
            except Exception as exc:
                log.warning("Capture shutdown failed for a client: %r", exc)
        self.clients.clear()
        self.interface_owners.clear()
        self.sessions.clear()

    async def _hop_channels(
        self, websocket: WebSocket, iface: str, channels: list, dwell_time_ms: int
    ) -> None:
        async def apply_channel(ch: dict) -> None:
            freq = ch.get("freq")
            width = ch.get("width")

            if freq and width:
                error = await self._set_channel(
                    iface, freq, width, self.clients.get(websocket, {}).get("namespace")
                )
                if not error:
                    await self.send_message_event(
                        websocket,
                        "info",
                        "CHANNEL_SET",
                        f"{iface}: {freq} MHz / {width} MHz",
                    )
                else:
                    await self.send_message_event(
                        websocket,
                        "error",
                        "CHANNEL_SET_FAILED",
                        f"{iface}: failed to set {freq} MHz / {width} MHz ({error})",
                    )

        try:
            await self.send_message_event(
                websocket, "info", "CHANNEL_LIST_STARTED", f"Hopping on {iface}"
            )

            if not channels:
                return

            if len(channels) == 1:
                await apply_channel(channels[0])
                return

            while True:
                for ch in channels:
                    await apply_channel(ch)
                    await asyncio.sleep(dwell_time_ms / 1000)

        except asyncio.CancelledError:
            return
        except Exception:
            await self.send_message_event(
                websocket, "error", "CHANNEL_HOP_ERROR", f"{iface} hopping failed."
            )

    async def _set_channel(
        self, iface: str, freq: int, width: int, namespace: Optional[str] = None
    ) -> Optional[str]:
        """Tune a capture interface. Returns None on success, else a short
        reason suitable for the CHANNEL_SET_FAILED event (e.g. iw's
        'Device or resource busy (-16)' when a managed vif on the same phy
        blocks retuning - common on single-radio devices)."""
        try:
            iface = validate_capture_interface(iface)
            freq = validate_capture_frequency(freq)
            width = validate_capture_width(width)
        except ValueError as exc:
            return str(exc)

        cmd = self._ns_prefix(namespace) + [
            IW_FILE, "dev", iface, "set", "freq", str(freq), str(width)
        ]

        if width >= 40:
            center_frequency = self._center_frequency(freq, width)
            if center_frequency < 0:
                return "no valid center frequency for this channel/width"
            cmd.append(str(center_frequency))

        # A shared phy is briefly locked while another vif scans (e.g.
        # wpa_supplicant's periodic scan on a disconnected managed vif), so
        # EBUSY here is often transient: retry once before reporting.
        detail = ""
        for attempt in range(2):
            try:
                result = await run_command_async(
                    cmd,
                    raise_on_fail=False,
                    timeout=_IW_TIMEOUT_SEC,
                )
            except Exception as exc:
                return str(exc)
            if result.success:
                return None
            lines = (result.stderr or result.stdout or "").strip().splitlines()
            detail = lines[-1] if lines else f"iw exited {result.return_code}"
            if attempt == 0 and "busy" in detail.lower():
                await asyncio.sleep(0.3)
                continue
            break
        return detail

    def _center_frequency(self, freq: int, channel_width: int) -> int:
        def compute_center(start: int, span: int) -> int:
            return ((start * 2) + span) // 2

        def match_range(
            freq: int, base: int, limit: int, step: int, span: int
        ) -> int | None:
            for start in range(base, limit + 1, step):
                if start <= freq <= start + span:
                    return compute_center(start, span)
            return None

        if channel_width == 20:
            return freq

        if channel_width == 40:
            return (
                match_range(freq, 5180, 5700, 40, 20)
                or {5745: 5755, 5785: 5795, 5825: 5835, 5865: 5875}.get(freq)
                or match_range(freq, 5955, 7075, 40, 20)
                or -1
            )

        if channel_width == 80:
            return (
                match_range(freq, 5180, 5660, 80, 60)
                or {5745: 5775, 5825: 5855}.get(freq)
                or match_range(freq, 5955, 7055, 80, 60)
                or -1
            )

        if channel_width == 160:
            return (
                match_range(freq, 5180, 5500, 160, 140)
                or {5745: 5815}.get(freq)
                or match_range(freq, 5955, 6915, 160, 140)
                or -1
            )

        return -1
