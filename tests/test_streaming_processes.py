import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from wlanpi_core.models.command_result import CommandResult
from wlanpi_core.streaming import connection_manager
from wlanpi_core.streaming.connection_manager import ConnectionManager
from wlanpi_core.streaming.models import (
    MAX_CAPTURE_DURATION_SEC,
    CaptureConfigurations,
    CaptureStart,
)


class BlockingStdout:
    async def read(self, size):
        await asyncio.Event().wait()


class CaptureProcess:
    def __init__(self):
        self.returncode = None
        self.stdout = BlockingStdout()
        self.terminated = False
        self.killed = False
        self._finished = asyncio.Event()

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self._finished.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self._finished.set()

    async def wait(self):
        await self._finished.wait()
        return self.returncode


def _connected_client(manager, websocket):
    manager.clients[websocket] = {
        "configs": {},
        "proc": None,
        "task": None,
        "channel_tasks": {},
        "interfaces": set(),
        "did": None,
        "session_id": None,
        "subscribers": set(),
        "subscribed_to": None,
        "namespace": None,
        "session_config": None,
        "started_mono": None,
        "duration_sec": None,
        "deadline_task": None,
        "stop_reason": None,
        "owner_attached": True,
        "orphan_task": None,
        "session_end": None,
        "pcapng_buffer": bytearray(),
        "pcapng_header": bytearray(),
        "pcapng_endian": None,
        "pcapng_header_complete": False,
        "subscription_queue": None,
        "subscription_task": None,
        "subscription_closing": False,
    }


def _configs(**by_interface):
    """Build exactly what the endpoint hands apply_configuration()."""
    return CaptureConfigurations.model_validate(by_interface).root


async def _drain_channel_task(manager, websocket, iface):
    """Await an interface's hop task so its retune has definitely happened.

    Single-channel plans apply once and return, so this terminates. Awaiting
    the task is the synchronization point; never poll the mock (AGENTS #1).
    """
    task = manager.clients[websocket]["channel_tasks"].get(iface)
    if task is not None:
        await task


def _root_status(*ifaces):
    """network_config.status()-shaped dict with adapters in root."""
    return {"root": {iface: {"type": "monitor"} for iface in ifaces}}


def _mock_root_adapters(mocker, *ifaces):
    """Keep start_streaming / frequency discovery off the real iw path (AGENTS #6)."""
    mocker.patch(
        "wlanpi_core.streaming.connection_manager.network_config.status",
        return_value=_root_status(*ifaces),
    )


@pytest.mark.asyncio
async def test_supported_frequencies_uses_bounded_async_commands(mocker):
    """Frequencies come from core adapter enumeration plus per-phy iw channels.

    The namespace-aware path never falls back to a root-only `iw dev` scrape.
    """
    manager = ConnectionManager()
    websocket = object()
    _mock_root_adapters(mocker, "wlanpi0")
    mocker.patch(
        "wlanpi_core.adapters.interface.get_interface_info",
        return_value={"phy": "phy0"},
    )
    run_command = mocker.patch.object(
        connection_manager,
        "run_command_async",
        new=AsyncMock(
            return_value=CommandResult("* 2412 MHz\n* 2437 MHz (disabled)\n", "", 0),
        ),
    )
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())

    await manager.send_supported_frequencies(websocket)

    run_command.assert_awaited_once_with(
        [connection_manager.IW_FILE, "phy", "phy0", "channels"],
        timeout=connection_manager._IW_TIMEOUT_SEC,
    )
    send_event.assert_awaited_once_with(
        websocket,
        "frequencies",
        "SUPPORTED_FREQUENCIES",
        {"wlanpi0": [2412]},
    )


@pytest.mark.asyncio
async def test_set_channel_uses_bounded_async_command(mocker):
    manager = ConnectionManager()
    run_command = mocker.patch.object(
        connection_manager,
        "run_command_async",
        new=AsyncMock(return_value=CommandResult("", "", 0)),
    )

    assert await manager._set_channel("wlanpi0", 5180, 20) is None

    run_command.assert_awaited_once_with(
        [connection_manager.IW_FILE, "dev", "wlanpi0", "set", "freq", "5180", "20"],
        raise_on_fail=False,
        timeout=connection_manager._IW_TIMEOUT_SEC,
    )


@pytest.mark.asyncio
async def test_capture_process_is_isolated_and_reaped_on_stop(mocker):
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    _mock_root_adapters(mocker, "wlanpi0")
    process = CaptureProcess()
    create_process = mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(return_value=process),
    )
    mocker.patch.object(manager, "send_message_event", new=AsyncMock())
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    manager.configure(websocket, "wlanpi0", {})

    await manager.start_streaming(websocket, ["wlanpi0"], "")

    listener = object()
    _connected_client(manager, listener)
    session_id = manager.clients[websocket]["session_id"]
    manager.clients[websocket]["subscribers"].add(listener)
    manager.clients[listener]["subscribed_to"] = session_id

    create_process.assert_awaited_once_with(
        connection_manager.DUMPCAP_FILE,
        "-i",
        "wlanpi0",
        "-q",
        "-t",
        "-w",
        "-",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    assert send_event.await_args.args[3]["namespace"] is None

    await manager.stop_streaming(websocket)

    assert process.terminated is True
    assert process.returncode == -15
    assert manager.clients[websocket]["proc"] is None
    assert manager.clients[websocket]["task"] is None
    send_event.assert_any_await(
        listener,
        "status",
        "CAPTURE_STOPPED",
        {"message": "Capture stopped.", "session_id": session_id},
    )


@pytest.mark.asyncio
async def test_second_capture_does_not_orphan_first_process(mocker):
    manager = ConnectionManager()
    websocket = object()
    running_task = mocker.Mock()
    running_task.done.return_value = False
    manager.clients[websocket] = {
        "configs": {},
        "proc": CaptureProcess(),
        "task": running_task,
        "channel_tasks": {},
    }
    create_process = mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(),
    )
    send_event = mocker.patch.object(
        manager,
        "send_message_event",
        new=AsyncMock(),
    )

    await manager.start_streaming(websocket, ["wlanpi0"], "")

    create_process.assert_not_awaited()
    send_event.assert_awaited_once_with(
        websocket,
        "error",
        "CAPTURE_ALREADY_RUNNING",
        "A capture is already running for this client.",
    )


@pytest.mark.asyncio
async def test_capture_rejects_missing_interface_config_before_process(mocker):
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    create_process = mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(),
    )
    send_event = mocker.patch.object(
        manager,
        "send_message_event",
        new=AsyncMock(),
    )

    await manager.start_streaming(websocket, ["wlanpi0"], "")

    create_process.assert_not_awaited()
    send_event.assert_awaited_once_with(
        websocket,
        "error",
        "CONFIG_MISSING",
        "No config for: wlanpi0",
    )


@pytest.mark.asyncio
async def test_capture_interface_can_only_have_one_owner(mocker):
    manager = ConnectionManager()
    first_websocket = object()
    second_websocket = object()
    _connected_client(manager, first_websocket)
    _connected_client(manager, second_websocket)
    _mock_root_adapters(mocker, "wlanpi0")
    manager.configure(first_websocket, "wlanpi0", {})
    manager.configure(second_websocket, "wlanpi0", {})
    process = CaptureProcess()
    create_process = mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(return_value=process),
    )
    send_event = mocker.patch.object(
        manager,
        "send_message_event",
        new=AsyncMock(),
    )

    await manager.start_streaming(first_websocket, ["wlanpi0"], "")
    await manager.start_streaming(second_websocket, ["wlanpi0"], "")

    assert create_process.await_count == 1
    assert manager.interface_owners == {"wlanpi0": first_websocket}
    send_event.assert_any_await(
        second_websocket,
        "error",
        "INTERFACE_IN_USE",
        "Capture interface already in use: wlanpi0",
    )

    await manager.stop_streaming(first_websocket, notify=False)
    assert manager.interface_owners == {}


@pytest.mark.asyncio
async def test_shutdown_all_reaps_captures_and_discards_clients(mocker):
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    _mock_root_adapters(mocker, "wlanpi0")
    manager.configure(websocket, "wlanpi0", {})
    process = CaptureProcess()
    mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(return_value=process),
    )
    mocker.patch.object(manager, "send_message_event", new=AsyncMock())

    await manager.start_streaming(websocket, ["wlanpi0"], "")
    await manager.shutdown_all()

    assert process.terminated is True
    assert manager.clients == {}
    assert manager.interface_owners == {}
    assert manager.sessions == {}


@pytest.mark.parametrize(
    "config",
    [
        {"dwell_time": 1},
        {"channels": [{"freq": 2412, "width": 10}]},
        {"channels": [{"freq": 3000, "width": 20}]},
        {"channels": [{"freq": 99999, "width": 20}]},
        {"unknown": True},
    ],
)
def test_capture_rejects_unsafe_interface_configuration(config):
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)

    with pytest.raises(ValueError):
        manager.configure(websocket, "wlanpi0", config)

    assert manager.clients[websocket]["configs"] == {}


@pytest.mark.asyncio
async def test_capture_rejects_invalid_start_before_process(mocker):
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    create_process = mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(),
    )
    send_event = mocker.patch.object(
        manager,
        "send_message_event",
        new=AsyncMock(),
    )

    await manager.start_streaming(websocket, ["--help"], "tcp\nport 22")

    create_process.assert_not_awaited()
    send_event.assert_awaited_once_with(
        websocket,
        "error",
        "CAPTURE_CONFIG_INVALID",
        "Invalid capture start configuration.",
    )


async def _running_capture(manager, mocker, websocket, channels, duration_sec=None):
    """Start a capture with mocked process/iw and settle its first retune."""
    _mock_root_adapters(mocker, "wlanpi0")
    process = CaptureProcess()
    create_process = mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(return_value=process),
    )
    mocker.patch.object(manager, "send_message_event", new=AsyncMock())
    set_channel = mocker.patch.object(
        manager, "_set_channel", new=AsyncMock(return_value=None)
    )
    manager.configure(websocket, "wlanpi0", {"channels": channels})
    await manager.start_streaming(websocket, ["wlanpi0"], "", duration_sec)
    if len(channels) <= 1:
        # Multi-channel plans hop forever; only a parked one can be awaited.
        await _drain_channel_task(manager, websocket, "wlanpi0")
    return process, create_process, set_channel


@pytest.mark.asyncio
async def test_configure_mid_capture_retunes_without_restarting_capture(mocker):
    """Retune mid-capture without restarting dumpcap or changing session_id."""
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    process, create_process, set_channel = await _running_capture(
        manager, mocker, websocket, [{"freq": 2412, "width": 20}]
    )
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    session_id = manager.clients[websocket]["session_id"]
    set_channel.reset_mock()

    await manager.apply_configuration(
        websocket, _configs(wlanpi0={"channels": [{"freq": 5180, "width": 80}]})
    )
    await _drain_channel_task(manager, websocket, "wlanpi0")

    set_channel.assert_awaited_once_with("wlanpi0", 5180, 80, None)
    assert create_process.await_count == 1
    assert process.terminated is False
    assert manager.clients[websocket]["session_id"] == session_id

    _, _, code, data = send_event.await_args_list[-1].args
    assert code == "CONFIG_APPLIED"
    assert data["applied_live"] == ["wlanpi0"]
    assert data["deferred"] == []
    assert data["session_id"] == session_id

    await manager.stop_streaming(websocket, notify=False)


@pytest.mark.asyncio
async def test_configure_while_idle_is_stored_and_reported_as_deferred(mocker):
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())

    await manager.apply_configuration(
        websocket, _configs(wlanpi0={"channels": [{"freq": 2412, "width": 20}]})
    )

    assert manager.clients[websocket]["channel_tasks"] == {}
    assert manager.clients[websocket]["configs"]["wlanpi0"]["channels"] == [
        {"freq": 2412, "width": 20}
    ]
    _, _, code, data = send_event.await_args_list[-1].args
    assert code == "CONFIG_APPLIED"
    assert data["applied_live"] == []
    assert data["deferred"] == ["wlanpi0"]


@pytest.mark.asyncio
async def test_live_retune_refreshes_session_config_and_tells_subscribers(mocker):
    """Refresh session_config and queue CONFIG_CHANGED to subscribers."""
    manager = ConnectionManager()
    owner = object()
    subscriber = object()
    _connected_client(manager, owner)
    _connected_client(manager, subscriber)
    await _running_capture(manager, mocker, owner, [{"freq": 2412, "width": 20}])
    session_id = manager.clients[owner]["session_id"]
    queue: asyncio.Queue[tuple[str, object]] = asyncio.Queue(maxsize=128)
    manager.clients[subscriber]["subscribed_to"] = session_id
    manager.clients[subscriber]["subscription_queue"] = queue
    manager.clients[owner]["subscribers"].add(subscriber)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())

    await manager.apply_configuration(
        owner,
        _configs(
            wlanpi0={"channels": [{"freq": 5180, "width": 80}], "dwell_time": 500}
        ),
    )
    await _drain_channel_task(manager, owner, "wlanpi0")

    running = manager.clients[owner]["session_config"]["interfaces"]["wlanpi0"]
    assert running == {"channels": [{"freq": 5180, "width": 80}], "dwell_time": 500}

    kind, event_text = queue.get_nowait()
    assert kind == "event"
    payload = json.loads(event_text)
    assert payload["code"] == "CONFIG_CHANGED"
    assert payload["data"]["config"]["interfaces"]["wlanpi0"] == running
    assert manager.clients[subscriber]["subscribed_to"] == session_id
    changed = [
        call for call in send_event.await_args_list if call.args[2] == "CONFIG_CHANGED"
    ]
    assert changed == []

    await manager.stop_streaming(owner, notify=False)


@pytest.mark.asyncio
async def test_live_retune_to_empty_channel_list_parks_the_radio(mocker):
    """Empty channels cancel the hop task without stopping the capture."""
    manager = ConnectionManager()
    websocket = object()
    _connected_client(manager, websocket)
    process, _, _ = await _running_capture(
        manager,
        mocker,
        websocket,
        [{"freq": 2412, "width": 20}, {"freq": 2437, "width": 20}],
    )
    mocker.patch.object(manager, "send_event", new=AsyncMock())
    hop_task = manager.clients[websocket]["channel_tasks"]["wlanpi0"]

    await manager.apply_configuration(websocket, _configs(wlanpi0={"channels": []}))

    assert manager.clients[websocket]["channel_tasks"] == {}
    assert hop_task.done()
    assert process.terminated is False

    await manager.stop_streaming(websocket, notify=False)


@pytest.mark.asyncio
async def test_set_channel_retries_once_when_phy_is_busy(mocker):
    """A scan on a shared phy makes iw fail with EBUSY transiently.

    One retry absorbs the common collision.
    """
    manager = ConnectionManager()
    busy = CommandResult("", "command failed: Device or resource busy (-16)", 240)
    ok = CommandResult("", "", 0)
    run = mocker.patch(
        "wlanpi_core.streaming.connection_manager.run_command_async",
        side_effect=[busy, ok],
    )

    assert await manager._set_channel("wlanpi0", 2412, 20) is None
    assert run.call_count == 2


async def test_set_channel_does_not_retry_non_busy_failures(mocker):
    manager = ConnectionManager()
    failed = CommandResult("", "command failed: Operation not supported (-95)", 240)
    run = mocker.patch(
        "wlanpi_core.streaming.connection_manager.run_command_async",
        return_value=failed,
    )

    error = await manager._set_channel("wlanpi0", 2412, 20)
    assert error is not None and "not supported" in error
    assert run.call_count == 1


async def test_set_channel_rejects_invalid_center_before_command(mocker):
    manager = ConnectionManager()
    run_command = mocker.patch.object(
        connection_manager,
        "run_command_async",
        new=AsyncMock(),
    )

    assert await manager._set_channel("wlanpi0", 5000, 160) is not None
    run_command.assert_not_awaited()


# --- Session lifetime on the descriptor (P6.2) -----------------------------


class _FakeClock:
    """Injected in place of manager._clock; tests move `now` explicitly."""

    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_capture_started_and_descriptor_report_elapsed_from_manager_clock(
    mocker,
):
    """Report elapsed_sec from the injected manager clock.

    Nothing here sleeps or patches ``time`` (AGENTS #1, #7). A perpetual
    capture reports null duration/remaining.
    """
    manager = ConnectionManager()
    clock = _FakeClock(1000.0)
    manager._clock = clock
    owner = object()
    _connected_client(manager, owner)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    await _running_capture(manager, mocker, owner, [{"freq": 2412, "width": 20}])
    session_id = manager.clients[owner]["session_id"]

    started = next(
        call for call in send_event.await_args_list if call.args[2] == "CAPTURE_STARTED"
    )
    assert started.args[3]["elapsed_sec"] == 0
    assert started.args[3]["duration_sec"] is None
    assert started.args[3]["remaining_sec"] is None

    clock.now = 1030.7
    descriptor = manager._session_descriptor(session_id, owner)
    assert descriptor["elapsed_sec"] == 30
    assert descriptor["duration_sec"] is None
    assert descriptor["remaining_sec"] is None

    await manager.stop_streaming(owner, notify=False)
    assert manager.clients[owner]["started_mono"] is None


@pytest.mark.asyncio
async def test_session_list_and_subscribed_carry_lifetime_fields(mocker):
    """SESSIONS uses send_event; SUBSCRIBED arrives on the subscription queue."""
    manager = ConnectionManager()
    clock = _FakeClock(500.0)
    manager._clock = clock
    owner = object()
    subscriber = object()
    _connected_client(manager, owner)
    _connected_client(manager, subscriber)
    await _running_capture(manager, mocker, owner, [{"freq": 2412, "width": 20}])
    session_id = manager.clients[owner]["session_id"]
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    # Keep the pump from draining the queue so the test can read SUBSCRIBED.
    mocker.patch.object(manager, "_send_subscription", new=AsyncMock())

    clock.now = 512.2
    await manager.send_session_list(subscriber)
    await manager.subscribe(subscriber, session_id)

    listing = next(
        call for call in send_event.await_args_list if call.args[2] == "SESSIONS"
    )
    (session,) = listing.args[3]["sessions"]
    assert session["session_id"] == session_id
    assert session["elapsed_sec"] == 12
    assert session["remaining_sec"] is None

    queue = manager.clients[subscriber]["subscription_queue"]
    kind, event_text = queue.get_nowait()
    assert kind == "event"
    payload = json.loads(event_text)
    assert payload["code"] == "SUBSCRIBED"
    assert payload["data"]["elapsed_sec"] == 12
    assert payload["data"]["duration_sec"] is None

    sub_task = manager.clients[subscriber]["subscription_task"]
    if sub_task is not None:
        sub_task.cancel()
        try:
            await sub_task
        except asyncio.CancelledError:
            pass
    await manager.stop_streaming(owner, notify=False)


# --- Bounded captures: duration_sec on start (P6.3) -------------------------


class _FakeSleep:
    """Injected as manager._sleep.

    Records the requested delay and blocks until the test releases that delay,
    so expiry is driven by an event and never by the wall clock (AGENTS #1).
    Keyed by delay because a detached bounded capture has two sleepers: the
    deadline and the orphan grace.
    """

    def __init__(self):
        self.delays = []
        self._events = {}

    def release(self, delay):
        self.event_for(delay).set()

    def event_for(self, delay):
        return self._events.setdefault(delay, asyncio.Event())

    async def __call__(self, delay):
        self.delays.append(delay)
        await self.event_for(delay).wait()


class EndingStdout:
    """A capture process whose output ends as soon as it is read."""

    async def read(self, size):
        return b""


def _events(send_event, code):
    return [call for call in send_event.await_args_list if call.args[2] == code]


@pytest.mark.parametrize("value", [None, 1, 300, MAX_CAPTURE_DURATION_SEC])
def test_capture_start_accepts_valid_duration(value):
    start = CaptureStart(interfaces=["wlanpi0"], duration_sec=value)
    assert start.duration_sec == value


@pytest.mark.parametrize(
    "value", [0, -1, MAX_CAPTURE_DURATION_SEC + 1, True, 5.5, "300"]
)
def test_capture_start_rejects_invalid_duration(value):
    with pytest.raises(ValueError):
        CaptureStart(interfaces=["wlanpi0"], duration_sec=value)


@pytest.mark.asyncio
async def test_start_without_duration_is_perpetual(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    _connected_client(manager, owner)
    await _running_capture(manager, mocker, owner, [{"freq": 2412, "width": 20}])

    client = manager.clients[owner]
    assert client["deadline_task"] is None
    assert manager._sleep.delays == []
    lifetime = manager._lifetime_fields(client)
    assert lifetime["duration_sec"] is None
    assert lifetime["remaining_sec"] is None

    await manager.stop_streaming(owner, notify=False)


@pytest.mark.asyncio
async def test_invalid_duration_is_rejected_before_any_process_starts(mocker):
    manager = ConnectionManager()
    owner = object()
    _connected_client(manager, owner)
    _mock_root_adapters(mocker, "wlanpi0")
    create_process = mocker.patch.object(
        connection_manager.asyncio, "create_subprocess_exec", new=AsyncMock()
    )
    send_message_event = mocker.patch.object(
        manager, "send_message_event", new=AsyncMock()
    )
    manager.configure(owner, "wlanpi0", {"channels": [{"freq": 2412, "width": 20}]})

    await manager.start_streaming(owner, ["wlanpi0"], "", 0)

    create_process.assert_not_awaited()
    assert send_message_event.await_args.args[2] == "CAPTURE_CONFIG_INVALID"
    assert manager.interface_owners == {}


@pytest.mark.asyncio
async def test_bounded_capture_reports_duration_and_remaining(mocker):
    manager = ConnectionManager()
    clock = _FakeClock(100.0)
    manager._clock = clock
    manager._sleep = _FakeSleep()
    owner = object()
    _connected_client(manager, owner)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=300
    )
    session_id = manager.clients[owner]["session_id"]

    (started,) = _events(send_event, "CAPTURE_STARTED")
    assert started.args[3]["duration_sec"] == 300
    assert started.args[3]["remaining_sec"] == 300
    assert manager._sleep.delays == [300]

    clock.now = 220.5
    descriptor = manager._session_descriptor(session_id, owner)
    assert descriptor["elapsed_sec"] == 120
    assert descriptor["duration_sec"] == 300
    assert descriptor["remaining_sec"] == 180

    clock.now = 1000.0
    assert manager._session_descriptor(session_id, owner)["remaining_sec"] == 0

    await manager.stop_streaming(owner, notify=False)


@pytest.mark.asyncio
async def test_duration_elapsed_stops_capture_and_tells_owner_and_subscriber(
    mocker,
):
    """Owner gets CAPTURE_STOPPED via send_event; subscriber via queue."""
    manager = ConnectionManager()
    sleep = _FakeSleep()
    manager._sleep = sleep
    owner = object()
    subscriber = object()
    _connected_client(manager, owner)
    _connected_client(manager, subscriber)
    process, _, _ = await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=5
    )
    session_id = manager.clients[owner]["session_id"]
    mocker.patch.object(manager, "_send_subscription", new=AsyncMock())
    await manager.subscribe(subscriber, session_id)
    queue = manager.clients[subscriber]["subscription_queue"]
    while not queue.empty():
        queue.get_nowait()
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    deadline_task = manager.clients[owner]["deadline_task"]

    sleep.release(5)
    await deadline_task

    assert process.terminated is True
    assert manager.sessions == {}
    assert manager.interface_owners == {}
    assert manager.clients[owner]["deadline_task"] is None
    stopped = _events(send_event, "CAPTURE_STOPPED")
    assert any(call.args[0] is owner for call in stopped)
    assert all(call.args[3]["reason"] == "DURATION_ELAPSED" for call in stopped)
    kind, event_text = queue.get_nowait()
    assert kind == "event"
    payload = json.loads(event_text)
    assert payload["code"] == "CAPTURE_STOPPED"
    assert payload["data"]["reason"] == "DURATION_ELAPSED"
    assert payload["data"]["session_id"] == session_id
    sub_task = manager.clients[subscriber].get("subscription_task")
    if sub_task is not None:
        sub_task.cancel()
        try:
            await sub_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_manual_stop_cancels_the_duration_timer(mocker):
    manager = ConnectionManager()
    sleep = _FakeSleep()
    manager._sleep = sleep
    owner = object()
    _connected_client(manager, owner)
    await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    deadline_task = manager.clients[owner]["deadline_task"]

    await manager.stop_streaming(owner)

    with pytest.raises(asyncio.CancelledError):
        await deadline_task
    assert manager.clients[owner]["deadline_task"] is None
    (stopped,) = _events(send_event, "CAPTURE_STOPPED")
    assert stopped.args[3]["reason"] == "OWNER_STOP"
    sleep.release(60)
    assert len(_events(send_event, "CAPTURE_STOPPED")) == 1


@pytest.mark.asyncio
async def test_owner_disconnect_reports_reason_to_subscribers(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    subscriber = object()
    _connected_client(manager, owner)
    _connected_client(manager, subscriber)
    await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    session_id = manager.clients[owner]["session_id"]
    mocker.patch.object(manager, "_send_subscription", new=AsyncMock())
    await manager.subscribe(subscriber, session_id)
    queue = manager.clients[subscriber]["subscription_queue"]
    while not queue.empty():
        queue.get_nowait()
    deadline_task = manager.clients[owner]["deadline_task"]

    await manager.disconnect(owner)

    assert deadline_task.cancelled() or deadline_task.done()
    assert owner not in manager.clients
    kind, event_text = queue.get_nowait()
    assert kind == "event"
    payload = json.loads(event_text)
    assert payload["code"] == "CAPTURE_STOPPED"
    assert payload["data"]["reason"] == "OWNER_DISCONNECT"
    sub_task = manager.clients[subscriber].get("subscription_task")
    if sub_task is not None:
        sub_task.cancel()
        try:
            await sub_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_process_exit_cancels_the_duration_timer(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    _connected_client(manager, owner)
    _mock_root_adapters(mocker, "wlanpi0")
    process = CaptureProcess()
    process.stdout = EndingStdout()
    mocker.patch.object(
        connection_manager.asyncio,
        "create_subprocess_exec",
        new=AsyncMock(return_value=process),
    )
    mocker.patch.object(manager, "_set_channel", new=AsyncMock(return_value=None))
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())
    manager.configure(owner, "wlanpi0", {"channels": [{"freq": 2412, "width": 20}]})

    await manager.start_streaming(owner, ["wlanpi0"], "", 60)
    deadline_task = manager.clients[owner]["deadline_task"]
    await manager.clients[owner]["task"]

    assert manager.clients[owner]["deadline_task"] is None
    with pytest.raises(asyncio.CancelledError):
        await deadline_task
    (ended,) = _events(send_event, "CAPTURE_ENDED")
    assert ended.args[3]["reason"] == "PROCESS_EXITED"
    assert manager.sessions == {}


# --- Detached bounded captures (P6.4) ---------------------------------------


@pytest.mark.asyncio
async def test_bounded_owner_disconnect_detaches_without_stopping(mocker):
    manager = ConnectionManager()
    sleep = _FakeSleep()
    manager._sleep = sleep
    owner = object()
    _connected_client(manager, owner)
    manager.clients[owner]["did"] = "owner-did"
    process, _, _ = await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    session_id = manager.clients[owner]["session_id"]

    await manager.disconnect(owner)

    assert process.terminated is False
    assert session_id in manager.sessions
    assert manager.clients[owner]["owner_attached"] is False
    assert manager.clients[owner]["orphan_task"] is not None
    assert sleep.delays[-1] == connection_manager.ORPHAN_GRACE_SEC
    # Keep the session alive for later tests' cleanup path.
    await manager.stop_streaming(owner, notify=False, reason="OWNER_STOP")


@pytest.mark.asyncio
async def test_perpetual_owner_disconnect_stops_capture(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    _connected_client(manager, owner)
    process, _, _ = await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}]
    )

    await manager.disconnect(owner)

    assert process.terminated is True
    assert manager.sessions == {}
    assert owner not in manager.clients


@pytest.mark.asyncio
async def test_orphan_grace_stops_detached_capture_with_no_listeners(mocker):
    manager = ConnectionManager()
    sleep = _FakeSleep()
    manager._sleep = sleep
    owner = object()
    _connected_client(manager, owner)
    manager.clients[owner]["did"] = "owner-did"
    process, _, _ = await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    await manager.disconnect(owner)
    orphan = manager.clients[owner]["orphan_task"]
    # Disarm the duration timer so only the orphan path is under test when
    # FakeSleep is released (one Event wakes every waiter).
    manager._cancel_deadline(manager.clients[owner])

    sleep.release.set()
    await orphan

    assert process.terminated is True
    assert manager.sessions == {}
    assert owner not in manager.clients


@pytest.mark.asyncio
async def test_bare_stop_without_attached_capture_requires_session_id(mocker):
    manager = ConnectionManager()
    sleep = _FakeSleep()
    manager._sleep = sleep
    owner = object()
    other = object()
    _connected_client(manager, owner)
    _connected_client(manager, other)
    manager.clients[owner]["did"] = "owner-did"
    manager.clients[other]["did"] = "owner-did"
    await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    session_id = manager.clients[owner]["session_id"]
    await manager.disconnect(owner)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())

    await manager.stop_session(other, None)

    err = next(
        c for c in send_event.await_args_list if c.args[2] == "STOP_REQUIRES_SESSION"
    )
    assert err.args[3]["sessions"] == [session_id]
    assert session_id in manager.sessions
    await manager.stop_streaming(owner, notify=False, reason="OWNER_STOP")


@pytest.mark.asyncio
async def test_configure_on_detached_interface_is_control_not_allowed(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    other = object()
    _connected_client(manager, owner)
    _connected_client(manager, other)
    manager.clients[owner]["did"] = "owner-did"
    manager.clients[other]["did"] = "owner-did"
    await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    session_id = manager.clients[owner]["session_id"]
    await manager.disconnect(owner)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())

    await manager.apply_configuration(
        other, _configs(wlanpi0={"channels": [{"freq": 5180, "width": 20}]})
    )

    err = next(
        c for c in send_event.await_args_list if c.args[2] == "CONTROL_NOT_ALLOWED"
    )
    assert err.args[3]["session_id"] == session_id
    assert err.args[3]["owner_attached"] is False
    assert "stop" in err.args[3]["allowed"]
    await manager.stop_streaming(owner, notify=False, reason="OWNER_STOP")


@pytest.mark.asyncio
async def test_stop_session_by_id_from_same_did_stops_detached(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    other = object()
    _connected_client(manager, owner)
    _connected_client(manager, other)
    manager.clients[owner]["did"] = "owner-did"
    manager.clients[other]["did"] = "owner-did"
    process, _, _ = await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    session_id = manager.clients[owner]["session_id"]
    await manager.disconnect(owner)
    send_event = mocker.patch.object(manager, "send_event", new=AsyncMock())

    await manager.stop_session(other, session_id)

    assert process.terminated is True
    assert manager.sessions == {}
    stopped = _events(send_event, "CAPTURE_STOPPED")
    assert any(c.args[0] is other for c in stopped)
    assert all(c.args[3]["reason"] == "OWNER_STOP" for c in stopped)


@pytest.mark.asyncio
async def test_broadcast_skips_detached_owner_but_queues_subscribers(mocker):
    manager = ConnectionManager()
    manager._sleep = _FakeSleep()
    owner = object()
    subscriber = object()
    _connected_client(manager, owner)
    _connected_client(manager, subscriber)
    manager.clients[owner]["did"] = "owner-did"
    await _running_capture(
        manager, mocker, owner, [{"freq": 2412, "width": 20}], duration_sec=60
    )
    session_id = manager.clients[owner]["session_id"]
    await manager.disconnect(owner)
    queue: asyncio.Queue[tuple[str, object]] = asyncio.Queue(maxsize=128)
    manager.clients[subscriber]["subscribed_to"] = session_id
    manager.clients[subscriber]["subscription_queue"] = queue
    manager.clients[owner]["subscribers"].add(subscriber)
    manager._cancel_orphan(manager.clients[owner])

    # Minimal SHB+IDB so framing yields a block; use a tiny complete-looking chunk
    # that _pcapng_blocks may buffer. Queue still receives whatever completes.
    chunk = b"\x0a\x0d\x0d\x0a" + b"\x00" * 24
    await manager._broadcast_chunk(owner, manager.clients[owner], chunk)

    # Detached owner must not be asked to send_bytes (object has none).
    assert manager.clients[owner]["owner_attached"] is False
    await manager.stop_streaming(owner, notify=False, reason="OWNER_STOP")
