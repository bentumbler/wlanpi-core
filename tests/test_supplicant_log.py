"""Supplicant log store, launcher flags, debug_level plumbing, monitor outcomes."""
import json
import threading
from itertools import count
from unittest.mock import patch

import pytest
from pydantic import ValidationError as PydanticValidationError

from wlanpi_core.connection.monitor import ConnectionMonitor, stop_all_connection_monitors
from wlanpi_core.schemas.network.network import (
    NetSecurity,
    NetworkModeEnum,
    RootConfig,
    SecurityTypes,
)
from wlanpi_core.services.network_namespace_service import NetworkNamespaceService
from wlanpi_core.wpa import supplicant
from wlanpi_core.wpa.supplicant_log import (
    CONN_ID_RE,
    SupplicantLogStore,
    debug_flags,
    new_conn_id,
)
from tests.test_namespace_matrix.handlers import _wait_for_monitors_idle


def _root(**kwargs) -> RootConfig:
    base = dict(
        mode=NetworkModeEnum.managed,
        iface_display_name="wlan0",
        phy="phy0",
        interface="wlan0",
        security=NetSecurity(ssid="Lab", security=SecurityTypes.wpa2, psk="secret"),
    )
    base.update(kwargs)
    return RootConfig(**base)


def _ticking_clock():
    """Deterministic, strictly increasing started_at values for prune ordering."""
    counter = count()
    return lambda: f"2026-09-06T10:00:{next(counter):02d}.000Z"


# --- ids and flags ---


def test_new_conn_id_format():
    assert CONN_ID_RE.match(new_conn_id())
    assert new_conn_id() != new_conn_id()


def test_debug_flags_never_emit_key_dump():
    assert debug_flags(None) == []
    assert debug_flags(0) == []
    assert debug_flags(1) == ["-d"]
    assert debug_flags(2) == ["-dd"]
    with pytest.raises(ValueError):
        debug_flags(3)
    assert "-K" not in debug_flags(2)


def test_root_config_debug_level_bounds():
    assert _root().debug_level is None
    assert _root(debug_level=2).debug_level == 2
    with pytest.raises(PydanticValidationError):
        _root(debug_level=3)


def test_effective_debug_level_rules():
    eff = NetworkNamespaceService.effective_debug_level
    assert eff(_root(mlo=True)) == 2
    assert eff(_root(mlo=False)) == 0
    assert eff(_root(mlo=True, debug_level=1)) == 1
    assert eff(_root(mlo=True, debug_level=2), override=0) == 0


# --- store ---


def test_create_writes_sidecar_and_empty_log(tmp_path):
    store = SupplicantLogStore(tmp_path)
    cid = new_conn_id()
    path = store.create(
        cid, iface="wlan1", namespace="ns_sta", phy="phy1", ssid="Lab-EHT",
        mlo=True, debug_level=2, config_id="mlo_lab",
    )
    assert path == tmp_path / f"{cid}.log"
    assert path.read_text() == ""
    sidecar = json.loads((tmp_path / f"{cid}.json").read_text())
    assert sidecar["conn_id"] == cid
    assert sidecar["outcome"] == "in_progress"
    assert sidecar["ended_at"] is None
    assert sidecar["mlo"] is True and sidecar["debug_level"] == 2
    assert sidecar["config_id"] == "mlo_lab" and sidecar["namespace"] == "ns_sta"
    assert store.list()[0]["conn_id"] == cid


def test_store_rejects_bad_conn_id(tmp_path):
    store = SupplicantLogStore(tmp_path)
    with pytest.raises(ValueError):
        store.log_path("../etc/passwd")
    assert store.read("conn_00000000") is None


def test_prune_keeps_retain_newest_and_never_open(tmp_path):
    store = SupplicantLogStore(tmp_path, retain=2)
    with patch("wlanpi_core.wpa.supplicant_log._now", side_effect=_ticking_clock()):
        ids = [new_conn_id() for _ in range(4)]
        store.create(ids[0], iface="wlan0", namespace=None)  # oldest, stays open
        for cid in ids[1:3]:
            store.create(cid, iface="wlan0", namespace=None)
            store.record_outcome(cid, "connected")
        store.create(ids[3], iface="wlan0", namespace=None)  # triggers prune
    remaining = {e["conn_id"] for e in store.list()}
    assert ids[0] in remaining, "open attempt must never be pruned"
    assert ids[3] in remaining
    assert ids[1] not in remaining, "oldest closed attempt pruned"
    assert not (tmp_path / f"{ids[1]}.log").exists()
    assert len(remaining) == 3  # retain=2 closed/new + the open one it may not touch


def test_record_outcome_copies_mld_status_keys(tmp_path):
    store = SupplicantLogStore(tmp_path)
    cid = new_conn_id()
    store.create(cid, iface="wlan0", namespace=None)
    ok = store.record_outcome(
        cid,
        "connected",
        {
            "wpa_state": "COMPLETED",
            "bssid": "aa:bb:cc:dd:ee:01",
            "freq": "5220",
            "ap_mld_addr": "aa:bb:cc:dd:ee:00",
            "mld_addr[0]": "02:00:00:00:00:01",
            "link_id": "1",
            "ip_address": "10.0.0.5",
        },
    )
    assert ok
    sidecar = store.read(cid)
    assert sidecar["outcome"] == "connected" and sidecar["ended_at"]
    assert sidecar["ap_mld_addr"] == "aa:bb:cc:dd:ee:00"
    assert sidecar["mld_addr[0]"] == "02:00:00:00:00:01"
    assert sidecar["link_id"] == "1"
    assert "ip_address" not in sidecar and "wpa_state" not in sidecar
    assert store.record_outcome("conn_00000000", "connected") is False


def test_close_open_only_matching_iface_and_namespace(tmp_path):
    store = SupplicantLogStore(tmp_path)
    a, b, c = new_conn_id(), new_conn_id(), new_conn_id()
    store.create(a, iface="wlan1", namespace="ns_sta")
    store.create(b, iface="wlan1", namespace=None)
    store.create(c, iface="wlan1", namespace="ns_sta")
    store.record_outcome(c, "connected")
    assert store.close_open("wlan1", "ns_sta") == 1
    assert store.read(a)["outcome"] == "deactivated" and store.read(a)["ended_at"]
    assert store.read(b)["outcome"] == "in_progress"
    assert store.read(c)["outcome"] == "connected"


# --- launcher ---


def test_start_supplicant_argv_uses_debug_flags_and_log_path(tmp_path):
    log_path = tmp_path / "logs" / "conn_deadbeef.log"
    # patch.object on the imported module object: survives module reloads elsewhere in the suite
    with patch.object(supplicant, "ns_exec") as ns_exec:
        supplicant.start_or_restart_supplicant(
            "wlan1", "ns_sta", tmp_path / "wlan1.conf", debug_level=2, log_path=log_path
        )
    argv = [c.args[0] for c in ns_exec.call_args_list if c.args[0][0] == "wpa_supplicant"][0]
    assert argv[-1] == "-dd"
    assert argv[argv.index("-f") + 1] == str(log_path)
    assert "-K" not in argv
    assert log_path.read_text() == ""


# --- monitor ---


def _run_monitor(store, cid, status, timeout=5):
    """Start a monitor with conn_id, wait for its outcome write, tear down loudly."""
    stop_all_connection_monitors()
    _wait_for_monitors_idle()
    recorded = threading.Event()
    real = store.record_outcome

    def record(*args, **kwargs):
        result = real(*args, **kwargs)
        recorded.set()
        return result

    with patch("wlanpi_core.connection.monitor.get_wpa_status", return_value=status):
        with patch("wlanpi_core.connection.monitor.restart_dhcp_with_timeout"):
            with patch("wlanpi_core.connection.monitor.set_default_route"):
                with patch.object(store, "record_outcome", side_effect=record):
                    ConnectionMonitor.start_monitor(
                        _root(), "wlan0", None, timeout=timeout, conn_id=cid, log_store=store
                    )
                    done = recorded.wait(timeout=10)
                    stop_all_connection_monitors()
                    _wait_for_monitors_idle()
    assert done, "monitor never recorded an outcome"


def test_monitor_records_connected_with_mld_keys(tmp_path):
    store = SupplicantLogStore(tmp_path)
    cid = new_conn_id()
    store.create(cid, iface="wlan0", namespace=None)
    _run_monitor(
        store,
        cid,
        {"wpa_status": {"wpa_state": "COMPLETED", "ap_mld_addr": "aa:bb:cc:dd:ee:00"}},
    )
    sidecar = store.read(cid)
    assert sidecar["outcome"] == "connected"
    assert sidecar["ap_mld_addr"] == "aa:bb:cc:dd:ee:00"


def test_monitor_records_timeout(tmp_path):
    store = SupplicantLogStore(tmp_path)
    cid = new_conn_id()
    store.create(cid, iface="wlan0", namespace=None)
    _run_monitor(store, cid, {"wpa_status": {"wpa_state": "SCANNING"}}, timeout=1)
    assert store.read(cid)["outcome"] == "timeout"


def test_monitor_without_conn_id_touches_no_store(tmp_path):
    store = SupplicantLogStore(tmp_path)
    stop_all_connection_monitors()
    _wait_for_monitors_idle()
    dhcp_ran = threading.Event()
    with patch(
        "wlanpi_core.connection.monitor.get_wpa_status",
        return_value={"wpa_status": {"wpa_state": "COMPLETED"}},
    ):
        with patch(
            "wlanpi_core.connection.monitor.restart_dhcp_with_timeout",
            side_effect=lambda *a, **k: dhcp_ran.set(),
        ):
            with patch.object(store, "record_outcome") as record:
                ConnectionMonitor.start_monitor(_root(), "wlan0", None, timeout=5, log_store=store)
                assert dhcp_ran.wait(timeout=5)
                stop_all_connection_monitors()
                _wait_for_monitors_idle()
    record.assert_not_called()
    assert store.list() == []
