"""
WPA supplicant process management.

This module provides functions for starting, stopping, and managing
wpa_supplicant processes.
"""
import logging
from pathlib import Path
from typing import Optional

from wlanpi_core.models.runcommand_error import RunCommandError
from wlanpi_core.utils.namespace_execution import ns_exec
from wlanpi_core.wpa.supplicant_log import debug_flags

log = logging.getLogger(__name__)


def start_or_restart_supplicant(
    iface: str,
    namespace: Optional[str],
    config_path: Path,
    ctrl_interface: str = "/run/wpa_supplicant",
    debug_level: int = 0,
    log_path: Optional[Path] = None,
) -> None:
    """
    Start or restart wpa_supplicant for an interface.

    Args:
        iface: Interface name
        namespace: Network namespace name, or None for root
        config_path: Path to wpa_supplicant configuration file
        ctrl_interface: Control interface directory
        debug_level: 0 = default verbosity, 1 = ``-d``, 2 = ``-dd``.
            ``-K`` (key material in the log) is never passed.
        log_path: File for ``-f``; defaults to the legacy ``/tmp/wpa-<iface>.log``

    Raises:
        RunCommandError: If wpa_supplicant fails to start

    Examples:
        >>> start_or_restart_supplicant("wlan0", "test_ns", Path("/etc/wpa_supplicant/wlan0.conf"))
    """
    namespace_display = namespace if namespace else "root"
    log.info(f"Starting/restarting wpa_supplicant for {iface} in namespace {namespace_display}")

    # Kill any existing wpa_supplicant for this interface
    try:
        ns_exec(["pkill", "-f", f"wpa_supplicant -B -i {iface}"], namespace=namespace)
    except RunCommandError:
        pass  # May not exist, that's okay

    # Remove control interface socket
    try:
        ns_exec(["rm", "-f", f"{ctrl_interface}/{iface}"], namespace=namespace)
    except RunCommandError:
        pass  # May not exist, that's okay

    # Prepare (truncate) the log file as the API user so it stays readable
    # after the root-owned supplicant appends to it.
    log_file = Path(log_path) if log_path else Path(f"/tmp/wpa-{iface}.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text("")

    # Start wpa_supplicant
    ns_exec(
        [
            "wpa_supplicant",
            "-B",
            "-i",
            iface,
            "-c",
            str(config_path),
            "-D",
            "nl80211",
            "-f",
            str(log_file),
            "-t",
            *debug_flags(debug_level),
        ],
        namespace=namespace,
    )

    log.info(
        f"wpa_supplicant started for {iface} in namespace {namespace_display} "
        f"(debug_level={debug_level}, log={log_file})"
    )


def kill_all_supplicants() -> None:
    """
    Stop any running wpa_supplicant processes across all namespaces.

    This is a best-effort operation and will not raise exceptions.

    Examples:
        >>> kill_all_supplicants()
    """
    try:
        from wlanpi_core.utils.general import run_command
        run_command(["sudo", "pkill", "-f", "wpa_supplicant"], raise_on_fail=False)
        log.info("Killed all wpa_supplicant processes")
    except Exception as e:
        log.warning(f"Failed to kill all wpa_supplicants: {e}")
