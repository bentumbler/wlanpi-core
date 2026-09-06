"""
Per-activation wpa_supplicant log store.

Every connection attempt core starts gets a ``conn_<8 hex>`` id, a log file
the supplicant appends to (``-f``), and a JSON sidecar describing the attempt.
The sidecar is what listing/retrieval reads; the ``.log`` is the artifact.
Design: docs/supplicant-log-plan.md.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from wlanpi_core.constants import SUPPLICANT_LOG_DIR, SUPPLICANT_LOG_RETAIN

log = logging.getLogger(__name__)

CONN_ID_RE = re.compile(r"^conn_[0-9a-f]{8}$")
OPEN_OUTCOMES = frozenset({"in_progress"})

# wpa_cli status keys copied into the sidecar on completion. wpa_supplicant
# 2.11 emits the MLD ones for an MLO association; older builds simply lack them.
_STATUS_KEYS = ("bssid", "freq", "ssid", "key_mgmt", "ap_mld_addr", "mld_addr")
_STATUS_KEY_RE = re.compile(r"^(mld_addr\[\d+\]|link_id|links|valid_links)$")


def new_conn_id() -> str:
    return f"conn_{secrets.token_hex(4)}"


def debug_flags(level: Optional[int]) -> list[str]:
    """Map a debug level to wpa_supplicant argv flags. Never emits ``-K``."""
    if not level:
        return []
    if level == 1:
        return ["-d"]
    if level == 2:
        return ["-dd"]
    raise ValueError(f"debug_level must be 0, 1 or 2, got {level!r}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class SupplicantLogStore:
    """Filesystem store of supplicant logs and sidecars for a log directory."""

    def __init__(
        self, log_dir: str | Path = SUPPLICANT_LOG_DIR, retain: int = SUPPLICANT_LOG_RETAIN
    ):
        self.log_dir = Path(log_dir)
        self.retain = retain

    # --- paths ---

    def log_path(self, conn_id: str) -> Path:
        return self.log_dir / f"{self._check(conn_id)}.log"

    def sidecar_path(self, conn_id: str) -> Path:
        return self.log_dir / f"{self._check(conn_id)}.json"

    @staticmethod
    def _check(conn_id: str) -> str:
        if not CONN_ID_RE.match(conn_id or ""):
            raise ValueError(f"invalid conn_id {conn_id!r}")
        return conn_id

    # --- write side ---

    def create(
        self,
        conn_id: str,
        *,
        iface: str,
        namespace: Optional[str],
        phy: Optional[str] = None,
        ssid: Optional[str] = None,
        mlo: bool = False,
        debug_level: int = 0,
        config_id: Optional[str] = None,
    ) -> Path:
        """Register an attempt: prune, write the sidecar, create an empty log.

        Returns the log path to hand to ``wpa_supplicant -f``. The file is
        created by the API user so it stays readable after root appends to it.
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.prune()
        sidecar = {
            "conn_id": self._check(conn_id),
            "config_id": config_id,
            "namespace": namespace,
            "iface": iface,
            "phy": phy,
            "ssid": ssid,
            "mlo": bool(mlo),
            "debug_level": int(debug_level),
            "started_at": _now(),
            "ended_at": None,
            "outcome": "in_progress",
        }
        self._write(conn_id, sidecar)
        path = self.log_path(conn_id)
        path.write_text("")
        return path

    def update(self, conn_id: str, **fields: Any) -> bool:
        """Merge fields into an existing sidecar. False if it does not exist."""
        current = self.read(conn_id)
        if current is None:
            return False
        current.update(fields)
        self._write(conn_id, current)
        return True

    def record_outcome(
        self, conn_id: str, outcome: str, wpa_status: Optional[dict] = None
    ) -> bool:
        """Close an attempt with its outcome plus the MLD keys from ``wpa_cli status``."""
        fields: dict[str, Any] = {"outcome": outcome, "ended_at": _now()}
        for key, value in (wpa_status or {}).items():
            if key in _STATUS_KEYS or _STATUS_KEY_RE.match(key):
                fields[key] = value
        return self.update(conn_id, **fields)

    def close_open(
        self, iface: str, namespace: Optional[str], outcome: str = "deactivated"
    ) -> int:
        """Mark every still-open attempt for iface/namespace as ended."""
        closed = 0
        for entry in self.list():
            if entry.get("ended_at") is not None:
                continue
            if entry.get("iface") != iface or entry.get("namespace") != namespace:
                continue
            if self.update(entry["conn_id"], outcome=outcome, ended_at=_now()):
                closed += 1
        return closed

    def prune(self) -> list[str]:
        """Drop the oldest attempts beyond ``retain``; never an open one."""
        entries = self.list()
        removable = [e for e in entries if e.get("outcome") not in OPEN_OUTCOMES]
        excess = len(entries) - self.retain
        pruned: list[str] = []
        for entry in reversed(removable):  # oldest first
            if excess <= 0:
                break
            self.delete(entry["conn_id"])
            pruned.append(entry["conn_id"])
            excess -= 1
        return pruned

    def delete(self, conn_id: str) -> None:
        for path in (self.log_path(conn_id), self.sidecar_path(conn_id)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    # --- read side ---

    def read(self, conn_id: str) -> Optional[dict]:
        path = self.sidecar_path(conn_id)
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("Unreadable supplicant log sidecar %s: %s", path, exc)
            return None

    def list(self) -> list[dict]:
        """All sidecars, newest first."""
        if not self.log_dir.is_dir():
            return []
        entries: list[dict] = []
        for path in self.log_dir.glob("conn_*.json"):
            if not CONN_ID_RE.match(path.stem):
                continue
            entry = self.read(path.stem)
            if entry is not None:
                entries.append(entry)
        entries.sort(key=lambda e: e.get("started_at") or "", reverse=True)
        return entries

    def _write(self, conn_id: str, sidecar: dict) -> None:
        path = self.sidecar_path(conn_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(sidecar, indent=2))
        tmp.replace(path)


default_store = SupplicantLogStore()
