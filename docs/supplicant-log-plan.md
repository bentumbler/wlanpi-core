# Supplicant debug logs for MCP — design plan

Companion to [`mcp-rollout.md`](./mcp-rollout.md) and
[`capture-ws-mcp-handover.md`](./capture-ws-mcp-handover.md). This is a
**separate concern from the capture WebSocket** and ships as its own PR series
(see §7). Nothing here changes the capture protocol.

**Goal:** when core connects an adapter via a namespace/root config, keep the
wpa_supplicant debug log for that connection attempt as a retrievable artifact,
and let an authenticated client (wlanpi-mcp) list and fetch it. Driving use
case: connect one MLO-capable adapter to an EHT AP while other adapters
capture each affiliated link's channel, then hand the agent the supplicant log
plus one pcap per link (§6).

---

## 1. What core does today (and why it is not enough)

| Fact | Where |
|---|---|
| Supplicant is launched once per activated interface: `wpa_supplicant -B -i <iface> -c <conf> -D nl80211 -f /tmp/wpa-<iface>.log -t` | `wlanpi_core/wpa/supplicant.py:61-76` |
| **No `-d`/`-dd`.** Only default verbosity; the MLD/RSN link-level lines that matter for MLO triage are debug-level and never written | same |
| Log path is keyed by **interface only**, truncated on every restart. Two namespaces using the same interface name collide; the previous attempt's log is destroyed | `supplicant.py:55-58` |
| The only reader, `parse_wpa_log()`, is a blocking tailer that forwards lines to `log.debug` and is **dead code** (no caller) | `supplicant.py:81-125`, wrapper `services/network_namespace_service.py:164-171` |
| Connection completion is detected by polling `wpa_cli status` from `ConnectionMonitor`, not from the log | `wlanpi_core/connection/monitor.py:98-118` |
| The API returns `NetworkSetupStatus.response.eventLog` (service-level events only) and `POST /network/config/activate/{id}` returns a bare `{id, message}` | `schemas/network/network.py:257-271`, `api/api_v1/endpoints/network_config_api.py:193-227` |
| `wpa_supplicant` on the image is **2.11**, which emits `ap_mld_addr=`, `link_id=`, `mld_addr[n]=` in `status`, `CTRL-EVENT-LINK-RECONFIG valid_links=`, and `MLD: assoc: link id=…` debug lines | `strings /sbin/wpa_supplicant` on the box |

So the data exists in the supplicant, but core discards it, keys it wrongly,
and exposes nothing. That is the whole gap.

---

## 2. Design

### 2.1 One log file per *activation*, not per interface

Introduce a **connection attempt id** (`conn_<8 hex>`, same style as
`cap_<8 hex>` capture session ids) minted in
`NetworkNamespaceService.activate_config()` right before the supplicant is
started. The log lives at:

```
/home/wlanpi/.local/share/wlanpi-core/netcfg/supplicant-logs/<conn_id>.log
```

(`SUPPLICANT_LOG_DIR` in `constants.py`, beside `PID_DIR`/`APPS_FILE`.)
Alongside it, a small JSON sidecar `<conn_id>.json`:

```json
{
  "conn_id": "conn_3f9a1c2e",
  "config_id": "mlo_lab",
  "namespace": "ns_sta",
  "iface": "wlan1",
  "phy": "phy1",
  "ssid": "Lab-EHT",
  "mlo": true,
  "debug_level": 2,
  "started_at": "2026-09-06T10:12:03.412Z",
  "ended_at": null,
  "outcome": "in_progress"
}
```

The sidecar is what listing endpoints read; the `.log` is the artifact. The
supplicant keeps appending to the log for as long as it runs (roams, link
reconfigs, deauths are all useful), so "ended_at"/"outcome" are written by the
`ConnectionMonitor` on `COMPLETED`/timeout and by deactivate/revert on kill.

Why a new directory and not `/tmp`: `/tmp` is cleared on reboot and is shared
scratch; MCP needs a stable, listable, per-attempt store that survives until
core prunes it. The supplicant runs as root via `sudo`; core pre-creates the
file as the `wlanpi` user (as it does today with `touch`) so it stays readable
by the API process. Verify on the box that root's append does not reset the
mode (it does not for an existing file, but this is the one thing to check
with `ls -l` after the first run).

### 2.2 Verbosity is a config field, default on for MLO

Add `debug_level: int = Field(default=0, ge=0, le=2)` to `RootConfig` (and so
`NamespaceConfig`) next to `mlo`. Mapping: 0 → no flag, 1 → `-d`, 2 → `-dd`.
`start_or_restart_supplicant()` gains `debug_level` and `log_path` parameters.

Default rule in the service: if `debug_level` was not given and `mlo` is
true, use 2 (`-dd`, decided: the per-link MLD/RSN lines are debug-level and
`-d` alone does not show them). Otherwise 0. That keeps existing configs
byte-identical in behaviour and gives the MLO case what it needs without the
caller having to know wpa_supplicant flags.

**One-shot override (decided: yes).** `POST /network/config/activate/{id}`
accepts `?debug_level=0|1|2`. When present it wins over both the stored field
and the MLO default for that activation only; the stored config is not
modified. The value used is recorded in the sidecar (`debug_level`) so a
retrieved log is self-describing.

**Never pass `-K`.** It dumps key material (PMK/PTK/GTK) into the log. If a
future need arises it must be an explicit, separately gated field, and the
retrieval endpoint must redact. Out of scope here.

### 2.3 Retention

- Keep the last `N` attempts (`SUPPLICANT_LOG_RETAIN = 10`, decided) and
  prune oldest on each new activation, both `.log` and `.json`. Pruning is by
  sidecar `started_at`, and a log whose sidecar is still `in_progress` is
  never pruned even if it falls outside the window.
- Cap a single log at ~20 MB by launching the supplicant with the file and
  letting core check size in the monitor; `-dd` on a busy roam can grow fast.
  If the cap is hit, mark `outcome: "truncated"` in the sidecar; do not kill
  the supplicant. (Log rotation via `logrotate` is possible but adds a
  packaging dependency; the size check is simpler and good enough.)
- `revert_to_root()` / `deactivate_config()` do **not** delete logs. Only
  pruning does. The whole point is to read the log *after* teardown.

### 2.4 API surface (REST, not WebSocket)

A supplicant log is a file with a beginning and (eventually) an end, and the
consumer wants it after the attempt, not byte-by-byte. REST fits; a stream
does not. New router `network_config` additions (all behind
`verify_auth_wrapper`, same as the rest of the router):

| Route | Returns |
|---|---|
| `GET /api/v1/network/config/supplicant-logs` | list of sidecars, newest first; optional `?config_id=`, `?namespace=`, `?iface=` filters |
| `GET /api/v1/network/config/supplicant-logs/{conn_id}` | sidecar + `size_bytes` + `lines` |
| `GET /api/v1/network/config/supplicant-logs/{conn_id}/content` | `text/plain`, full log; `?tail=<n>` for the last *n* lines; `?since=<epoch>` filters on the `-t` timestamp prefix |
| `GET /api/v1/network/config/supplicant-logs/{conn_id}/events` | JSON list of parsed control events only (§2.5) — the cheap summary an agent reads first |
| `DELETE /api/v1/network/config/supplicant-logs/{conn_id}` | removes the pair |

And `POST /network/config/activate/{id}` returns the minted ids so the caller
does not have to go and find them:

```json
{"id": "mlo_lab", "message": "Configuration activated successfully",
 "connections": [{"conn_id": "conn_3f9a1c2e", "iface": "wlan1", "namespace": "ns_sta"}]}
```

`response_model` stays `dict` (it already is `dict[str, str]` and must become
`dict[str, Any]`), so this is additive for existing clients.

Path parameters are validated against `^conn_[0-9a-f]{8}$` before any
filesystem access; no user-controlled path segments reach `Path()`.

### 2.5 Event extraction (the part the agent actually reads)

A pure function `wpa.supplicant_log.parse_events(text) -> list[dict]`,
unit-testable with no hardware, that turns the log into structured records.
It replaces the dead `parse_wpa_log()`. Each record is
`{"t": <epoch float>, "kind": ..., ...}`. Recognised line families:

- `CTRL-EVENT-SCAN-RESULTS`, `CTRL-EVENT-SCAN-STARTED`
- `SME: Trying to authenticate with <bssid> (SSID='…' freq=…)` → `auth_attempt`
- `Trying to associate with <bssid>` / `Associated with <bssid>` → `assoc`
- `MLD: assoc: link id=<n>, addr=<mac>` and `MLD: assoc: mld=<mac>, link=<mac>` → `mlo_link` (one per affiliated link; this is how the agent learns which links joined)
- `MLD: AP MLD ID=…`, `MLD: address: <mac>` → `mlo_mld`
- `CTRL-EVENT-LINK-RECONFIG valid_links=0x…` → `link_reconfig`
- `CTRL-EVENT-LINK-CHANNEL-SWITCH …` → `link_csa`
- `WPA: Key negotiation completed`, `CTRL-EVENT-CONNECTED - Connection to <bssid> completed` → `connected`
- `CTRL-EVENT-DISCONNECTED bssid=… reason=… locally_generated=…` → `disconnected`
- `CTRL-EVENT-SSID-TEMP-DISABLED`, `CTRL-EVENT-AUTH-REJECT`, `CTRL-EVENT-ASSOC-REJECT` → `reject` with status code
- `RSN: … MLO Link <n> …` → `mlo_key` (GTK/IGTK per link)

Anything unmatched is dropped from `/events` but stays in `/content`. The
regex table is data, so adding a family is a one-line change plus a fixture
line in tests.

### 2.6 What changes in `ConnectionMonitor`

Nothing structural. It gains the `conn_id` in its key data so that on
`COMPLETED` it writes `outcome: "connected"`, `ended_at`, and the
`ap_mld_addr` / `link_id` / `mld_addr[n]` fields from `wpa_cli status`
(2.11 emits them; `get_wpa_status()` already returns the dict, it only needs
to pass through the keys) into the sidecar. On timeout it writes
`outcome: "timeout"`. The monitor still polls `wpa_cli status`; the log is
not used for control flow.

---

## 3. Security notes

- Logs contain SSIDs, BSSIDs, EAP identities and, at `-dd`, EAPOL frames
  (hex) and RSN IE contents. They do **not** contain the PSK or PMK unless
  `-K` is passed, which this design forbids. Treat the content endpoint as
  device-open read, same policy as capture subscribe (auth plan Appendix A,
  policy A).
- The retrieval endpoints must not be reachable anonymously. They sit in the
  `network_config` router which is already fully guarded; the route-auth
  walker test (`test_auth_dispatch.py`) will catch a regression.
- No shelling out on the read path. Listing, tailing and parsing are pure
  Python over files core itself wrote.

---

## 4. MLO scan enrichment (separate PR, needed for step 1 of the use case)

`GET /utils/wlan/scan?detail=full` returns the raw `iw` BSS block but the
parsed fields carry no MLD info (`wpa/scan.py:240-290` yields `freq`,
`primaryChannel`, `channelWidth`, `amendments=["be"]` only). The agent needs,
per SSID, the set of affiliated links and their channels. `iw` 6.9 on the box
prints the Multi-Link element (`MLD with links:` / `MLD %s`) when the driver
reports it. Add to `parse_iw_bss_block()`:

```json
"mld": {"addr": "aa:bb:cc:dd:ee:01", "mld_id": 0,
        "links": [{"link_id": 0, "freq": 2437}, {"link_id": 1, "freq": 5220}, {"link_id": 2, "freq": 6115}]}
```

and a `band` field (`"2.4"|"5"|"6"`) derived from `freq`, which today is left
for the client to infer. Whether `iw` shows the affiliated links' frequencies
depends on the driver exposing the reduced-neighbour-report / per-STA profile;
verify on the actual MLO adapter before promising the `links[].freq` field.
If it does not, fall back to grouping scan rows by SSID + `mld.addr`, which
gives the same answer (each affiliated BSS is its own scan row with its own
`freq`).

This is a small parser change plus fixture; it does not touch the log work.

---

## 5. Adapter capability check

To pick "an MLO-capable adapter" the agent needs to know which phys support
EHT. `GET /wifi/capabilities` returns raw `iw phy info` text
(`wlan/capabilities.py:13-30`). The cheapest useful addition is a parsed
`eht: bool` per phy (presence of an `EHT Iftypes:` / `EHT MAC Capabilities`
block). Also a separate small PR. Until then the agent can grep the raw text
itself; do not block the log work on this.

---

## 6. The use case, end to end, with the pieces above

Orchestration lives in **wlanpi-mcp**, not core. Core provides primitives;
MCP sequences them.

1. **Scan.** `GET /utils/wlan/scan?detail=full` on any managed adapter.
   Group rows for the target SSID by `mld.addr` (§4) → the set of links
   `{link_id, freq, width}`. Count = number of capture adapters needed.
2. **Choose adapters.** `GET /wifi/capabilities` → pick one `eht` phy for the
   station. Remaining phys (up to the link count) are capture adapters. If
   there are fewer capture adapters than links, MCP reports which links are
   covered and which are not; core does not decide.
3. **Build one `NetConfig`** with a `NamespaceConfig` per adapter:
   station → `mode: managed, mlo: true, security: {...}` (debug_level defaults
   to 2 per §2.2); each capture adapter → `mode: monitor`, no security, in its
   own namespace. `POST /network/config/` then
   `POST /network/config/activate/{id}` → response carries the station's
   `conn_id`.
4. **Start captures first, then let the station connect.** Open one capture
   WebSocket per capture adapter (`wlanpiN` names; core resolves their
   namespaces), `configure` each with a single channel (`{"channels":[{"freq":
   <link freq>, "width": <link width>}]}`, no hopping) and `start`. MCP
   writes each stream to its own file. Only after all captures report
   `CAPTURE_STARTED` does MCP activate the station config (so step 3 is
   really two activations, or the station config is a second `NetConfig`; the
   latter is simpler and matches "one concern per config").
5. **Wait for outcome.** Poll `GET /network/config/supplicant-logs/{conn_id}`
   until `outcome != "in_progress"` (or a caller-supplied timeout), then `stop`
   the captures.
6. **Deliver.** MCP returns to the agent: the sidecar (outcome, `ap_mld_addr`,
   the links that actually associated), `/events` (compact), a pointer to
   `/content` (full log), and the per-link pcap paths. Individual files, not a
   multiplexed stream, exactly as you suggested: up to three pcaps plus one
   log, each independently readable.

The activation-vs-capture ordering in step 4 matters: the capture adapters
must already be on-channel when the station sends its first Authentication
frame, or the interesting part (ML probe, multi-link auth/assoc, per-link
4-way handshake and GTK/IGTK install) is missed.

Known interaction to keep in mind: `_set_channel()` in the capture manager
already retries once on `EBUSY` because a supplicant on a *shared phy* scans
periodically (`streaming/connection_manager.py:751-753`). With every adapter
in its own namespace on its own phy this does not arise, but a monitor VIF
sharing the station's phy must not be used as a capture adapter.

---

## 7. PR slicing (each ≤ ~400 lines, one concern, targets `dev`)

| # | Branch | Content | Depends on |
|---|---|---|---|
| S1 | `feature/supplicant-log-store` | `conn_id` minting; `SUPPLICANT_LOG_DIR`; `debug_level` on `RootConfig`; `start_or_restart_supplicant(debug_level, log_path)`; sidecar write; retention; `ConnectionMonitor` writes outcome + MLD status keys; activate response gains `connections[]` and accepts `?debug_level=`; delete dead `parse_wpa_log` and its wrapper; matrix rows for `mlo: true` default level and for two namespaces sharing an iface name | — |
| S2 | `feature/supplicant-log-api` | Four GET routes + DELETE; `parse_events()` with fixture log (recorded on the box from a real MLO association, secrets scrubbed); OpenAPI docstrings; `docs/` consumer notes | S1 |
| S3 | `feature/scan-mld-fields` | `mld` + `band` in scan parser (§4) with `iw` fixture | — |
| S4 | `feature/wifi-capabilities-eht` | parsed `eht` flag per phy (§5) | — |
| M1 | wlanpi-mcp | `connect_and_trace_mlo` tool implementing §6 against S1–S4 and the capture handover | S1–S4 |

S1 is the one that touches the activation path and is the one to get right;
S2 is pure read-side. S3/S4 are independent and can go in any order. Debian
changelog bumps on S1–S4 (package content); none on doc-only follow-ups.

**Test rules that bite here** (from `AGENTS.md`): the monitor writes the
sidecar from a real thread, so tests must use an `Event` set by the mocked
`get_wpa_status` side effect and must stop the monitor loudly; the sidecar
writer is patched at `wlanpi_core.connection.monitor`, not at the source
module, because the monitor imports it at module top.

---

## 8. Decisions (2026-09-06)

1. **MLO default verbosity is `-dd`** (`debug_level=2`). The retention cap and
   per-file size cap make the volume safe.
2. **Activate accepts a one-shot `?debug_level=` override** so an agent can
   bump verbosity without editing the stored config (§2.2).
3. **Retention is 10 attempts.** In-progress attempts are never pruned.

S1 is unblocked; it branches from `dev` and targets `dev`.
