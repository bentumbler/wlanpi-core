# Connection trace — design plan (the pinnacle capability)

Companion to [`supplicant-log-plan.md`](./supplicant-log-plan.md) (S1–S4),
[`capture-ws-lifetime-plan.md`](./capture-ws-lifetime-plan.md) (P6.x),
[`capture-ws-mcp-handover.md`](./capture-ws-mcp-handover.md) (the WS contract)
and [`MCP-CLASSROOM-LABS.md`](./MCP-CLASSROOM-LABS.md) (Tier 5: L15 single
link, L16 MLO). The MCP-side contract is
[`connection-trace-mcp-blueprint.md`](./connection-trace-mcp-blueprint.md).

**Status:** design, 2026-09-15. Nothing here is implemented.
**Branch:** this document lives on `docs/connection-trace-plan`; the first
code PR is **P6.5** (`feature/capture-file-sink-p65`), see §13.
**Decides:** where orchestration lives (core), file-vs-stream (file), the
adapter assignment rule, the error contract, the PR stack.

---

## 0. The capability in one paragraph

A **connection trace** connects one adapter (the *station*) to an SSID
while other adapters (the *capture adapters*) sit in monitor mode, each in
its own namespace, on the channel of every BSS the station may use, and
the supplicant writes a debug log. After a bounded time core hands back the
supplicant log, one pcap per captured channel, and a merged
machine-readable timeline. The capability is generic: a classic single-band
BSS needs one capture adapter; a roaming test across an ESS needs one per
channel in use; a Wi-Fi 7 AP MLD needs one per affiliated link. **MLO is
the same trace with more capture adapters and an EHT-capable station**,
plus a handful of extra fields in the summary. A short run (~45 s) shows
the (multi-link) association and the 4-way handshake; a long run (10–60
min) shows roams, channel switches, link usage and link reconfiguration as
someone walks around. If the box has fewer capture adapters than channels
to cover, the caller decides how many must be covered and in what band
priority; core never silently degrades.

The station on a Wi-Fi 7 box is a Qualcomm STR-MLO card kept in the
**root** namespace because its kernel and supplicant patches are fragile;
the rule generalises: the station phy is never moved and never used for
capture.

---

## 1. Decisions (the short version)

| # | Question | Decision | Why |
|---|---|---|---|
| D1 | Where does the sequencing live — core or MCP? | **Core**, as a REST resource `/wifi/trace/…` with a state machine. MCP wraps it; the primitives (NetConfig, capture WS, supplicant-log routes) stay as the manual fallback. | Ordering is safety-critical (captures on channel *before* the first Authentication frame), adapter/phy/namespace facts live in core, and N WebSockets driven from a remote LLM are fragile and unauditable. Supersedes §6 of the supplicant-log plan, written before a file sink existed. |
| D2 | Stream the captures or write them to file? | **File on the box.** `dumpcap -w <file>` inside each namespace. Nothing is streamed during a trace. | Even one busy channel plus a `-dd` log is marginal over a WebSocket to a remote client on the very Wi-Fi under test; three are a coin toss, and a dropped chunk is a corrupt pcapng, not a gap. dumpcap's own writer is the most loss-resistant path on a Pi. §5. |
| D3 | How does the client get the files? | **Artifact download** routes with `Range`, `Content-Length`, SHA-256 in the manifest, plus an on-box **summary** endpoint so the agent never needs the bytes. | The model reads JSON; humans open pcaps in Wireshark. Both must work. |
| D4 | Fewer adapters than channels | `plan` always answers. `sessions` refuses with `409 INSUFFICIENT_ADAPTERS` (plan attached) unless the caller's `minLinksCovered` is met. `bandPriority` decides which channels get an adapter first. | "Graceful" means *explicit*: the caller (and the human behind it) lowers the bar knowingly. Matches the classroom rule that an agent may not unilaterally accept a degraded result. |
| D5 | Station adapter | Root namespace, `RootConfig`; `mlo: true` and an EHT-capable phy only when the target is an MLD. `debug_level` 2 by default for a trace (it is a diagnostic run). **Its phy is never moved and never used for capture.** | Ben's constraint for the Qualcomm card; generally, moving the station's phy mid-experiment is the one thing guaranteed to break the experiment. |
| D6 | Capture adapters | One phy per **link** (one BSS on one channel), each in its own namespace `trc_<n>`, monitor VIF `wlanpi<N>`, fixed channel, width = min(link width, adapter max, 160). | The phy moves whole into a netns, so one phy = one channel. Mgmt/EAPOL are on the primary 20 MHz, so a width shortfall loses only wide data PPDUs, never the association. |
| D7 | Concurrency | One trace at a time; capture interfaces are claimed in the registry the capture WS uses, so a WS `start` on them gets `INTERFACE_IN_USE` and vice versa. | Two orchestrators on one radio set is undebuggable. |
| D8 | Lifetime | Bounded: `captureDurationSec` 5–3600 after association (or after failure hold). Every end has a `reason`. Teardown always runs; artifacts always survive it. | Same rules as P6.3/P6.4; the failure case is the one worth capturing. |
| D9 | Summary decoding | Pure-Python 802.11 parser in core: radiotap, mgmt IEs (incl. Multi-Link and TID-to-Link Mapping for MLO), action frames, EAPOL detection. Not tshark. | The image ships tshark 3.4.16, which predates EHT/Multi-Link dissection. The harness's radiotap/IE parser is the seed. |
| D10 | Wire style | camelCase JSON, `Field(description=…)` on every field, `operationId` on every route, enums for every state and reason. | The consumer is an MCP generator and then a model. Undocumented fields are invisible to both. |

---

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **Target** | The thing the station will join: an SSID resolved to either a classic **BSS** (`kind: "bss"`, one link) or an AP **MLD** (`kind: "mld"`, one link per affiliated BSS). |
| **Link** | One BSS on one channel: `{linkId, bssid, band, channel, freq, widthMhz}`. A classic BSS has exactly one link (`linkId: 0`); an MLD has up to three. Every capture adapter covers one link. |
| **Scope** | `target` (default): cover the links of the chosen target. `ess`: cover every BSS heard with that SSID, so a roam between APs on different channels stays in view. In `ess` scope links are all BSSs of the SSID, de-duplicated by channel. |
| **Station** | The adapter that connects. Root namespace, never captures. |
| **Capture adapter** | A phy moved into its own namespace with a monitor VIF on one link's channel. |
| **Coverage** | Links with a capture adapter vs. links in scope. |

---

## 3. What core has today, and the gap

| Need | Have | Gap |
|---|---|---|
| Find the target and its links | `GET /utils/wlan/scan?detail=full` returns freq/width/`amendments`; no MLD grouping, no `band` | **S3** (`mld`, `band` on scan rows); `GET /wifi/trace/targets` (**M2**) builds BSS/MLD/ESS views. |
| Station in root, log kept | `RootConfig` (managed, optional `mlo: true`); S1 gives `debug_level`, `conn_id`, sidecar with outcome and MLD status keys | None on the API: the orchestrator calls `ConnectionMonitor.start_monitor(timeout=…)` directly (**M5**). No change to S1's activate route. |
| One capture adapter per link, own namespace, monitor, fixed channel | `NamespaceConfig{mode: monitor}` moves the phy and creates the VIF; capture WS sets the channel inside the netns | No per-phy band/monitor/EHT capability model (**M1**, absorbs **S4**), no planner (**M3**), no dumpcap-to-file (**P6.5**). |
| Supplicant log read + events | S1 store; S2 planned | S2 not started; needed for the merged timeline. |
| Start captures, *then* connect | Capture WS does channel set + dumpcap, to a socket only | File sink (**P6.5**), orchestrator (**M5**). |
| Return log + pcaps + summary | S2 content route for the log | No pcap retrieval anywhere. Manifest + download (**M6**). Summary (**M7**). |
| Docs an AI can use | `openapi_docs.py` tag/response pattern | New tag, examples, error enums, operationIds, guide lesson, classroom L15/L16 (**M8**). |

Hardware facts checked on this box (2026-09-13): kernel 6.12.13-v8-wlanpi+,
wpa_supplicant 2.11, `iw` supports `set_wiphy_netns`, phy0 (Intel BE200)
has 2.4/5/6 GHz and a monitor VIF `wlanpi0` alongside managed `wlan0`
(shared phy, §4.3). dumpcap/tshark 3.4.16. 1.9 GB RAM, 4 cores, 40 GB free.
Starlette 0.49 (`FileResponse` honours `Range`). With one USB monitor dongle
added, this box can run a single-link trace (station `wlan0`, capture on
the dongle) as soon as M1–M6 exist; the Wi-Fi 7 box needs the Qualcomm
station plus one dongle per link.

---

## 4. API surface

All routes under `/api/v1/wifi/trace`, tag `connection_trace`, behind
`verify_auth_wrapper`, classic mode only (`409 MODE_CONFLICT` otherwise,
like NetConfig activate).

### 4.1 Discovery (read-only, no side effects)

| Route | operationId | Returns |
|---|---|---|
| `GET /wifi/trace/adapters` | `trace_adapters` | Per-phy inventory: `phy`, `driver`, `bus`, `bands: ["2.4","5","6"]`, `maxWidthMhz` per band, `monitorCapable`, `ehtCapable`, `interfaces[] {iface, mode, namespace, associatedSsid, busy}`, `eligibility: {station: bool, stationMlo: bool, capture: bool, reasons[]}`. Reasons enum: `NOT_EHT`, `NO_MONITOR`, `SHARED_WITH_MANAGED`, `MANAGEMENT_PATH`, `CLAIMED_BY_CAPTURE`, `IN_ACTIVE_CONFIG`, `IDLE_MANAGED_NOT_BORROWED`, `PINNED_STATION_PHY`. `busy` marks an interface claimed by a running trace or capture WS session (§14.2 B4). |
| `GET /wifi/trace/targets?ssid=&iface=&namespace=` | `trace_targets` | Scan (same adapter-selection contract as `/utils/wlan/scan`, so `needsSelection` can come back) and resolve: `targets[] {ssid, kind: "bss"|"mld", bssid|mldAddr, security, signal, links[]}` and `ess[] {ssid, bssCount, channels[]}`. A classic BSS is a target with one link; an MLD is one target with N links; an ESS of three classic APs is three targets sharing an `ess` entry. |
| `POST /wifi/trace/plan` | `trace_plan` | Dry run of the assignment rule (§5). Body = the `target` and `capture` parts of a session request. Returns a `Plan` (§4.3). Never fails on feasibility; feasibility is data in the plan. |

### 4.2 Session lifecycle

| Route | operationId | Notes |
|---|---|---|
| `POST /wifi/trace/sessions` | `trace_session_create` | Plans, checks `minLinksCovered`, runs the state machine in a background task. `202 Accepted` with the session and the plan actually applied. `409 INSUFFICIENT_ADAPTERS` (plan attached), `409 STATION_NEEDS_SELECTION` (candidates attached), `409 STATION_NOT_EHT` (MLD target, chosen phy cannot), `409 SESSION_ACTIVE`, `409 TARGET_NOT_FOUND`, `409 INTERFACE_IN_USE`, `422` on validation, `507` on disk. |
| `GET /wifi/trace/sessions` | `trace_session_list` | Newest first: state, target, coverage, `startedAt`, `endedAt`. |
| `GET /wifi/trace/sessions/{id}` | `trace_session_get` | State, `since`, per-link capture status (`fileBytes` growing is the liveness signal), station status (from the S1 sidecar), `elapsedSec`/`remainingSec`, artifact list, `endReason`. |
| `POST /wifi/trace/sessions/{id}/stop` | `trace_session_stop` | Early stop; reason `CALLER_STOP`. Idempotent. |
| `DELETE /wifi/trace/sessions/{id}` | `trace_session_delete` | Removes the session directory. 409 if running. |
| `GET /wifi/trace/sessions/{id}/summary` | `trace_session_summary` | The merged timeline (§7). 409 `NOT_FINALISED` while running. |
| `GET /wifi/trace/sessions/{id}/artifacts` | `trace_artifacts_list` | Manifest (§6.3). |
| `GET /wifi/trace/sessions/{id}/artifacts/{name}` | `trace_artifact_download` | Bytes. `Range` supported, `Content-Disposition: attachment`, `ETag` = sha256. `name` validated against the manifest, never used as a path. |

### 4.3 Request and plan shapes

```json
POST /wifi/trace/sessions
{
  "target": {"ssid": "WLANPI-LAB", "bssid": null, "mldAddr": null},
  "station": {"phy": null, "security": {"security": "WPA2-PSK", "psk": "…"},
              "debugLevel": 2, "associationTimeoutSec": 30, "keepConnected": false},
  "capture": {"scope": "target", "bandPriority": ["6", "5", "2.4"], "minLinksCovered": "all",
              "filterMode": "focused", "snaplenBytes": null, "captureFilter": null,
              "maxFileMb": 512, "allowBorrowIdleManaged": false},
  "timing": {"profile": "assoc", "captureDurationSec": null, "prerollSec": 3,
             "postFailureHoldSec": 10},
  "label": "lab AP, desk 4"
}
```

- `target.bssid` / `target.mldAddr` disambiguate when one SSID is served
  by several BSSs or MLDs; omitted → the strongest. Setting `mldAddr` on an
  SSID that is not MLO is a 422.
- `station.phy` null → the only eligible phy (EHT-eligible when the
  resolved target is an MLD); more than one → `STATION_NEEDS_SELECTION`.
  `keepConnected: false` deactivates the station on finalise (default).
- `capture.scope` `target` | `ess` (§2). `minLinksCovered` ∈ `"all" | "any" | <int>`, default `"all"`.
- `capture.filterMode` `focused` (default) | `full` | `mgmt_only` (§6.2). `captureFilter` is a raw BPF override.
- `capture.allowBorrowIdleManaged` (default `false`) lets the planner move a phy that hosts an *idle* managed interface such as `wlan0`. Off by default because it removes that interface from root for the duration (§14.2 B5).
- `timing.profile`: `assoc` → 45 s capture; `roam` → 600 s and `snaplenBytes: 512`. Explicit values win. `captureDurationSec` 5–3600.
- Security is redacted in every response (`NetSecurity.__str__` already
  does this for logs; the response model omits the field).

`Plan` (returned by `plan` and inside the session), MLD example with one
adapter short:

```json
{
  "target": {"ssid": "WLANPI-EHT", "kind": "mld", "mldAddr": "aa:bb:cc:dd:ee:00", "links": [ … ]},
  "scope": "target",
  "station": {"phy": "phy1", "iface": "wlan1", "namespace": null, "ehtCapable": true, "mlo": true},
  "assignments": [
    {"linkId": 2, "bssid": "…:02", "band": "6", "freq": 6115, "linkWidthMhz": 320, "captureWidthMhz": 160,
     "phy": "phy2", "iface": "wlanpi2", "namespace": "trc_2", "centerFreq": 6185},
    {"linkId": 1, "bssid": "…:01", "band": "5", "freq": 5220, "linkWidthMhz": 80, "captureWidthMhz": 80,
     "phy": "phy3", "iface": "wlanpi3", "namespace": "trc_1", "centerFreq": 5210}
  ],
  "uncovered": [{"linkId": 0, "band": "2.4", "freq": 2437, "reason": "ADAPTERS_EXHAUSTED"}],
  "excluded": [{"phy": "phy0", "reasons": ["SHARED_WITH_MANAGED"]}],
  "feasible": false,
  "coverage": {"links": 3, "covered": 2, "minRequired": 3},
  "warnings": ["link 2 is 320 MHz; capturing at 160 MHz (adapter max)"]
}
```

The single-link case is the same document with `kind: "bss"`, one link,
one assignment and (usually) `feasible: true`.

---

## 5. The assignment rule (M3, a pure function)

Inputs: the links in scope, the adapter inventory, `bandPriority`,
`station.phy`, target kind. Output: a `Plan`. No I/O, so it is tested as a
matrix (`tests/scenarios/trace_plan_matrix.csv`, AGENTS rule 8).

1. **Pin the station.** The chosen phy must be managed-capable, in root or
   movable to root, not the management path, and `ehtCapable` when the
   target is an MLD. It leaves the capture pool and appears in `excluded`
   with `PINNED_STATION_PHY`.
2. **Build the capture pool.** A phy is eligible when it is
   `monitorCapable`, not the station, not hosting an *associated* managed
   interface (`SHARED_WITH_MANAGED` — the busy-retune problem, handover §7),
   not the interface carrying the API client's route (`MANAGEMENT_PATH`),
   not claimed by a running capture WS session (`CLAIMED_BY_CAPTURE`), not
   part of another active NetConfig (`IN_ACTIVE_CONFIG`). A phy hosting an
   *idle* managed interface is eligible **only** when the caller sets
   `capture.allowBorrowIdleManaged` (reason `IDLE_MANAGED_NOT_BORROWED`
   otherwise): moving it removes that interface from root for the duration,
   which other API consumers can see (§14.2 B5). When borrowed, teardown
   recreates it on its original phy, in root, with its original name and
   type.
3. **Order the links.** Links whose band is in `bandPriority`, in that
   order; then the rest in scan order (strongest first). In `ess` scope a
   channel shared by two APs is one link.
4. **Assign, best fit.** For each ordered link, pick the eligible phy that
   supports the band and has the *fewest* other supported bands (a 2.4-only
   dongle is not spent on 2.4 while a tri-band adapter could have covered 6
   GHz later; ties → highest max width for that band, then phy name).
   Record `captureWidthMhz = min(linkWidth, adapterMaxWidth(band), 160)`
   and the centre frequency (the existing `_center_frequency` covers 5 and
   6 GHz).
5. **Uncovered reasons.** `NO_ADAPTER_FOR_BAND`, `ADAPTERS_EXHAUSTED`,
   `BAND_DISABLED_REGULATORY` (the phy lists the band but every channel is
   `disabled` under the current reg domain — common for 6 GHz).
6. **Feasible** ⇔ covered ≥ `minLinksCovered` (`"all"` = links in scope,
   `"any"` = 1). Zero eligible capture phys with `"any"` → feasible as a
   supplicant-log-only trace; `warnings` says so.

Deterministic, so `plan` then `sessions` with the same inputs give the same
assignments unless the air or the adapters changed; the session response
carries the plan it actually used.

### 5.3 The shared-phy trap on this box

phy0 (BE200) hosts `wlan0` (managed) and `wlanpi0` (monitor). If `wlan0`
is the station, `wlanpi0` cannot be a capture adapter (same phy; retunes
fail with `EBUSY` while the station scans, and the capture WS would
silently capture wherever the radio sits). Rule 2 excludes it and the
reason is visible in `plan.excluded`. So a single-link trace on this box
needs one USB dongle; an MLD trace on the Wi-Fi 7 box needs one per link.
With no capture adapter at all the plan is a supplicant-log-only trace when
the caller asks for `minLinksCovered: "any"`, and a 409 otherwise.

---

## 6. Captures: file sink, sizing, retrieval

### 6.1 Why not the WebSocket

The capture WS reads dumpcap's stdout in 4 KB chunks in Python and fans out
to sockets. A slow subscriber slows the reader; dumpcap's pipe fills; the
kernel drops. Writing with `dumpcap -w` uses dumpcap's own buffered writer
and the only loss mode is disk throughput, which the manifest reports
(dumpcap exit status and its `packets dropped` stderr summary). Nothing is
streamed during a trace; progress is `fileBytes` per link on the session
descriptor.

### 6.2 dumpcap invocation and the capture filter (P6.5)

```
ip netns exec trc_<n> dumpcap -i wlanpi<N> -q -t
    -w <dir>/link<id>_<band>ghz_<iface>.pcapng
    -a filesize:<maxFileMb*1024>            # hard cap; link marked TRUNCATED
    -s <snaplen>                            # default 512, see below
    -f "<per-link filter>"                  # built at `preparing`, see below
```

The channel is set once before start, reusing `_set_channel` + `_ns_prefix`
extracted from `ConnectionManager` into `streaming/capture_runner.py` that
both callers import — that extraction *is* P6.5, no behaviour change on
the WS side (§14.3). The interface claim goes into the same registry so the
WS and the trace cannot both own `wlanpi2`.

**Filtering is on by default, because file size is the binding constraint.**
Each link gets its own `-f`, built after the plan is fixed, when that link's
BSSID is known. `capture.filterMode`:

| Mode | Filter | Use |
|---|---|---|
| `focused` (default) | the four clauses below | Everything the summary needs, without the rest of the channel |
| `full` | none | Reference runs, RF forensics, "what else was on air" |
| `mgmt_only` | `type mgt or ether proto 0x888e` | Long runs where only events matter. Drops data, so `summary.linkUsage` is omitted and `warnings` says so |

`captureFilter` (raw BPF) still exists and overrides `filterMode`; the
manifest records which was used.

**The `focused` filter, per link:**

```
   wlan host <link bssid>          # 1. everything to/from/through this AP link
or wlan host <station mac>         # 2. frames addressed to us carrying no BSSID (ACK, BlockAck)
or wlan addr1 ff:ff:ff:ff:ff:ff    # 3. broadcast receiver address
or (wlan[4] & 1 = 1)               # 4. any group-addressed frame
```

Clause 1 carries the bulk of the evidence — beacons, probe responses,
authentication, association, EAPOL and data for the BSS under test — and it
matches regardless of the station's address, which matters because an MLD's
per-link station addresses are not known until it associates.

**Clauses 3 and 4 are not garnish; the association is invisible without
them.** A wildcard Probe Request from the station carries no BSSID at all
(addr1 and addr3 are broadcast), so a BSSID-only filter hides the whole
discovery phase. A broadcast Deauthentication is how you learn the BSS
dropped everyone rather than only us. Group-addressed data is where the
GTK/IGTK rekey, ARP, DHCP and IPv6 multicast live, which is the difference
between "associated" and "actually working". Clause 4 (the group bit in
addr1) subsumes clause 3; both are listed because clause 3 is the portable
form if the byte test does not compile.

What `focused` drops, and why that is the win: every neighbouring BSS's
beacons and data. On a busy channel that is the large majority of frames.

**Fail-safe.** dumpcap rejects a bad `-f` at start-up, so a filter mistake
surfaces immediately rather than as a quiet file. If a link's dumpcap exits
within the first second with a filter error, core retries that link **once,
unfiltered**, records `filterFallback: true` on the artifact and adds a
`warnings` entry. A filter that matches nothing is indistinguishable from a
quiet channel, and that is the failure mode that wastes a walk test.

**To verify on the box before P6.5 ships** (dumpcap 3.4.16, bullseye
libpcap): that `wlan[4] & 1 = 1` compiles against a radiotap-headed monitor
interface, i.e. that libpcap applies the variable radiotap offset to
`wlan[]` indexing. If it does not, `focused` keeps clauses 1–3 and the
multicast-data note becomes a documented limitation. Verify `ether proto
0x888e` the same way before relying on `mgmt_only`.

**Snaplen: 512 by default, not 256.** An Association Request carrying a
Multi-Link element plus RSN can exceed 256 bytes, and truncating it would
cut the exact element the summary parses. 512 keeps every management frame
the parser needs while still discarding data payloads. Smaller values are
accepted but add a `warnings` entry that management parsing may truncate.
Full-length frames are needed only when a human wants to read payloads in
Wireshark.

**Sizing.** `maxFileMb` (default 512, cap 4096) is the backstop; a link
that hits it ends `TRUNCATED` and the trace continues. Retention: last 5
sessions or 4 GB, whichever bites first; a running session is never pruned.
Disk is checked at `plan` (`warnings`) and at create (`507
INSUFFICIENT_STORAGE` if the projection exceeds free minus 1 GB). The
projection uses a measured bytes-per-second-per-link figure, not a guess:
hardware verification records the same 60 s window in `full` and in
`focused` on a busy channel, and those numbers replace this paragraph.
Until then, plan for the unfiltered worst case — a busy 5 GHz channel can
exceed 4 000 frames/s — and treat `focused` as a reduction to be measured
rather than a promise.

### 6.3 Artifacts and download (M6)

```
~/.local/share/wlanpi-core/trace/<trc_xxxxxxxx>/
  manifest.json      plan + request (redacted) + state history + artifact table
  link0_5ghz_wlanpi1.pcapng            (one per assignment)
  supplicant.log     copied from the S1 store on finalise (so S1's retain-10 cannot prune it)
  supplicant.json    the S1 sidecar
  summary.json       written on finalise (M7)
```

Manifest artifact entries: `name`, `kind`
(`pcapng|supplicant_log|sidecar|summary|manifest`), `linkId`, `band`,
`iface`, `sizeBytes`, `sha256`, `packets`, `dropped`, `truncated`, `url`.
Download is Starlette `FileResponse` (Range works on 0.49),
`application/x-pcapng` or `text/plain`. The nginx front-ends need
`proxy_max_temp_file_size 0` and `proxy_buffering off` on
`/api/v1/wifi/trace/` so a 600 MB pull is not spooled to `/var/lib/nginx`.
Optional later: `?gzip=1`.

Clock: every pcap timestamp and every `-t` supplicant line is the system
clock, so the manifest records `GET /system/datetime` (source, NTP sync)
at start; the summary's timeline sorts across files on it. Radiotap TSFT is
per-adapter and is **not** used for cross-file ordering.

---

## 7. The state machine (M5)

```
planned ──► preparing ──► preroll ──► connecting ──┬─► associated ──► capturing ──► finalising ──► complete
                │            │           │         │                     │
                │            │           │         └─► assoc_failed ─► holding ─┘ (postFailureHoldSec)
                └────────────┴───────────┴───────────────────────────────────────► failed / aborted
```

| State | What runs | Leaves on |
|---|---|---|
| `preparing` | Build one **in-memory** `NamespaceConfig{mode: monitor}` per assignment and realise it through `NetworkNamespaceService` primitives (create netns, move phy, create VIF); set each channel; start each dumpcap. A link whose channel set or dumpcap fails is `linkStatus: FAILED` with the `iw`/dumpcap reason; the trace continues if coverage still meets the bar, else → `failed` with teardown. | all links started (or bar still met) |
| `preroll` | Wait `prerollSec` so every radio is demonstrably writing (`fileBytes > 0`; beacons guarantee bytes within a beacon interval). | timer |
| `connecting` | Realise the **in-memory** station `RootConfig` (`mlo: true` iff MLD target, `debug_level`) the same way, calling `ConnectionMonitor.start_monitor(timeout=associationTimeoutSec)` directly. Poll the S1 sidecar. | sidecar `outcome` |
| `associated` | Record `bssid` (or `apMldAddr` and associated links) from the sidecar. | immediate |
| `assoc_failed` | Keep capturing for `postFailureHoldSec` (the reject/deauth frames are the evidence). | timer |
| `capturing` | Run for `captureDurationSec`. Early `stop` → `CALLER_STOP`. Link process exit → link `PROCESS_EXITED`, trace continues. | timer / stop |
| `finalising` | Stop dumpcaps (SIGINT, wait, SIGTERM); reverse the capture set-up (phys home, only trace-created namespaces deleted, borrowed managed VIFs recreated); stop the station unless `keepConnected`; copy the supplicant log; hash; write `summary.json`. Each step's failure is recorded in `manifest.stateHistory` and the next step still runs. | done |

`endReason` ∈ `DURATION_ELAPSED | CALLER_STOP | ASSOC_FAILED | COVERAGE_LOST |
STATION_START_FAILED | INTERNAL_ERROR | SERVICE_RESTART`. On core start-up
any manifest left in a running state is marked `aborted/SERVICE_RESTART`
and the existing `revert_to_root` cleanup runs for its namespaces; files
are kept.

**The orchestrator never touches the stored-config path.** It does not
create NetConfig files, does not call `activate_config()`, and does not
write `current.txt`. That is not tidiness: `activate_config()` enforces one
active config, so it would refuse (409) whenever a user config is active,
and `override_active` would call `kill_all_supplicants()` and drop the
user's connections. Full reasoning in §14.1. The orchestrator builds
`NamespaceConfig` / `RootConfig` objects in memory, drives
`NetworkNamespaceService` primitives with them, and records in the manifest
exactly what it created so teardown and start-up recovery can reverse it.

`ConnectionMonitor.start_monitor(timeout=)` already takes the argument the
orchestrator needs, so the S1 activate route is untouched by this work.

---

## 8. The summary the agent reads (M7)

One document; the agent should need nothing else for the short test.
Generic fields first; the `mlo` blocks are present only for an MLD target.

```json
{
  "target": {"ssid": "WLANPI-LAB", "kind": "bss", "bssid": "…", "links": [ … ]},
  "outcome": {"associated": true, "bssid": "…", "secondsToAssociate": 0.92,
              "linksCovered": [0], "linksUncovered": [], "endReason": "DURATION_ELAPSED",
              "mlo": null},
  "perLink": [
    {"linkId": 0, "band": "5", "freq": 5220, "iface": "wlanpi1",
     "frames": {"total": 18234, "mgmt": 912, "ctrl": 3020, "data": 14302, "retryPct": 4.1},
     "stationFrames": {"toSta": 4021, "fromSta": 3980, "avgRssi": -54, "mcsHistogram": {"9": 800}},
     "beacons": {"count": 450, "bssid": "…", "firstAt": "…", "lastAt": "…"},
     "handshake": {"auth": "…ts…", "assocReq": "…", "assocResp": {"ts": "…", "status": 0},
                   "eapol": ["m1@…", "m2@…", "m3@…", "m4@…"]},
     "truncated": false, "dropped": 0}
  ],
  "timeline": [
    {"t": "…", "src": "supplicant", "kind": "auth_attempt", "bssid": "…"},
    {"t": "…", "src": "link0", "kind": "auth", "dir": "sta→ap", "status": 0},
    {"t": "…", "src": "link0", "kind": "assoc_req"},
    {"t": "…", "src": "link0", "kind": "assoc_resp", "status": 0},
    {"t": "…", "src": "link0", "kind": "eapol", "msg": 3},
    {"t": "…", "src": "supplicant", "kind": "connected"},
    {"t": "…", "src": "link0", "kind": "action", "category": "wnm", "subtype": "bss_transition_request"},
    {"t": "…", "src": "supplicant", "kind": "disconnected", "reason": 3, "locallyGenerated": true},
    {"t": "…", "src": "link1", "kind": "reassoc_req"}
  ],
  "linkUsage": [{"windowStart": "…", "windowSec": 10, "perLink": {"0": {"data": 1201}}}],
  "warnings": []
}
```

For an MLD target, `outcome.mlo = {apMldAddr, linksAssociated[]}`,
`beacons.mlIeLinks[]`, `assocReq/assocResp` carry `mlIeLinks` /
`acceptedLinks`, `eapol` entries carry `mloLinkKeys[]`, and the timeline
gains `mlo_link`, `link_reconfig`, `tid_to_link_mapping_*` kinds.

Parser scope (Python, no tshark): radiotap (TSFT, flags, rate/MCS/VHT/HE,
dBm, channel); 802.11 header (type/subtype, addresses, seq, retry,
protected); mgmt IEs incl. SSID, RSN, Channel Switch Announcement, BSS
Transition (WNM action), FT authentication, Multi-Link (ext id 107) and
TID-to-Link Mapping (ext 109); status/reason codes; Protected EHT action
subtypes; EAPOL-Key detection on data frames (LLC/SNAP 0x888e, key info →
message 1–4; MLO GTK/IGTK KDEs by link when present). `linkUsage` is a 10 s
histogram of data frames to/from the station's addresses per link — the
"which channel carried the traffic / did the primary link change" evidence
for the long test. The station's addresses come from the S1 sidecar (MLD
keys when present, else the interface MAC) and from supplicant lines.

The supplicant half of the timeline is S2's `parse_events()`; M7 merges,
it does not re-parse.

---

## 9. Error contract

| HTTP | `error` | Meaning | What a caller does |
|---|---|---|---|
| 409 | `MODE_CONFLICT` | Not classic mode | Stop; report. |
| 409 | `SESSION_ACTIVE` | A trace is running (id attached) | Wait, or `stop` it only if it is yours (ask). |
| 409 | `STATION_NEEDS_SELECTION` | More than one eligible station phy; `candidates[]` attached | Pick one, re-issue with `station.phy`. |
| 409 | `STATION_NOT_EHT` | MLD target but chosen phy is not EHT-capable | Choose another phy or report. |
| 409 | `TARGET_NOT_FOUND` | SSID (or bssid/mldAddr) not seen | Re-scan once; then report. |
| 409 | `INSUFFICIENT_ADAPTERS` | Coverage below `minLinksCovered`; `plan` attached | Tell the human what would be uncovered; re-issue with a lower bar only on their say-so. |
| 409 | `INTERFACE_IN_USE` | A capture WS session holds a chosen interface | List capture sessions; never stop someone else's. |
| 409 | `NOT_FINALISED` | Summary/artifact requested while running | Poll `GET /sessions/{id}`. |
| 422 | `VALIDATION_ERROR` | Bad body (duration range, unknown band, `mldAddr` on a non-MLO SSID, bad filter) | Fix and retry. |
| 507 | `INSUFFICIENT_STORAGE` | Projected size exceeds free space | Shorter duration, snaplen, or delete old sessions. |
| 404 | — | Unknown session/artifact | — |

Every 4xx body is `ApiErrorResponse` (`error`, `message`, optional
`detail`), matching the scan routes, and every code is enumerated in the
route's `responses=` so it lands in Swagger and in the MCP tool description.

---

## 10. OpenAPI and Swagger requirements (M8, enforced from M1)

- New tag `connection_trace` in `OPENAPI_TAGS`: what a trace is (one
  station, N capture adapters, one supplicant log), that it is
  create-then-poll, that results are files on the box plus a JSON summary,
  that `plan` is the safe dry run, and that MLO is the multi-link case of
  the same resource.
- `operationId` on every route (§4) — MCP generators use it as the tool name.
- Every model is Pydantic with `Field(description=…, examples=[…])` on every
  field, camelCase aliases, and `Literal`/`Enum` for `kind`, `scope`,
  `state`, `endReason`, `band`, `profile`, `eligibility.reasons`,
  `uncovered.reason`, `linkStatus`, `filterMode`.
- Three full request examples on `trace_session_create` (single-link
  `assoc`, ESS `roam`, MLD `assoc`) and two `Plan` examples on `trace_plan`
  (feasible single link; MLD one adapter short), via `openapi_examples`.
- `responses=` carries every §9 code with `ApiErrorResponse`; the download
  route declares `application/x-pcapng` and `text/plain` content and `206`.
- `OPENAPI_DESCRIPTION` gets a row in "Long-running and multi-step work":
  *Create, poll, then fetch — `POST /wifi/trace/sessions` → `GET
  /wifi/trace/sessions/{id}` until `complete` → `/summary` (JSON) and
  `/artifacts/{name}` (files; not for the model).*
- `docs/API-INTEGRATION-GUIDE.md` Lesson 13 "Connection trace" with the
  poll loop and the "never pass a pcap to the model" note;
  `docs/openapi.json` is regenerated by the sync workflow, never hand-edited.
- `tests/test_openapi_schema.py`: add `connection_trace` to
  `EXPECTED_TAGS`; a test that every `/wifi/trace` operation has an
  `operationId`, a `description`, and at least one documented 4xx.

---

## 11. Faults and how each one shows up

| Fault | Where it lands | Trace continues? |
|---|---|---|
| Fewer adapters than links | `plan.uncovered`, 409 unless bar met | per caller |
| No capture adapters at all | feasible only for `"any"`; `warnings` | yes (log-only) |
| Station phy is the only monitor phy | excluded `PINNED_STATION_PHY`; as above | yes (log-only) |
| Channel set fails on a link | link `FAILED` + `iw` reason; coverage re-checked | if bar still met |
| dumpcap exits early | link `PROCESS_EXITED`, partial file kept | yes |
| File cap hit | link `TRUNCATED` | yes |
| Station never associates | `assoc_failed` → hold → finalise; `endReason: ASSOC_FAILED` | yes, that is the evidence |
| Supplicant fails to start | `failed/STATION_START_FAILED`; capture files kept | no |
| Target gone between plan and create | 409 `TARGET_NOT_FOUND` | — |
| Link set differs at create from the plan | re-planned at create; response plan authoritative; `warnings` | yes |
| Station roams to a channel not in scope (`target` scope) | visible only in the supplicant log; summary `warnings` names the new bssid/channel and suggests `scope: "ess"` | yes |
| 6 GHz disabled by reg domain | `BAND_DISABLED_REGULATORY` | per bar |
| Adapter unplugged mid-run | link `PROCESS_EXITED`; teardown tolerates a missing phy | yes |
| Capture filter rejected by dumpcap | one unfiltered retry for that link; `filterFallback: true` + `warnings` (§6.2) | yes |
| Core restarts | `aborted/SERVICE_RESTART`, namespaces reverted, files kept | — |
| Disk low | 507 at create; `warnings` at plan | — |
| Caller disappears | nothing changes: sessions are not socket-bound; the duration cap bounds the radio hold | yes |

---

## 12. What MLO adds (and nothing else)

| Aspect | Classic BSS / ESS | AP MLD |
|---|---|---|
| Target kind | `bss` (one link) or `ess` scope (one link per channel) | `mld` (one link per affiliated BSS) |
| Station eligibility | any managed-capable phy | `ehtCapable` phy; `RootConfig.mlo: true` |
| Scan dependency | none beyond today's scan | S3 (`mld` grouping) |
| Capture adapters needed | 1 (or channels in ESS) | link count (2–3) |
| Summary extras | — | `outcome.mlo`, Multi-Link IE fields, per-link EAPOL keys, `mlo_link` / `link_reconfig` / TID-to-link events |
| Supplicant lines used | `SME:`, `Associated`, `CTRL-EVENT-*` | plus `MLD: assoc:`, `CTRL-EVENT-LINK-RECONFIG` |

Everything else — namespaces, file sink, artifacts, download, state machine,
error contract, planner — is identical. That is why the resource is
`/wifi/trace`, not `/wifi/mlo`.

---

## 13. Branches and PR stack (one concern each, ≤ ~400 lines)

### 13.1 Where each piece lives

This plan and the blueprint are a **docs-only** concern on
`docs/connection-trace-plan`, forked from `docs/capture-ws-lifetime-plan`
and sent as a fork PR into it, exactly as the lifetime plan was. **None of
this work belongs on `feature/capture-detach-p64`:** P6.4 is detached
bounded captures and nothing else.

Two bases, decided by what each PR touches:

| Base | Which PRs | Why |
|---|---|---|
| **P6 stack tip** (`feature/capture-detach-p64`) | **P6.5** only | It edits `streaming/connection_manager.py`, whose namespace-aware capture primitives exist *only* on the P6 stack. On `dev` the method is `_set_channel(iface, freq, width)` with no namespace argument, and neither `_ns_prefix` nor `_resolve_namespace` exists; the interface-claim registry the file sink must share is P6's `did`-owned model. Branching it from `dev` would mean writing the netns machinery twice and guaranteeing a conflict when #165 merges. |
| **`dev`** | S2, S3, M1, M2, M3 | New modules and read-only routes. They touch no capture WS code, so they need nothing from the P6 line. |

Everything downstream of P6.5 (M5 onward) inherits its base until #165 and
the P6.x stack merge upstream; the whole line is then re-sent against `dev`
in order, per `capture-ws-lifetime-plan.md` §2.

### 13.2 The stack

```
dev
├── S2 feature/supplicant-log-api        log read routes + parse_events           [prereq, planned]
├── S3 feature/scan-mld-fields           mld + band on scan rows                  [MLD targets only]
├── M1 feature/trace-adapter-inventory   GET /wifi/trace/adapters; parsed phy caps (absorbs S4)
├── M2 feature/trace-targets             GET /wifi/trace/targets (bss/ess now; mld once S3 lands)
└── M3 feature/trace-plan                planner + POST /wifi/trace/plan + CSV matrix   needs M1, M2

feature/capture-auth (P6, #165) → P6.1 → P6.2 → P6.3 → feature/capture-detach-p64 (P6.4)
└── P6.5 feature/capture-file-sink-p65   capture_runner extraction; dumpcap -w file sink;
    │                                    claims shared with the WS. No WS behaviour change.
    ├── M5 feature/trace-session         orchestrator, state machine, persistence, routes  needs M3, S1
    ├── M6 feature/trace-artifacts       manifest, download (Range), retention, nginx      needs M5
    ├── M7 feature/trace-summary         802.11 parser, merged timeline, /summary          needs M6, S2
    └── M8 docs/connection-trace-docs    OpenAPI polish, guide Lesson 13, classroom L15/L16
```

**P6.5 is the one that must stay small and boring.** It moves `_ns_prefix`,
`_resolve_namespace` and `_set_channel` into `streaming/capture_runner.py`,
adds a file-sink start/stop the WebSocket path does not call, and leaves
every existing capture WS test passing unchanged. It keeps thin delegating
methods on `ConnectionManager` so existing patch targets still resolve
(§14.3). If it acquires a behaviour change, it is the wrong PR.

A single-link trace is usable after M1, M2, M3, P6.5, M5 and M6 with S1
(the summary is M7; until then the log is retrievable by the file path in
the manifest, and by `conn_id` once S2 lands). MLD targets need S3 in M2.
M1, M2 and P6.5 are independent and can go in parallel. M5 is the one to
review hardest; split it M5a (orchestrator + tests, no routes) and M5b
(routes) if it passes 400 lines. Debian changelog bumps on P6.5 and M1–M7;
none on M8 or the docs branch.

**Test rules that bite** (AGENTS.md): the orchestrator is asyncio with real
subprocesses in production — inject `_clock`, `_sleep`, and a process
factory the way `ConnectionManager` does, and never wait on wall time;
matrix the planner in CSV; the dumpcap/`iw` calls are mocked with
`threading.Event`-based synchronisation, not polling; fixtures for M7 are
real pcapngs recorded on the box during hardware verification, payloads
zeroed.

**Hardware verification checklist.** Single link, on this box plus one USB
dongle, after M5: (1) station `wlan0` never moves, `wlanpi0` is excluded
with `SHARED_WITH_MANAGED`; (2) one-link plan feasible, dongle assigned;
(3) wrong PSK → `ASSOC_FAILED`, auth/assoc/deauth in the summary; (4) `ess`
scope with two APs on different channels and two dongles → `roam` 10 min
walk shows reassoc on the second link; (5) WS `start` on the claimed
`wlanpiN` gets `INTERFACE_IN_USE`; (6) `Range` download of a 600 MB file
through nginx `:31416`; (7) `systemctl restart wlanpi-core` mid-trace →
`aborted`, phys home, files kept. MLD, on the Wi-Fi 7 box: (8) Qualcomm phy
stays in root for the whole trace; (9) three dongles cover a 3-link AP,
assignments match `bandPriority`; (10) unplug one → `PROCESS_EXITED`, trace
completes; (11) `roam` walk → `linkUsage` shifts, `link_reconfig` present;
(12) which `wpa_cli status` keys carry the station's per-link addresses on
2.11 + this driver (the MLD `linkUsage` depends on it).

Three more that gate the filter and the compatibility claim: (13) each
`focused` clause compiles under dumpcap 3.4.16, in particular
`wlan[4] & 1 = 1` against a radiotap monitor interface, and a deliberately
bad `-f` triggers exactly one unfiltered retry; (14) the same 60 s window
recorded `full` and `focused` on a busy channel, with the measured sizes
written back into §6.2, and the `focused` file still containing the
station's probe requests, the beacons, the four EAPOL frames and at least
one group-addressed frame; (15) with **no** trace and no capture running,
`GET /utils/wlan/scan`, `GET /network/interfaces`, `GET /network/config/`
and `GET /network/config/status` return what they returned before the
branch, and during a trace the scan does not select a claimed adapter.

---

## 14. Compatibility: what must not break

**The invariant.** With no trace running and no capture session open, every
existing endpoint returns exactly what it returns today. Everything below is
either additive or gated on a trace being active. The reviewer's check is
that P6.5 and M1–M7 **add** tests and edit no existing expectation.

### 14.1 Three things in the first draft that would have broken, and what replaced them

| # | The draft said | What it would have broken | Now |
|---|---|---|---|
| 1 | Create `_trc_cap_<id>` / `_trc_sta_<id>` NetConfigs and activate them through `POST /network/config/activate/{id}` | `activate_config()` enforces a single active config: with any user config active it raises `ConfigActiveError` (409), so the trace would fail whenever someone had a config on. With `override_active` it calls `ns.kill_all_supplicants()`, **dropping the user's connections**. On success it overwrites `current.txt`, so the device forgets which config the user activated. | The orchestrator never touches the config store. It builds `NamespaceConfig` / `RootConfig` objects in memory and drives `NetworkNamespaceService` primitives directly. `CONFIG_DIR`, `current.txt`, `kill_all_supplicants` and the single-active-config rule are untouched, and a trace can run while a user config is active. |
| 2 | Hide trace configs from `GET /network/config/` behind `?system=true` | A new filter on `list_configs()`, a semantic change to a shipped route, for the benefit of configs that no longer exist. | Dropped entirely. No change to `list_configs()`. |
| 3 | `POST /network/config/activate/{id}` gains `?association_timeout=` | Not breaking, but a public-API change for nothing. | Dropped. `ConnectionMonitor.start_monitor(timeout=…)` already takes it. S1's activate route is untouched. |

### 14.2 Interactions that must be handled, each gated on a trace running

| # | Risk | Rule |
|---|---|---|
| B4 | `select_scan_adapter()` counts monitor adapters **across all namespaces**. While a trace holds two or more monitor VIFs, a bare `GET /utils/wlan/scan` would flip to `needsSelection: true`, and auto-selection could pick a capture VIF and **retune a radio mid-trace**. | Adapter enumeration gains `busy: true` for interfaces claimed by a trace or a capture WS session, and scan candidate selection skips busy adapters. With nothing running the candidate list is identical to today. This also fixes a latent form of the same problem with today's capture WS (handover §7). |
| B5 | Borrowing a phy that hosts an **idle managed** interface removes e.g. `wlan0` from root for the duration, changing `/network/interfaces`, `/network/config/status` and scan selection. | Not eligible by default; `capture.allowBorrowIdleManaged: true` is an explicit caller opt-in. Teardown recreates the VIF on its original phy, in root, with its original name and type, and start-up recovery does the same after a crash. |
| B6 | `wlanpiN` name collision with an existing monitor VIF. | Allocate the lowest free index across all namespaces. Never rename, retune or delete a VIF the trace did not create. |
| B7 | Namespace deletion. | Delete only namespaces this trace created, as recorded in the manifest. Never a pre-existing one, even if it matches `trc_*`. |
| B8 | Capture WS contention. | A trace claim makes a WS `start` on that interface return the **existing** `INTERFACE_IN_USE` error. New contention, no new error code; note it in the handover. |
| B9 | nginx buffering. | `proxy_buffering off` and `proxy_max_temp_file_size 0` go **inside `location /api/v1/wifi/trace/`** only. Server-wide would change buffering for every endpoint. |
| B10 | `GET /network/config/status` shows `trc_*` namespaces while a trace runs. | Accepted and documented. The response is a map keyed by namespace, clients iterate keys, and those namespaces genuinely exist. They disappear on finalise. |
| B11 | S1 log retention (10 attempts) could prune the log a finished trace refers to. | Finalise copies the log and sidecar into the session directory; the trace never depends on the S1 store surviving. |

### 14.3 P6.5 specifically

`tests/test_streaming_processes.py` both patches and calls
`manager._set_channel(...)` directly, in five places. So the extraction
**keeps `_set_channel`, `_ns_prefix` and `_resolve_namespace` on
`ConnectionManager` as thin delegates with unchanged signatures**, with the
implementation in `streaming/capture_runner.py`. The existing capture tests
must pass **unedited**; that is the acceptance test for "no behaviour
change", and a PR that has to touch them is the wrong PR.

---

## 15. Out of scope (do not smuggle in)

- Live tailing of a trace (WS subscribe to a file-backed capture). A later
  PR can `tail` the summary counters if there is a real need.
- Injection, deauth tests, or any transmit from a capture adapter.
- Capture width 320 MHz (adapter and `validate_capture_width` both cap at
  160; mgmt is on the primary 20 MHz anyway).
- Multiple concurrent traces.
- Following a roam to an unplanned channel by retuning a capture adapter
  mid-trace (`ess` scope is the answer; retune-on-roam is a later concern).
- Upgrading tshark on the image. The Python parser covers what the summary
  needs; humans use Wireshark 4.x on the fetched files.
- Per-user ACLs on artifacts (device-open reads, auth plan Appendix A,
  policy A, same as capture subscribe).
