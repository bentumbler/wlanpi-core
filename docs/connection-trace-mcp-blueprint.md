# Connection trace — MCP blueprint for wlanpi-mcp

**Audience:** the wlanpi-mcp engineer (and the coding agents they drive).
**Prereq reading:** [`connection-trace-plan.md`](./connection-trace-plan.md)
(the core contract this wraps), [`capture-ws-mcp-handover.md`](./capture-ws-mcp-handover.md)
§2/§4 (identity and token), [`mcp-auth-plan.md`](./mcp-auth-plan.md).
**Status:** blueprint, 2026-09-15; the core routes are P6.5 and M1–M7 in
the plan (§13) and are not shipped yet. Build against the OpenAPI once M1 lands; mock the
rest from the examples in this file.

A **connection trace** is one station adapter connecting to an SSID while
N capture adapters (one per channel or MLO link in scope) record to files
on the box and the supplicant writes a debug log. N = 1 for a classic AP,
N = channels in use for a roaming test across an ESS, N = affiliated links
for a Wi-Fi 7 AP MLD. The tools below are the same for all three; only the
plan's coverage numbers and a few summary fields differ.

The principle from the capture handover still holds: **core provides
primitives and one orchestrated resource; MCP wraps them as small, typed
tools and never ships raw bytes to the model.**

---

## 1. Tool set

Names follow the `operationId`s in the plan so generated and hand-written
tools agree. All tools take the core JWT from the environment (handover
§4), speak to `http://localhost:31415` on-box or `https://wlanpi.local:31416`
remote, and return the core JSON unchanged apart from the additions noted.

| Tool | Core route | Blocks? | Returns |
|---|---|---|---|
| `trace_adapters` | `GET /wifi/trace/adapters` | no | inventory + eligibility reasons |
| `trace_targets(ssid?, iface?, namespace?)` | `GET /wifi/trace/targets` | ≤ 15 s (a scan) | targets (`bss` / `mld`) and `ess[]`; may return `needsSelection` exactly like `wlan_scan` |
| `trace_plan(target, capture, station?)` | `POST /wifi/trace/plan` | no | `Plan` — dry run, no side effects |
| `trace_start(request)` | `POST /wifi/trace/sessions` | no | `202` session descriptor with the applied plan, or a typed 409 (§3) |
| `trace_status(session_id)` | `GET /wifi/trace/sessions/{id}` | no | state, per-link `fileBytes`, station status, `remainingSec` |
| `trace_wait(session_id, until, max_wait_sec)` | polls `GET …/{id}` every 2 s | ≤ `max_wait_sec` (cap 120) | the descriptor when `until` is reached or the budget runs out (`reached: false`) |
| `trace_stop(session_id)` | `POST …/{id}/stop` | no | descriptor |
| `trace_summary(session_id, detail?, link_id?)` | `GET …/{id}/summary` | no | the merged timeline document (§4) |
| `trace_artifacts(session_id)` | `GET …/{id}/artifacts` | no | manifest |
| `trace_fetch(session_id, name, dest_dir?)` | `GET …/{id}/artifacts/{name}` | yes, until saved | `{path, sizeBytes, sha256, verified}` — **the file lands on the MCP host's disk; the bytes never enter the tool result** |
| `trace_delete(session_id)` | `DELETE …/{id}` | no | `{deleted: true}` |
| `trace_list()` | `GET /wifi/trace/sessions` | no | recent sessions |
| `supplicant_events(conn_id)` | `GET /network/config/supplicant-logs/{conn_id}/events` (S2) | no | parsed supplicant events, for callers who want the log side alone |

`until` for `trace_wait` ∈ `associated | capturing | complete | ended`
(`ended` = any terminal state). MCP clients time out tool calls (commonly
60–120 s), so a 10-minute trace is driven by the agent calling `wait`
repeatedly; each call returns progress it can narrate. Do not build a
single blocking "run the whole trace" tool.

`trace_fetch` streams with `Range` resumption, verifies the manifest
`sha256`, writes to `dest_dir` (default: a per-session folder under the MCP
host's data dir) and refuses `name`s not in the manifest. It is the only
tool that moves large data and the only one a human needs when they want
Wireshark.

---

## 2. Sequencing (what the agent should be led to do)

```
trace_adapters                   ── know what the box can do before promising anything
trace_targets(ssid)              ── resolve the SSID: one BSS, an ESS of several, or an MLD; log channels/bands   ⎇ needsSelection → pick, retry
trace_plan(target, capture)      ── read coverage; if uncovered links: STOP and tell the human
trace_start(request)             ── only after the plan is acceptable
trace_wait(id, "associated", 60)      ── narrate: associated to which BSS (or links), seconds to associate
trace_wait(id, "complete", 120) ×N    ── narrate per-link fileBytes growth; for `roam`, every ~2 min
trace_summary(id)                ── the evidence; build the report from this
trace_artifacts(id)              ── list the files; fetch only if the human asks
trace_delete(id)                 ── only if the human says the files are no longer needed
```

Two things MCP should enforce in the tool layer rather than trust the model
to remember:

1. **`trace_start` refuses to run without a prior `trace_plan` in the same
   MCP session whose `feasible` was true, or an explicit
   `confirmed_partial: true` argument.** The 409 `INSUFFICIENT_ADAPTERS`
   from core is the backstop; this is the front stop. It mirrors the
   classroom rule that an agent never authorises a degraded run on its own.
2. **Tool descriptions state the safety envelope**: the station phy is
   never used for capture; the trace never transmits from capture adapters;
   `keepConnected: false` is the default so the box is left as found; and a
   trace changes nothing another API consumer can see except that adapters
   it holds are marked busy for the duration (plan §14).
3. **Do not set `filterMode: "full"` to "be safe".** `focused` is the
   default because file size is the binding constraint, and it already
   keeps the station's probe requests, broadcast deauthentication and
   group-addressed traffic (plan §6.2). `full` is for a human who has asked
   to see the rest of the channel, and on a long run it is the difference
   between a fetchable file and a multi-gigabyte one. `mgmt_only` drops the
   data that `linkUsage` counts, so never pick it for a roam question.
4. **Do not set `allowBorrowIdleManaged` without asking.** It moves an idle
   `wlan0`-style interface out of the root namespace for the duration.

Scope choice belongs to the human: `target` for "show me the association",
`ess` for "show me the roam". The tool description for `trace_plan` should
say that an ESS roam test needs one adapter per channel in use and that a
roam to an unplanned channel is only visible in the supplicant log.

---

## 3. Error mapping

| Core response | Tool result | Agent guidance in the tool description |
|---|---|---|
| 409 `INSUFFICIENT_ADAPTERS` | `{error, plan}` | Report the uncovered links and their `reason`. Ask the human whether a partial trace is acceptable. Re-issue with `minLinksCovered` lowered **only** on a yes. |
| 409 `STATION_NEEDS_SELECTION` | `{error, candidates}` | Choose by `bus` and (for MLD) `ehtCapable`; say which one and why. |
| 409 `STATION_NOT_EHT` | `{error, candidates}` | The MLD target needs an EHT station; pick one or report. |
| 409 `TARGET_NOT_FOUND` | `{error}` | Re-scan once; then report with the `targets` evidence. |
| 409 `SESSION_ACTIVE` | `{error, sessionId}` | Never stop a session this MCP did not start. Offer to wait. |
| 409 `INTERFACE_IN_USE` | `{error, interfaces}` | A capture WS owns a radio; list sessions via the capture tools; never stop someone else's. |
| 409 `MODE_CONFLICT` | `{error}` | Wrong device mode; stop. |
| 422 | `{error, detail}` | Fix the request (e.g. `mldAddr` given for a non-MLO SSID). |
| 507 | `{error, projectedMb, freeMb}` | Suggest a shorter duration or `snaplenBytes`, or deleting old sessions (ask first). |
| Any 401 | re-issue token per handover §4 | — |
| `wait` budget exhausted | `{reached: false, state, …}` | Normal for long traces; call again. |

Every error is a **structured tool result**, not an exception: an exception
tempts an agent to retry the same call.

---

## 4. What the model gets, and what it must not get

- **Gets:** `summary.json` (bounded: the timeline is capped at ~2 000
  events by core, oldest data events dropped first, mgmt/EAPOL/action never
  dropped), the plan, the manifest (names, sizes, hashes), supplicant
  `events` (S2). Typical size 20–150 KB.
- **Never gets:** pcap bytes, the full `-dd` supplicant log (`/content`),
  or the raw `iw phy` text. If the agent needs a specific frame,
  `trace_summary(session_id, detail="link", link_id=…)` returns the
  per-link handshake block with per-frame records for mgmt and EAPOL only.
  Anything beyond that is Wireshark territory: `fetch` the file and hand
  the path to the human.

Context budget: the `roam` summary's `linkUsage` histogram is 10 s bins; at
one hour that is 360 rows × links — fine. Do not lower the bin size in MCP.

---

## 5. The report the agent should produce

Give this shape to the model in the `trace_summary` tool description so
reports are comparable across runs (the classroom L15/L16 rubrics grade it):

1. **Target** — SSID, kind (BSS / ESS / MLD), BSSID or AP MLD address,
   links (band/channel/width) as seen by the scan, and which were captured
   (coverage and why not).
2. **Association** — seconds to associate; which channel/link carried
   Authentication/Association; status codes; 4-way handshake completion
   per captured link. For an MLD: which links the AP accepted, from the
   Association Response Multi-Link element **and** the supplicant's
   `mlo_link` lines — they must agree, say if they do not.
3. **Behaviour over time** (`roam` only) — data share per link over time;
   roams (reassociation to a new BSSID), BSS transition requests, channel
   switch announcements; for an MLD, TID-to-link mapping and link
   reconfiguration events; a plain-language reading ("moved from AP-2 on
   channel 44 to AP-1 on 36 at 14:03 as RSSI fell below −70").
4. **Anomalies** — retries above ~10 %, deauth/disassoc with reason codes,
   a captured link that never carried the station's frames, dumpcap drops
   or truncation, a roam to a channel outside scope.
5. **Evidence pointers** — artifact names and timeline timestamps the
   claims rest on. Two independent evidence types for the headline claim
   (supplicant + pcap), as in every other lab.
6. **Confidence and gaps** — uncovered links, `truncated` files, clock
   source (`manifest.datetime.ntpSynced`).

---

## 6. Manual fallback (when the orchestrator is not on the box)

The same outcome can be composed from primitives; it is slower and the
agent must do the ordering itself. Keep this in the MCP docs as "degraded
mode", not as a tool:

1. `wlan_scan(detail=full)` → pick the BSS (or group rows by `mld.addr`, S3).
2. `config_create` a NetConfig with one `NamespaceConfig{mode: monitor}`
   per capture adapter; `config_activate`.
3. One capture WS per adapter: `configure` single channel, `start` with
   `duration_sec`; a collector process `subscribe`s and writes each stream
   to a file (harness `--raw-out`). Wait for every `CAPTURE_STARTED`.
4. `config_create` + `config_activate(debug_level=2)` for the station
   `RootConfig` (`mlo: true` for an MLD); keep the `conn_id`.
5. Poll `GET /network/config/supplicant-logs/{conn_id}` until `outcome`
   changes; hold; `stop` captures by `session_id`.
6. Deliver: S2 `events` + the collector's files. No merged summary.

The streamed variant is exactly what D2 in the plan avoids for more than
one link; use it for one link or on-box only.

---

## 7. Classroom mock (Mode M) for L15/L16

A ~120-line FastAPI stub serving `/wifi/trace/*` from canned JSON is enough
for the labs until M5 ships, exactly as the capture mock in
`MCP-LAB-INSTRUCTOR-NOTES.md` §6. Canned sets: a single-BSS target
(`WLANPI-LAB`), an ESS of two APs on two channels, a 3-link MLD
(`WLANPI-EHT`); adapter inventories for 3, 2, 1 and 0 eligible capture
phys; a plan for each combination; a session that walks the state machine
on a timer (`preparing` 2 s, `preroll` 3 s, `connecting` 4 s, `capturing`
for the requested duration); one `assoc_failed` variant (wrong PSK, status
code 1 in the summary); success summaries for the single-link and MLD
cases; a manifest whose `fetch` returns a small real pcapng recorded on
hardware. The instructor console flips the adapter count between groups.

---

## 8. Checklist for the MCP engineer

1. Generate tools from `docs/openapi.json` once M1 lands; keep the
   `operationId` names.
2. Implement `trace_wait` and `trace_fetch` by hand (polling and Range
   download are not in the spec).
3. Front-stop in `trace_start` (§2 item 1).
4. Structured errors for every §3 row; unit-test each mapping against the
   plan's example bodies.
5. Cap tool results at the sizes in §4; never return bytes.
6. Report shape (§5) in the summary tool's description.
7. Token from env, never in `mcp.json` (handover §4).
8. Test against the Mode M mock, then on the box: single link with one USB
   dongle first, MLD on the Wi-Fi 7 box second (plan §13 checklist).
