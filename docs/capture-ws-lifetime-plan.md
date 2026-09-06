# Capture WebSocket session lifetime — plan (P6.2 / P6.3 / P6.4)

Companion to [`capture-ws-mcp-handover.md`](./capture-ws-mcp-handover.md) (the
consumer contract) and [`mcp-rollout.md`](./mcp-rollout.md) (the master plan).
This document scopes three follow-ups to P6 (#165) that make a capture
session's **lifetime** visible and, optionally, bounded and detachable. Each is
one PR, one concern, and they stack in order.

## 0. Problem

A passive subscriber to a running capture already learns what it is receiving:
`SESSIONS`, `SUBSCRIBED`, and `CONFIG_CHANGED` all carry the session descriptor
(owner `did`, interfaces, namespace, per-interface channels/dwell, filter). It
does **not** learn how long the capture has been running or how long it will
continue, because today a capture has no end other than the owner stopping,
the owner's socket closing, or dumpcap exiting. "How long left" is undefined.

Two consequences we want to fix:

1. There is no way to start a capture that stops itself. Every client that wants
   a bounded capture (harness `--duration`, MCP `duration_s`) implements a local
   sleep-then-`stop`, and nothing else on the box can see that plan.
2. Because the capture lives with the owner's socket, a caller cannot start a
   bounded capture, hand it to a child process that subscribes and writes the
   stream to a file, and exit. The capture dies with the parent.

## 1. Lifetime rule (the design in one table)

| Capture | Owner socket closes | Nobody attached | Deadline reached | `stop` |
|---|---|---|---|---|
| **Perpetual** (no `duration_sec`) | stop now (unchanged) | n/a — dies with owner | n/a | owner socket |
| **Bounded** (`duration_sec` set) | keeps running, marked detached | stop after a fixed grace window | stop, reason `DURATION_ELAPSED` | owner socket, **or any socket authenticated as the owner's `did`**, by `session_id` |

Principles:

- **Perpetual captures never outlive their owner.** Nobody else can stop or
  retune them, so letting subscribers keep a radio pinned indefinitely is the
  wrong default. Existing behaviour and the handover's "capture lives with its
  socket" rule are preserved for the perpetual case.
- **Only a bounded capture may be detached.** The deadline is the backstop for
  every failure mode (owner gone, token revoked, saver process crashed). The cap
  on `duration_sec` bounds the blast radius.
- **A detached capture with no listeners is an orphan** and is stopped after a
  short server-side grace window (reason `NO_LISTENERS`). The grace exists
  because "start, fork a saver, exit" races the child's `subscribe` against the
  parent's socket close. It is a constant, not client-settable — a second
  client-chosen timeout would be one more thing to reason about.
- **Every end tells you why.** `CAPTURE_STOPPED` keeps its code (existing
  clients keep working) and gains `data.reason`.
- **Clocks are monotonic and internal.** No raw timestamps on the wire; clients
  get integer `elapsed_sec` / `duration_sec` / `remaining_sec` computed at send
  time.

## 2. PR stack

All three are single-commit branches. Until #165 (`feature/capture-auth`)
merges upstream, they are fork PRs into the branch below them; once #165 lands
they are re-sent upstream against `dev` in order.

```
feature/capture-auth (P6, #165)
└── feature/capture-live-reconfig-p61 (P6.1, fork PR #6)
    └── feature/capture-descriptor-clock-p62 (P6.2)
        └── feature/capture-duration-p63 (P6.3)
            └── feature/capture-detach-p64 (P6.4)
```

P6.2 does not functionally depend on P6.1, but both touch the descriptor,
`start_streaming`, and Lesson 11, so stacking avoids merge noise.
`integration/mcp-prague` merges the top of the stack for device testing and is
never a PR source.

### P6.2 — elapsed / lifetime fields on the session descriptor

**Concern:** anyone who can list or subscribe can see how long the capture has
been running. Additive JSON, no behaviour change.

| Change | Where |
|---|---|
| Record monotonic start on `start`; clear on session end | `ConnectionManager.start_streaming` / `_end_session` |
| Descriptor gains `elapsed_sec` (int, computed at send time), `duration_sec: null`, `remaining_sec: null` | `_session_descriptor`; also on `CAPTURE_STARTED` |
| Clock is an injectable attribute (`manager._clock`, default `time.monotonic`) so tests never patch `time` (AGENTS #7) | `ConnectionManager.__init__` |
| Harness prints the lifetime line under the config on subscribe / list | `tools/capture_harness` `_print_config` |
| Docs: Lesson 11 (11.2, 11.4), handover §1/§2a | `docs/` |

Tests (`tests/test_streaming_processes.py`): `SESSIONS` and `SUBSCRIBED` carry
the fields; `elapsed_sec` follows the injected clock; perpetual leaves
`duration_sec`/`remaining_sec` null; fields are gone after stop.

### P6.3 — optional `duration_sec` on `start`

**Concern:** the owner may bound the session; omitted/null keeps today's
perpetual capture.

| Decision | Choice |
|---|---|
| Payload | `{"command": "start", "interfaces": [...], "pcap_filter": "...", "duration_sec": 300}` |
| Validation | integer, `1 <= duration_sec <= 3600`; `0`, negatives, bools, floats → `CAPTURE_CONFIG_INVALID`. Cap is a named constant; raise it later if a real use case needs it. |
| Timer | one asyncio task per bounded session, stored in client state, cancelled on every teardown path (manual stop, disconnect, process exit, shutdown). It calls the normal stop path with reason `DURATION_ELAPSED`. `dumpcap -a duration:N` was rejected: it ends as an indistinguishable `CAPTURE_ENDED`. |
| Sleep | injectable (`manager._sleep`, default `asyncio.sleep`) so the expiry test awaits an event instead of the wall clock (AGENTS #1). |
| Events | `CAPTURE_STOPPED` `data.reason` ∈ `OWNER_STOP`, `OWNER_DISCONNECT`, `DURATION_ELAPSED`; `CAPTURE_ENDED` `data.reason` = `PROCESS_EXITED`. Owner and subscribers both receive it. |
| Descriptor | `duration_sec` and `remaining_sec` (int, recomputed on every send; floors at 0). |
| Not changeable live | `configure` is radio config; changing a running deadline is a separate concern. |
| Owner disconnect | unchanged in this PR: the capture still dies with the socket even with time left. (P6.4 changes that.) |
| Harness | owner `--duration N` sends `duration_sec` and waits for core's `CAPTURE_STOPPED` instead of stopping locally; subscriber `--duration` stays a local read budget. |

Tests: omitted → no timer task; bounded → timer present, `remaining_sec`
decreases with the injected clock; expiry terminates the process and tells
owner + subscriber `DURATION_ELAPSED`; manual stop and disconnect cancel the
timer (no stray stop after teardown); invalid values rejected before any
process starts; model tests for the validator.

### P6.4 — detached bounded captures

**Concern:** a bounded capture belongs to a `did`, not a socket. It survives
the owner's socket, dies when nobody listens, and can be stopped by its owner
from any connection.

| Change | Where |
|---|---|
| Owner send failure no longer ends the capture; it detaches the owner (bounded) or ends the capture (perpetual, as today) | `_broadcast_chunk` |
| `disconnect()` on a bounded running owner marks the owner detached instead of stopping; arms the orphan timer if no subscribers remain | `disconnect` → `_detach_owner` |
| Session state outlives the socket: the owner's client record is kept as a detached record until the session ends, so interface ownership still blocks a competing `start`; the record is dropped on session end | `stop_streaming` / stream teardown |
| Orphan timer: grace `ORPHAN_GRACE_SEC = 15`; last subscriber leaving arms it, any `subscribe` cancels it; on expiry stop with reason `NO_LISTENERS` | new `_orphan_watch` |
| `stop` accepts optional `session_id`; allowed for the owning socket or any socket whose `did` equals the session owner's; others get `SESSION_NOT_OWNED` | endpoint + `stop_session` |
| Descriptor gains `owner_attached` (bool) and `subscriber_count` | `_session_descriptor` |
| No events are sent to a detached owner socket | `send_event` call sites |
| Docs: handover §2 (replace "capture lives with its socket" with the rule table), §5 item 9, §8 last bullet; Lesson 11 new section; auth plan Appendix A.1 already states owner = `did` with a lifecycle independent of listener connections — cite it | `docs/` |

Tests: perpetual + owner disconnect + subscriber present → stops (existing);
bounded + owner disconnect + subscriber → keeps streaming, descriptor says
`owner_attached: false`; bounded + owner disconnect + no subscriber → stops
after grace with `NO_LISTENERS`, record dropped, interface released; subscribe
inside the grace cancels the orphan timer; last subscriber leaving a detached
session arms it; same-`did` stop by `session_id` works, other `did` refused;
deadline still fires on a detached session and cleans up; owner send failure on
a bounded capture detaches rather than ends.

## 3. Decisions taken (change here, not in the PRs)

| Item | Value | Why |
|---|---|---|
| `duration_sec` cap | 3600 | Bounds the radio hold for revoked-token / crashed-saver cases while the detach pattern is new |
| Orphan grace | 15 s | Covers fork-then-subscribe and a quick reconnect; short enough not to leave a radio hopping into nowhere |
| Integer seconds on the wire | yes | Clients compare and display; sub-second precision invites false precision |
| Who may stop a detached session | same `did` | Matches Appendix A.1 (rights per operation, owner = `did`) |
| Perpetual + subscribers + owner gone | stop | Unchanged; nobody could retune or stop it otherwise |

## 4. Out of scope (do not smuggle in)

- Changing `duration_sec` on a running capture (would be live-applicable, but a
  separate concern).
- Detached **perpetual** captures, or subscriber-set timeouts.
- REST `/wifi/capture/sessions` from the P0 sketch.
- Reporting the current channel for an interface that was started without a
  `configure` (descriptor shows `{}` for it today). Real gap, separate PR.
- Revocation tearing down live or detached sessions (Appendix A decision 3).
- Command/data plane split, chunk sizing (P6.1 follow-up).

## 5. Status

| PR | Branch | State |
|---|---|---|
| P6.2 | `feature/capture-descriptor-clock-p62` | in progress |
| P6.3 | `feature/capture-duration-p63` | planned |
| P6.4 | `feature/capture-detach-p64` | planned |
