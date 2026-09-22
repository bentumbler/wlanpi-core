# Namespace safety fix series

Working plan for the phy/iface identity fixes (#236, #202) and the follow-up
namespace issues (#269 to #279). This file lives on the fork integration
branch only. Drop it (or trim it) before the per-PR branches go upstream.

## Workflow

- All work lands as commits on `bentumbler/wlanpi-core:integration/namespace-safety`,
  based on upstream `dev` plus the #265 test commit.
- One commit (or small group) per planned PR below, so each can be
  cherry-picked onto its own branch from `dev` and sent upstream once proven.
- No upstream PRs until the whole series is tested on hardware.
- Hardware testing needs a Trixie WLAN Pi (dev requires Python >= 3.13).
  Build with `dpkg-buildpackage -us -uc -b` and install the `.deb`.
- Gates on every commit: `tox -e lint && tox -e formatcheck && tox -e py313`.

Baseline on the branch before Phase 0: namespace + P0 matrices gave
`9 failed, 76 passed, 20 skipped`; the 9 failures are the identity rows listed
in #265.

After Phase 0: `78 passed, 20 skipped, 13 xfailed`. The 13 are the 9 original
identity rows plus 4 new #236 rows, each listed in a `KNOWN_BUGS` dict in the
matrix `test_matrix.py`.

## Phases

### Phase 0: make the tests trustworthy (tests only, no changelog bump)

Extends #265. Today several identity rows pass on a fix that does nothing and
fail on a correct cross-netns fix.

- `live_adapter_inventory_mocks` (`tests/conftest.py`):
  - stateful: delete removes the iface, phy move re-homes it, add creates it;
    add on a missing phy fails;
  - raise on any unrecognised command (today it returns empty success, and
    `hardware_success_mocks` returns `"phy0\nphy1"` for everything);
  - model `ip netns list`, bare `iw dev` (with `phy#N` headers and `wiphy N`),
    and `ip netns exec <ns> iw dev [<iface> info]`;
  - drop `addr` from the `iw phy <x> info` stub (real `iw` does not print it);
  - patch every `run_command` user (`network_config`, `adapters.interface`,
    `adapters.discovery`, `adapters.phy`), plus an autouse guard that fails on
    a real `utils.general.run_command` call;
  - record namespace-side `interface.create_interface` calls.
- Assertions: exact `adds` / `deleted` / `phy_moves` lists; "wlan1 exists
  after activation"; no `None` accepted on the stale-phy rows; P0 rows assert
  the CSV's expected body/state (e.g. `current.txt`), not only the HTTP code.
- `xfail(strict=True)` on all 9 identity rows with reasons `#236`, `#202`,
  `#237`, so the branch stays green and each fix must remove its markers.
- `tests/test_p0_api_matrix/test_matrix.py`: fail (not skip) on ImportError
  of `handlers.py`.
- Fix the AGENTS.md rule 7 violation in `ssid_delayed_beyond_monitor_timeout`
  (patching `monitor.time.sleep`).
- New rows: iface already in a netns at activation; `phy10` vs `phy1`;
  `iface_display_name != interface`; rollback after partial prepare.

### Phase 1: stop destructive activation

| PR | Scope | Clears |
|---|---|---|
| P1 #236 | Read-only cross-netns inventory helper in `adapters/discovery.py` (`{iface: (phy, netns)}`; not in `network_config`, which would be a circular import). Use it in the `activate_config`, `deactivate_config` and `revert_to_root(cfg)` gates (all root-only today, so rollback of namespaced configs is a no-op) and in `_prepare_root` / `_prepare_namespace`. Resolve before any delete. Fix `phy not in stdout` substring match. Look up both `interface` and `iface_display_name`. Address phys by index (`iw phy#N`). | 8 xfails |
| P2 #202 | `get_default_config` from the helper; no fake WPA2 without psk. Note the boot-time snapshot limit with a `# shortcut:` comment, or regenerate while unedited. | 3 xfails |

### Phase 2: correct teardown (internal only)

| PR | Scope | Depends on |
|---|---|---|
| P3 #269 | Pidfile per (netns, iface) under `/run/wlanpi-core/`; kill by PID; remove bare `pkill -f`. | P1 |
| P4 #275 | Only touch Core-created namespaces; walk phys (not ifaces) per netns; delete only when empty. | P3 |
| P5 #273 | Key runtime paths by (netns, iface); uniqueness validation across a profile; stop writing `interfaces.d`; `/etc/netns/<ns>/resolv.conf`. | coordinate with #261 |

### Phase 3: consistent state machine

| PR | Scope | Depends on |
|---|---|---|
| P6 #270 | Process-wide lock around activate/deactivate/revert/boot; 409 when busy. | none |
| P7 #271 | Override deactivates the previous profile; failed override or boot falls back to `default`. | P3, P6, #261 |
| P8 #277 | Atomic writes; refuse deleting the active profile; case-insensitive reserved IDs. | none |
| P9 #279 | Monitor generation ownership; stop-event checks before side effects; no gatewayless default route. | #261 DHCP work |
| P10 #278 | Hex SSID and `P"..."` PSK in wpa confs; unit tests. | none |

### Phase 4: API contract release (coordinate with webui, app, mcp)

| PR | Scope |
|---|---|
| P11 #272 | 0600 files (+ postinst chmod); redacted response model (`psk_set: true`); PATCH keeps the stored secret when omitted. |
| P12 #276 | Per-adapter outcomes in the activate response; consistent 400/422 mapping. |
| P13 #274 | `/wlan/revert` behaviour (see open decisions); update `current.txt`. |

### Later

#237 MAC pin: removes the last 2 xfails.

## API impact

Internal only: P1, P3, P4, P5, P8 (writes), P9, P10, and the lock in P6.

Client-visible:

- P11: `GET`/`PATCH /network/config/{id}` stop returning secrets. Breaking
  unless PATCH preserves them, because PATCH replaces whole `roots` /
  `namespaces` lists (`edit_config`).
- P12: activate body gains per-adapter outcomes (additive); validation
  failures move from 500 to 400/422.
- P6: new 409 "busy" on activate/deactivate/revert.
- P13: `/wlan/revert` message and possibly scope; `current.txt` updated.
  wlanpi-mcp calls it (`tools/wlan.py`).
- P8: deleting the active profile gets 409; `Default` / `ROOT` / `status`
  IDs rejected with 400.
- P7: after a failed activate, status shows `default`.
- P2: `GET /config/default` returns live radios.

## Open decisions

1. Who owns #261? P5, P7 and P9 overlap it.
2. P11 redaction: omit and return `psk_set: true` (recommended), or mask?
3. P13: honour `iface`/`namespace`, or document as revert-all (cheaper;
   endpoint is deprecated)?

## Issue map

| Issue | Topic | Related |
|---|---|---|
| #269 | Host-wide `pkill`; targeted kill never matches | #261, #236, #237 |
| #270 | No lock | #261, #238, #251 |
| #271 | Override never tears down previous; stale `current.txt` | #261, #207, #202 |
| #272 | Secrets on disk and in API | #232, #179, #230, #156 |
| #273 | Runtime state keyed by iface only | #261, #237, #156, #201 |
| #274 | `/wlan/revert` ignores inputs | #237, #238 |
| #275 | `revert_to_root(None)` scope | #236, #237 |
| #276 | Success/500 mapping | #202, #261 |
| #277 | Persistence, atomic writes, IDs | #232, #202 |
| #278 | wpa quoting | #261 |
| #279 | Monitor race, gatewayless route | #261, #207, #201 |
