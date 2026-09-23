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

## Status (2026-09-23)

**Review round 1 (Josh, five devices) addressed** as fix commits on each
owning branch merged up the stack (no force-push); per-PR mapping comments
and a retest summary on #302 (tip `b7f0dd6`). New on top: P14 (#301) Core
only touches netdevs it created (tmpfs ledger netns+name+ifindex; default is
a no-op after reboot; deactivate restores its own root entries) and P15
(#302) `GET /network/config/leftovers` + `POST /network/config/reset`.
dhcpcd now stops with SIGALRM (SIGHUP only rebinds in dhcpcd 10). Gates
green on every branch (tip 694 passed); HIL 163/163 on the tip .deb;
manual scenario script `/home/wlanpi/ns-manual-tests.sh` (auto set 43/43).
Deferred: #292, #293 skip-recreate, #294, #237.

**In-use rule (2026-09-23, on #301):** Core never takes a radio another tool
is using (mode Core never sets, a foreign wpa_supplicant/hostapd, or a
program capturing on a sibling netdev via a bound packet socket); the entry
is `in_use`, the rest of the profile runs, and teardown leaves it alone.
Ownership is keyed on the cfg80211 wdev id (ifindex changes across netns
moves) and is handed back on revert. Found and verified with the real
wlanpi-profiler (fakeap; its hostapd mode fails on mt76/ath12k, a profiler
2.1.3 bug). Tip `9ee9ce0`: 708 passed; HIL 163/163; manual 43/43;
profiler 34/34.


All planned PRs are implemented, gated, and hardware-verified on a Trixie
WLAN Pi (ath12k PCIe + 2x MT7921AU USB, iw 6.17, wpa_supplicant 2.12,
dhcpcd 10.1), and open upstream as stacked **draft** PRs against `dev`.
Each branch `bentumbler:ns-safety/pN-*` is cut from `dev` plus #265's
commit plus the series so far, without this plan doc, and passes
`tox -e lint`, `tox -e formatcheck` and `tox` on its own. The hardware
suite (installed .deb driven through the local API) ends at 127/127.

| PR | Branch | Upstream | Version |
|---|---|---|---|
| P0 tests (#265 follow-up) | p0-trustworthy-tests | #280 | none |
| P1 #236 live inventory | p1-live-inventory | #281 | 2.3.8 |
| P2 #202 live default | p2-live-default | #282 | 2.3.9 |
| P3 #269 supplicant pidfiles | p3-supplicant-pidfiles | #283 | 2.3.10 |
| P4 #275 Core namespaces | p4-core-namespaces | #284 | 2.3.11 |
| P5 #273 runtime state | p5-runtime-state | #285 | 2.3.12 |
| P6 #270 change lock | p6-change-lock | #286 | 2.3.13 |
| P7 #271 profile teardown | p7-profile-teardown | #289 | 2.3.14 |
| P8 #277 atomic writes | p8-atomic-writes | #290 | 2.3.15 |
| P9 #279 + #261 DHCP | p9-dhcpcd-monitor | #291 | 2.3.16 |
| P10 #278 wpa quoting | p10-wpa-quoting | #295 | 2.3.17 |
| P10b #236 radio lookup | p10b-radio-lookup | #296 | 2.3.18 |
| P11 #272 secrets | p11-secrets | #297 | 2.3.19 |
| P12 #276 outcomes | p12-activation-outcomes | #298 | 2.3.20 |
| P13 #274 wlan/revert | p13-wlan-revert | #299 | 2.3.21 |
| P14 #202/#288 Core-owned interfaces | p14-core-ownership | #301 | 2.3.22 |
| P15 leftovers + reset | p15-leftovers-reset | #302 | 2.3.23 |

Found on hardware and fixed in the series: dhclient missing on Trixie
(dhcpcd per namespace, P9); dhcpcd state collides across netns (P9); a
late ath12k association never got DHCP (P9); a display name reused across
namespaces grabbed the wrong radio (P5); default teardown took a radio from
a user's namespace (P7); a display name carried by another radio selected
it, and a failed rename deleted it (P10b); wpa_supplicant does not
unescape quoted values and rejects `psk=P"..."` (P10).

Open follow-ups: #237 MAC pin (last 2 xfails; also closes the
hot-plugged-adapter name-reuse gap noted in P10b); `network_service.renew_dhcp`
(legacy D-Bus path) still calls dhclient; `namespaces/apps.py` falls back to
`pkill -f <app>` when an app pidfile has no PID; `default.json` is a
snapshot of the radios at creation (`# shortcut:` in P2).


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
