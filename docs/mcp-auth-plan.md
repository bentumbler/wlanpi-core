# MCP Authentication & Transport Plan (wlanpi-core / wlanpi-mcp)

**Status:** Draft for discussion — candidate companion to [#139](https://github.com/WLAN-Pi/wlanpi-core/issues/139)
**Scope:** How a user (student), an MCP client harness, wlanpi-mcp, and wlanpi-core authenticate to each other — for the Prague release and beyond.
**Deployment model assumed:** one WLAN Pi per student. The student *owns* their device. Adversaries are other people on the shared classroom LAN, not co-users of the same box. Other on-box or companion apps may mint their own tokens (per-`device_id` tokens are already supported by core).

---

## 1. Current implementation analysis and fit for MCP

### 1.1 What exists today

| Layer | Today | Where |
|---|---|---|
| Auth dispatch | By **source IP**: loopback → HMAC required, anything else → Bearer JWT. Not by presented credential. | `wlanpi_core/core/auth.py` (`verify_auth_wrapper`) |
| MCP workaround | nginx rewrites `X-Wlanpi-Client: mcp` → `X-Real-IP: 192.0.2.1` so localhost MCP traffic takes the JWT branch. Merged as a bridge; #139 tracks its removal. | `install/etc/wlanpi-core/nginx/wlanpi_core.conf` |
| Tokens | HS256 (symmetric key in SQLite), claims `sub/iss/did/exp/iat/kid/jti`. **No `aud`**. Issued via HMAC bootstrap (`getjwt <device-id>`), 7-day default TTL, revocable, DB-backed. | `wlanpi_core/core/token.py` |
| Transport | Core API `:31415` and MCP `:8766` are **cleartext HTTP**. TLS (self-signed, 10-year cert) exists only for WebUI/Cockpit/Grafana. | nginx configs, `debian/postinst` |
| MCP server | Legacy HTTP+SSE on `:8766`, **forwards the user's core JWT unchanged** (passthrough), binds session to `sha256(token)`. Runs as `User=wlanpi`. | wlanpi-mcp repo |

### 1.2 Defects found during this review (all verified in code / on-device)

These matter because several prior design assumptions rest on them:

1. **The HMAC shared secret is readable by MCP today.** `shared_secret.bin` is created `root:wlanpi` mode `0640` (`wlanpi_core/core/security.py`), and `wlanpi-mcp.service` runs as `User=wlanpi Group=wlanpi`. The stated justification for the #135 nginx sentinel — "MCP cannot read the HMAC secret" — is factually wrong on current images. Everything running as user `wlanpi` is in the HMAC trust class, whether we like it or not. Any "dedicated MCP service credential" adds no isolation until these permissions are tightened.
2. **Revocation does not reliably take effect.** `TokenManager.verify_token` returns success from the in-process token cache **without checking the revoked flag**, and `revoke_token` never evicts the cache entry. A revoked token keeps working until the cache happens to clear (hourly purge, only when expired rows were deleted) or the service restarts.
3. **JWT expiry is not enforced.** `time_validation_enabled = False`: the `exp` claim is never validated and `is_expired` is hard-coded `False`. Expiry only bites when the hourly purge task deletes the DB row (~1h granularity). Any "short TTL" recommendation is fiction until this is enabled.
4. **OTG stub is an auth-bypass landmine.** If `is_otg_request()` ever returns `True`, `verify_auth_wrapper` falls through and returns with **no authentication performed**. Dead code today; must not stay this shape.

### 1.3 Fit against the MCP specification (2026-07-28)

The current live MCP spec revision is stateless at the protocol layer (SEP-2567): no `initialize` handshake, no `Mcp-Session-Id`, every JSON-RPC message is an independent `POST /mcp` carrying its own `Authorization` header; `Origin` validation is mandatory; **token passthrough is forbidden** for a spec-conformant resource server.

| Spec expectation | wlanpi-mcp today | Gap severity |
|---|---|---|
| Streamable HTTP `POST /mcp`, stateless | HTTP+SSE `:8766/sse` + session | Transport migration needed (client compat driver, not a security hole) |
| Bearer validated by MCP on every request, audience-bound | Bearer checked at SSE open, forwarded to core, no `aud` | Architectural — see §3 |
| No token passthrough | Full passthrough | Spec deviation — acceptable short-term on a single-box appliance (see §2.1), wrong long-term |
| Origin validation / DNS-rebinding defence | None; binds `0.0.0.0:8766` | Needed when we expose HTTP transport |
| TLS | None on either hop | **The actual live vulnerability** — tokens sniffable on the classroom LAN |

**Important nuance:** the spec's passthrough ban is written for multi-party cloud topologies (confused-deputy, audience mixing). On a single-operator appliance where core is both the token issuer and the only upstream, passthrough's *practical* marginal risk is near zero — the real Prague risks are cleartext transport, non-working revocation, and unenforced expiry. That is what drives the Prague/beyond split below.

### 1.4 Multiple token-holding apps — and the WLAN Pi app today

Core's model already supports "other apps mint their own tokens": each app calls `getjwt <its-device-id>` (or the pairing flow) and gets an independent, independently-revocable token with its own `did` claim. Nothing new is required for Prague except (a) making revocation/expiry actually work (§1.2), and (b) deciding cross-app rights on shared resources like streams (Appendix A).

**The WLAN Pi app is the only deployed third-party API consumer today.** Its bootstrap is: SSH to the device → run `sudo getjwt <app-device-id>` → use the returned 7-day JWT as a Bearer against `:31415`. Two consequences for this plan:

- It is the **compatibility baseline**: any auth change must keep (i) `getjwt`'s invocation and JSON output stable, and (ii) plain Bearer access to the core API working for tokens without new claims. §5 analyses this.
- Its SSH-based pairing is functional but clunky (requires SSH credentials to mint an API token — a stronger credential bootstrapping a weaker one). Marked as an **evolution item (B6)**: replace SSH+`getjwt` with a first-class pairing flow (one-time code shown on the front panel/WebUI, or OAuth device-code), with `getjwt` retained for headless/scripted use.

---

## 2. MCP for Prague — good security with minimal new scope

### 2.1 Security stance

Keep JWT passthrough for Prague, **documented as an accepted, temporary deviation** from the MCP spec, and spend the budget on the controls that stop real attacks:

- **Threats addressed:** LAN sniffing/MITM of tokens (other students), token theft from disk, tokens that outlive the class, inability to kill a compromised token, blast-radius of MCP tooling.
- **Threats consciously deferred:** confused-deputy via passthrough (single-box, single-owner — negligible), OAuth-grade client onboarding, per-scope authorization.

### 2.2 The "session" model (user-facing)

The user's request — session-based interaction, with next-day continuity under a renewed token — maps cleanly onto the stateless spec **without** re-introducing protocol sessions:

- **Identity = the JWT** (short-lived: default TTL ~24h for interactive use). "Log in for today's lab" = obtain/renew the token once (initial auth is acceptable per requirements).
- **Continuity = ownership bound to `did`, not to the token string.** Captures, jobs, and handles are owned by the `did` claim. A renewed token with the same `did` picks up yesterday's artifacts exactly. Nothing is lost at token rollover.
- **No `Mcp-Session-Id`, no server-side login session.** The "session" the student experiences is (valid token for today) + (their persistent, `did`-owned state on the device).

This gives the desired UX and is forward-compatible with the stateless transport in §3.

### 2.3 Prague work items (summary — details in §4.1)

1. **#139 as specified:** dispatch on presented credentials (Bearer present → JWT validation regardless of source IP; HMAC only when a signature header is present), remove the nginx sentinel map, MCP drops `X-Wlanpi-Client`. Kill the OTG fall-through while in the file.
2. **Make expiry and revocation real:** enable time validation; evict revoked tokens from the cache; add a `ttl`/`expires_delta` option to token issuance; default interactive tokens to ~24h.
3. **TLS on both hops via nginx** with the existing self-signed cert: HTTPS vhost for `:31415` and for MCP (prefer proxying MCP under `443` at `/mcp`, or a TLS `:8766`). UFW updated accordingly. Distribute/pin the device cert to the class (or accept TOFU on `wlanpi.local`) — stated honestly: self-signed TLS defeats passive sniffing; an *active* MITM requires cert pinning or trust distribution, which a classroom can do once.
4. **Token hygiene:** the harness reads `WLANPI_MCP_TOKEN` from its environment; no literal tokens in any client config; committed examples secret-free. Be precise about **where** the token lives and what "env" buys us:
   - **Location: the student's client machine** (where the MCP client/harness runs) — not the Pi. The Pi never needs a stored user token: it holds the HMAC secret and *mints* tokens. (Exception: stdio-mode MCP running on the Pi itself reads an env file such as `~/.config/wlanpi/mcp.env`, 0600 — but any process running as that user on the Pi can already run `getjwt`, so this stores nothing that user couldn't obtain anyway.)
   - **Env is a mitigation, not a vault.** It is strictly better than a token pasted into `mcp.json` (which is typically world-readable, synced to cloud backups, and prone to being committed), but a token exported in a shell profile is still plaintext at rest, and any process running as the same user can read it (including via `/proc/<pid>/environ`). The gold path on the client is **OS keychain → injected into the client's env at launch**; a plain env file chmod 600 is the acceptable floor.
   - **Why the floor is acceptable for Prague:** the blast radius of a leaked token is one student's own Pi, for ≤24h (P2), revocable (P2), read-mostly (P5 allowlist). We are not protecting a long-lived admin credential.
5. **MCP tool allowlist for class profiles:** default classroom config exposes read/scan/capture tools; service restart / reboot / network reconfig behind an "instructor" config flag.
6. **Capture over WS with auth (#141) + `did`-owned handles**, so MCP capture tooling ships at Prague. Rights model in Appendix A.

### 2.4 Harness (MCP client) — free / cost-effective options

TBD per requirements; candidates to evaluate, cheapest first:

| Option | Cost | Notes |
|---|---|---|
| **MCP Inspector** (official) | Free | Great for teaching the protocol itself; not an LLM harness. |
| **Claude Desktop / Claude Code (free tier) + stdio or remote MCP** | Free tier | Simplest polished UX; verify current free-tier remote-connector limits before committing. |
| **Open-source clients** (Cline, LibreChat, other OSS MCP hosts) | Free software; pay per LLM API token | Bring-your-own model key; a single classroom API key with per-student budgets is the cost-effective pattern. |
| **Tiny custom harness** on the MCP Python/TS SDK | Free + API tokens | Most control (can bake in the Pi's cert + env token handling); more to maintain. |

Whatever is chosen, the Prague contract it must meet is small: send `Authorization: Bearer $WLANPI_MCP_TOKEN` from env, trust the distributed device cert, speak SSE now / Streamable HTTP later.

---

## 3. MCP beyond Prague — the full architecture

Target: wlanpi-mcp as a spec-conformant **OAuth 2.1 resource server** on MCP Streamable HTTP.

1. **Transport:** stateless `POST /mcp` (Python SDK `stateless_http=True`), `Origin` allowlist, behind nginx TLS on 443. Legacy SSE listener retired (or kept briefly as a compat shim returning 405 on GET per spec).
2. **Audience-bound tokens:** core issues `aud=mcp` tokens for MCP clients (and `aud=core` for direct API clients). MCP rejects non-MCP-audience tokens.
3. **MCP validates tokens itself — via core introspection, not JWKS.** Because tokens are HS256 + DB-backed revocation, MCP cannot self-validate offline and a JWKS is impossible for symmetric keys. Core adds an HMAC-protected `POST /api/v1/auth/introspect`; MCP calls it per request with a short-TTL cache. (Asymmetric signing + JWKS is a later, optional migration — only worth it if off-box validators appear.)
4. **No passthrough + service identity + identity assertion.** MCP calls core with its own service credential and asserts the validated user identity (`did`) inside the HMAC-signed request body so core keeps per-user attribution, audit, rate limits, and handle-ownership checks. *Without the assertion piece, dropping passthrough silently destroys per-user attribution — this is the step most designs miss.*
5. **Tighten the secret trust boundary** so the service identity means something: `shared_secret.bin` → root-only (0600); MCP gets its own provisioned credential; anything still running as `wlanpi` no longer implicitly holds core's master HMAC secret.
6. **Pairing UX:** OAuth 2.1 device-code or WebUI consent replaces copy-from-terminal `getjwt`; client stores tokens in its own secret store. RFC 9728 protected-resource metadata + 401 `WWW-Authenticate` for auto-discovery.
7. **Scopes/roles:** tokens carry scopes (`read`, `capture`, `admin`) so "other apps with their own tokens" can be least-privileged, and the classroom/instructor split becomes a token property instead of an MCP config flag.

---

## 4. Implementation plan

### 4.1 Prague elements

| # | Item | Repo | Size | Notes |
|---|---|---|---|---|
| P1 | Credential-based auth dispatch; remove nginx sentinel; remove OTG fall-through | wlanpi-core | S | This **is** #139; tests already enumerated on the issue |
| P2 | Revocation cache eviction fix; enable `exp` validation; `ttl` param on token issuance; 24h default for interactive tokens | wlanpi-core | S | Makes P4/P5 meaningful; small diffs in `token.py` |
| P3 | nginx TLS vhosts for core API and MCP (existing cert); UFW updates; cert-distribution note for classrooms | wlanpi-core (+pi-gen) | S–M | Highest security value per line of config |
| P4 | `getjwt --export` / `--write-env` (0600) + stderr warning; docs stop showing paste-into-config | wlanpi-core | S | |
| P5 | MCP: drop `X-Wlanpi-Client`; HTTPS endpoint docs; classroom tool-allowlist profile; token from env only | wlanpi-mcp | S | Depends on P1, P3 |
| P6 | Capture WS auth (#141) + `did`-owned stream handles + subscribe rights (Appendix A policy) | wlanpi-core | M | Required for MCP capture at Prague |
| P7 | MCP capture tools using explicit handles (start/status/frames/stop) | wlanpi-mcp | M | Depends on P6 |
| P8 | Harness selection + one-page student setup guide (token env, cert trust) | docs | S | TBD harness decision gates the guide only |

Dependency chain: P1 → P5; P2 independent; P3 → P5/P8; P6 → P7. P1–P4 are individually small and can land as separate PRs immediately.

### 4.2 Beyond-Prague elements

| # | Item | Repo | Notes |
|---|---|---|---|
| B1 | Streamable HTTP `POST /mcp` stateless transport + Origin allowlist; retire SSE | wlanpi-mcp | Client compat driver; do when chosen harness supports it |
| B2 | `aud` claim issuance + audience enforcement | wlanpi-core, wlanpi-mcp | Prereq for B3 |
| B3 | `POST /auth/introspect` (HMAC-protected) + MCP per-request validation w/ short cache | wlanpi-core, wlanpi-mcp | Ends passthrough on the validation side |
| B4 | MCP service credential + signed `did` assertion to core; core authorizes on asserted identity | wlanpi-core, wlanpi-mcp | Ends passthrough on the upstream side; preserves attribution |
| B5 | Secret permissions tightening (0600 root-only) + provisioned per-service credentials | wlanpi-core | Do together with B4 |
| B6 | Pairing flow to replace SSH+`getjwt` bootstrap: one-time code on front panel/WebUI, or OAuth 2.1 device-code; RFC 9728 metadata | wlanpi-core, wlanpi-mcp, WLAN Pi app | Replaces SSH-run `getjwt` for humans and for the WLAN Pi app; `getjwt` kept for headless/scripted use |
| B7 | Scoped tokens (read/capture/admin) | wlanpi-core | Folds classroom profile into token policy |
| B8 | (Optional) asymmetric signing + JWKS | wlanpi-core | Only if off-box token validation becomes a need |

---

## 5. Could the full architecture be the direct Prague route?

Short answer: **it would not be a breaking change if sequenced with the compatibility rules below — the WLAN Pi app and the internal `getjwt` flow keep working throughout — but it roughly doubles the auth engineering for Prague while the extra items remove no classroom risk.** The deviation between the two tracks is scope and sequencing, not destination.

### 5.1 Impact of each beyond-Prague item on existing consumers

| Item | Breaking for the WLAN Pi app? | Breaking for internal HMAC clients (fpms, `getjwt`)? | Notes |
|---|---|---|---|
| B1 Streamable HTTP for MCP | No | No | MCP-only; the app talks REST to core directly, never through MCP |
| B2 `aud` claims | **No, if lenient** | No | Rule: core *issues* `aud` going forward but *accepts* tokens without `aud` (legacy) at core endpoints. Only MCP enforces `aud=mcp`. Existing 7-day app tokens age out naturally; the app's next SSH `getjwt` run returns an `aud=core` token transparently — same command, same JSON shape |
| B3 Introspection endpoint | No | No | Purely additive |
| B4 Service identity + `did` assertion | No | No | Internal to the MCP→core hop; the app's direct Bearer path is untouched |
| B5 Secret → 0600 root-only | No | **No, with an audit** | `getjwt` is documented as `sudo getjwt`, so root-only is fine for it and for the app's SSH flow. Must audit anything reading the secret as group `wlanpi` before flipping (candidates: pairing proxies, any service unit running as `wlanpi`) |
| B6 Pairing flow | No | No | Additive; SSH+`getjwt` remains as fallback until the app adopts pairing |
| B7 Scopes | **No, if lenient** | No | Rule: tokens without a scope claim get full legacy rights; scoping becomes opt-in per issuance |

The one genuinely app-facing transition in either track is **TLS on `:31415` — and that is already in the Prague slice (P3), not a beyond-Prague deviation.** If plain HTTP were switched off, the deployed app would break until it speaks HTTPS and trusts the self-signed cert. Rule: dual-stack `:31415` (HTTP + HTTPS) for one release cycle, or keep HTTP bound to loopback only, and coordinate the app's cert-trust update before removing cleartext.

### 5.2 Why the Prague slice still wins

- The classroom threat model (LAN sniffing, immortal tokens, no working revocation, blast radius) is fully addressed by P1–P8. B3/B4 defend against confused-deputy on a single-owner box — a non-risk until multi-party deployments exist.
- B4 (identity assertion) is the subtle piece: get it wrong and per-user attribution silently breaks. It deserves unhurried design, not a release-deadline implementation.
- B1 is gated on harness client support for Streamable HTTP, which is exactly the TBD decision.

**Cheap pull-forward worth taking:** B2's *issuance* side (mint `aud` claims now, enforce nowhere except MCP later) is a few lines in `create_token` and makes the later cutover a no-op. Everything else stays sequenced after Prague.

---

## 6. Relationship to issue #139

Recommendation: **keep #139 exactly as scoped** — it is a crisp, testable enabler (credential dispatch + sentinel removal) and P1 implements it verbatim. Post this document as a **new tracking issue** ("MCP auth & transport architecture — Prague and beyond"), referencing #139 as its first dependency, with §4.1 as the Prague checklist and §4.2 as the follow-on milestone. Widening #139 itself would delay its merge and blur its acceptance criteria.

---

## Appendix A — Streaming WS APIs: multi-listener rights and token interaction

Context: new WebSocket streaming APIs (starting with packet capture) may have **multiple concurrent listeners**, and one app may start a stream that another principal (e.g. MCP under the student's token) subscribes to. Open decision: is that cross-principal subscribe allowed, and under what rights?

### A.1 Model: streams are resources with an owner and a lifecycle

- Every stream/capture has an **owner = the `did` of the token that started it**, an id (`cap_abc`), and a lifecycle independent of any listener connection. Listeners joining or leaving never starts/stops the stream.
- Rights are evaluated **per operation**, not per connection:
  - `start` / `stop` / `reconfigure`: owner `did` only (later: or `admin` scope).
  - `subscribe` (read frames): policy decision, below.
  - `list`: any authenticated principal sees streams it may subscribe to.

### A.2 Subscribe policy options

| Policy | Behaviour | Fit |
|---|---|---|
| **A. Device-open reads** (Prague recommendation) | Any *valid authenticated* principal on this Pi may subscribe to any active stream; only the owner may stop/reconfigure. | Single-student-per-Pi: every token on the box belongs to the same human or their apps. Enables "WebUI starts capture, MCP listens" with zero ACL machinery. |
| B. Owner-only | Subscribe requires same `did` as owner. | Breaks the multi-app use case (WebUI `did` ≠ MCP client `did`); forces token sharing between apps, which is worse. |
| C. Per-stream ACL / grant | Owner grants read to named `did`s or "all". | Right long-term shape (B7 scopes can subsume it); too much machinery for Prague. |

Prague ships **A**, with the policy stated in docs; **C (or scope-based)** arrives with B7 for multi-user or higher-sensitivity deployments. Note the data-sensitivity angle: a classroom pcap contains *other students'* over-the-air traffic regardless of which principal reads it — device-open reads do not meaningfully widen that exposure on a one-owner device.

### A.3 Token presentation at the WS handshake

Browsers cannot set `Authorization` on WebSocket upgrades, so pick one deliberately:

- **Recommended:** first-message auth — connection opens, client's first frame is `{"type":"auth","token":"..."}`, server closes (4401) if not received within a short window. Works from every client type, keeps tokens out of URLs.
- Acceptable: `Sec-WebSocket-Protocol` token smuggling (works in browsers, slightly hacky).
- **Avoid query-string tokens:** the current nginx `json_combined` log format records the request line and body — tokens would land in `nginx_access.log`.

### A.4 Token lifetime vs connection lifetime

- Validate at subscribe time; the connection may then outlive the token's TTL until closed (a capture spanning token renewal must not drop). This is safe because subscribe rights were checked against a then-valid token, and the blast radius is read-only frames.
- **Revocation is the exception:** revoking a token should actively close that principal's listener sockets (core keeps `did` → active-connections map; the P2 cache-eviction fix should emit the event). If this is too much for Prague, document that revocation stops *new* subscriptions immediately and existing sockets persist until the stream ends.
- Ownership survives renewal automatically because it binds to `did` (§2.2) — a renewed token stops/queries yesterday's still-running capture without ceremony.

### A.5 MCP's consumption pattern (stateless-safe)

MCP tool calls are request/response; a spec-conformant stateless MCP server should not hold a WS open on behalf of one protocol session. Pattern:

1. `capture_start` → core creates stream, returns handle (`cap_abc`, owner = student's `did`).
2. MCP subscribes internally (as a listener like any other) and buffers/summarises.
3. `capture_frames(handle, cursor)` → MCP returns frames/summary since cursor; possession of the handle is **not** authorization — MCP re-checks `(handle, did-of-presented-token)` per call.
4. `capture_stop(handle)` → owner-checked at core.

Multiple listeners (WebUI live view + MCP summarizer + a future scandump consumer) attach to the same core stream; core owns fan-out and per-listener backpressure so one slow consumer cannot stall the capture.

### A.6 Decisions needed before P6 lands

1. Subscribe policy A vs C for Prague (recommendation: A).
2. Handshake auth mechanism (recommendation: first-message auth).
3. Revocation → active-socket close: Prague or beyond (recommendation: beyond, documented).
4. Whether `stop` needs an instructor override path before scopes exist (recommendation: no — `sudo` on the box is the override).
