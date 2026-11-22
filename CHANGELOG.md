# Changelog

All notable changes to `rakomi_flutter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Stability policy

- **0.x line**: adapter-interface changes are **additive-only**. Breaking adapter changes
  bump the **minor** version (`0.1.x` → `0.2.0`) and ship with a `MIGRATION.md` entry.
- **1.0**: full SemVer applies. No breaking adapter changes within a major. Public API
  changes that would break consumers go into the next major (`1.x` → `2.0`).
- **Pinning while on the 0.x line**: because 0.x minors may change the adapter
  interface, pin an exact version (no caret) if your change-management process
  requires a reviewed, deliberate upgrade for every dependency bump — this is
  the usual expectation in regulated sectors. Caret pinning is appropriate for
  workloads without that constraint.
- **Migration discipline**: every minor bump ships with a one-page migration note in
  `MIGRATION.md`; every major bump ships with a full migration guide.
- **Vulnerability disclosure**: `security@rakomi.com` is the coordinated-disclosure
  inbox. The disclosure process and the timelines we commit to are described in
  `SECURITY.md`.
- **Every entry below states the API version this release targets** (`API version: /v1`) — this SDK
  is versioned independently of the Rakomi API and of every other Rakomi SDK, pinned to the API
  surface it was built and tested against.

## [Unreleased]

API version: /v1

### Changed

- **Breaking: a browser sign-in session refreshes at `/oauth/token`.** The API no longer refreshes a
  session issued to an OAuth client at `/v1/auth/refresh`, so the SDK records which client made the
  session (stored with the refresh token, kept across launches, cleared on sign-out) and refreshes it
  with `grant_type=refresh_token` and that `client_id` (a DPoP proof, when bound, names
  `/oauth/token`). Password, magic link, OTP and MFA sessions keep `/v1/auth/refresh`. A browser
  session stored by an earlier version has no client recorded and is refused at its next refresh: the
  user signs in again once.
- **Breaking: `RakomiAuth.completeSignIn(body, oauthClientId: ...)`** takes a required named
  `oauthClientId`: the `client_id` the tokens were issued to at `/oauth/token`, or `null` for tokens
  from a `/v1/auth/*` endpoint.
- **`signOut()` of a browser sign-in session revokes its refresh token at `/oauth/revoke`** (RFC 7009,
  with its `client_id`), so the server session ends even when no access token is held. A first-party
  session still calls `/v1/auth/logout` with its access token, now as `DPoP` with a proof when the
  session is DPoP-bound.
- **A refresh answered with a `5xx` other than `503` and `521`–`523` is retried once, immediately.**
  The server may have rotated the refresh token before it failed; it hands the rotation back only to an
  identical retry (same device, same DPoP key) within 10 seconds. The SDK now sends that retry at once —
  with a fresh proof from the same key on a DPoP-bound session — when the first answer arrived within
  8 seconds. If the retry is neither a success nor a definitive rejection, the outcome is unknown: the
  SDK ends the session locally (`AuthStateUnauthenticated`, `SdkErrorCode.refreshFailed` with
  `httpStatus` and `errorMessage: 'refresh_outcome_unknown'`) and the user signs in again. Before, the
  failure was transient and the stored token was presented again later; if the server had rotated it,
  that later use was a reuse, which revokes every session of the user. A `503`, `521`–`523`, `429` or
  `408` is unchanged: transient, the session kept.
- **A refresh that gets no response (a transport failure) gets the same one immediate retry.** The
  answer can be lost after the server rotated the token, so a transport failure is no longer transient
  on its own: the SDK retries once at once (fresh proof, same DPoP key); a success continues, a
  definitive rejection signs out, and anything else ends the session with
  `errorMessage: 'refresh_outcome_unknown'` and no `httpStatus`. Before, the session was kept and the
  stored token was presented again later.

## [0.2.0] - 2026-10-06

This release contains breaking changes; see `MIGRATION.md` for the 0.1 → 0.2 upgrade steps.

Found and fixed while building `examples/quickstarts/flutter/`, a minimal app that authenticates
against a live Rakomi API: every call this SDK makes against the API was broken on at least one of
path, header or field name, so no combination of sign-in, sign-up, refresh, sign-out or MFA had ever
completed end to end against a real server.

API version: /v1

### Added

- **Opt-in biometric lock in front of the stored credential.** New `RakomiProvider` /
  `RakomiAuth` parameters `requireBiometricUnlock` (default `false`, no change for existing apps)
  and `biometricPromptReason`. When on, the SDK prompts BEFORE it reads or uses the stored refresh
  credential — on `hydrate()`, on `getToken()` when it has to refresh, and on every refresh —
  unless a prompt succeeded within `freshAuthWindow`. A cancelled, failed or unavailable prompt
  yields no token (`null`) and an `AuthStateError` with `SdkErrorCode.biometricError`; the stored
  credential is kept for a retry. `freshAuthWindow` previously had no effect and is now the length
  of that window. Previously the only biometric path was `unlockWithBiometric`, which the app had
  to call itself; it was not a gate, and `hydrate()` / `getToken()` used the stored credential
  without prompting. Apps that turn the lock on see a prompt on cold start and when a refresh needs
  the stored credential outside the window.

### Fixed

- **A transient failure during refresh no longer signs the user out.** A DPoP-bound session was
  cleared — refresh token, user snapshot and session — on a `5xx` from the refresh endpoint, and a
  `5xx` carrying a `DPoP-Nonce` header was read as a proof rejection. Now only a definitive
  rejection ends the session: a `4xx` whose OAuth `error` is `invalid_grant`, `invalid_client`,
  `invalid_token`, `unauthorized_client` or `access_denied`, a `403` whose `code` is
  `auth/user_blocked` or `auth/pending_parental_consent` (the API's error `code` is now read,
  with or without its `auth/` prefix), or a bare `401`. A `2xx` the SDK cannot read also ends
  it, and the refresh token is not sent again: the server has already consumed it, and presenting
  it again would count as reuse. A `5xx`, `429`,
  `408` or a network failure keeps the session, the stored refresh token
  and the DPoP key, and surfaces as `SdkErrorCode.networkError` with the new `httpStatus` and
  `retryAfter` fields. `Retry-After` (delta-seconds or HTTP-date) is honoured: no refresh is sent
  before it has passed, for at most two minutes. A `403` without one of those codes (for example
  from a proxy) no longer signs out; a `400 invalid_grant` now does. A cold start whose refresh
  fails transiently keeps the stored credential, settles on a typed `AuthStateError`, and the next
  successful `getToken()` completes the restore (`restoreSucceeded`).
- **Offline JWT verification hardcoded the expected `iss` to the frozen platform constant
  regardless of the SDK's own configured `apiBaseUrl`.** Now that a tenant's issuer can be its own
  bound custom-domain host, the default expected `iss` is derived FROM `apiBaseUrl`
  (`deriveDefaultIssuer`, RFC 8414 §3.3 style, trailing-slash normalized, tenant-path-suffix aware)
  instead of hardcoded — mirrors the same generalization `@rakomi/react-native` shipped for
  `expectedIssuer`. A PLATFORM host (`rakomi.com` or any subdomain of it, or a local-dev host)
  ALWAYS expects the frozen constant regardless of which platform host `apiBaseUrl` names — the
  server's own issuer identity is frozen there in every environment, so deriving the expectation
  from the host itself would reject every real token a staging/dev deployment mints; only a
  genuinely different (custom-domain) host expects `apiBaseUrl` itself. `expectedAudience` stays
  the frozen platform constant (confirmed server-side: user-flow token `aud` never varies with the
  resolved per-tenant `iss`). **Zero behaviour change for a platform-hosted tenant, on ANY platform
  host** (proven by a dedicated should-PASS/backward-compat test pair, plus should-FAIL plants for
  a confusable non-platform host such as `evilrakomi.com`). The persisted JWKS cache storage slot
  is now also scoped per-host (in addition to per-tenant), so a tenant's issuer-host change across
  app upgrades never silently reuses a stale cross-host JWKS document as "fresh".
- **The publishable key was never sent on any `apiKeyAuth()`-protected call** (`/v1/auth/login`,
  `/v1/auth/register`, `/v1/auth/refresh`, `/v1/auth/magic-link`, `/v1/auth/email-otp`,
  `/v1/auth/mfa/verify-login`) — every one of those requests was answered `401 auth/missing_api_key`
  before credentials were even checked.
- **`signOut()` posted a `refresh_token` body to `/v1/auth/logout` and no `Authorization` header** —
  that route is `jwtAuth()`-guarded and reads nothing from the body, so server-side session
  revocation silently never happened (the failure was swallowed as best-effort).
- **The passwordless send paths pointed at endpoints that do not exist**: `/v1/auth/magic-link/send`
  and `/v1/auth/email-otp/send` have no `/send` suffix on the real routes
  (`/v1/auth/magic-link`, `/v1/auth/email-otp`).
- **The MFA challenge was read from fields the login response never sends** (`next_action`,
  `challenge_id`) instead of the real discriminated-union shape (`next_step: "mfa_verify"`,
  `mfa_challenge_token`) — an MFA-enforcing tenant's users could never reach the TOTP step.
  `verifyMfaImpl` itself posted to a nonexistent `/v1/auth/mfa/totp/verify` with `challenge_id`/
  `tenant_id`; the real route is `/v1/auth/mfa/verify-login` with `mfa_challenge_token`/`code`.
- **`RakomiMfaFlow` (`verifyMfaImpl`) was never exported from the public `rakomi_flutter` barrel**,
  even though `RakomiAuth.verifyMfa()`'s own stub error told callers to use it — there was no public
  import path to the method it named.
- **`signUp` claimed an authenticated session `/v1/auth/register` never grants.** Registration
  returns `{message, next_step?}` with no tokens (email verification gates the session); `signUp`
  decoded that body as a token envelope and always failed with `signInFailed(token_missing)`, even
  on a successful registration. It now settles on `unauthenticated` and still completes sign-in on
  the rarer case where a tenant's response does carry tokens.
- **A 200 response with an undecodable refresh body could escape as a raw, untyped exception**
  instead of the typed `SdkError` every other failure path already produces. A concurrent caller
  sharing an in-flight refresh (`RakomiAuth`'s single-flight completer) received the raw decode
  exception directly — a contract violation of this SDK's own "errors never throw across the
  public API surface" invariant. Both the request-post path and the outer refresh handler now
  convert any unexpected failure into a typed, audited (`AuthEventType.refreshFailed`) `SdkError`;
  an unreadable `2xx` refresh response ends the session locally (see above).
- **`restoreSucceeded` was emitted after a sign-in.** When a cold-start restore failed
  transiently and the user then signed in, the next successful refresh reported
  `restoreSucceeded` for a session that came from the sign-in. A sign-in now settles the pending
  restore.
- **The social/browser sign-in flow called endpoints that do not exist** — `/v1/auth/oauth/
  <provider>/start` and `/v1/auth/oauth/callback` — so every provider button led to a dead end.
  Rewritten to the standard RFC 8252 browser + RFC 7636 PKCE contract `@rakomi/react-native`'s
  `startSocialSignIn` already uses: an authorization request to a resolved `authorization_endpoint`
  (live OIDC discovery, falling back to the platform's `api.`/`accounts.` host-naming convention),
  and a form-urlencoded RFC 6749 §4.1.3 code exchange at `POST {apiBaseUrl}/oauth/token`. The
  callback handler no longer reads a `one_time_id` off the (attacker-influenced) callback URL —
  that was this SDK's own since-removed bespoke endpoint's invention; the in-flight correlation id
  is now a local variable, never trusted from the wire.

### Changed

- **Breaking: signing keys are read from the expected issuer's own `jwks_uri`.**
  Unless `jwksUrl` is set, `RakomiProvider` resolves the issuer's discovery
  document (OAuth 2.0 Authorization Server Metadata first, then OpenID Connect
  Discovery, both path-aware) and verifies tokens only against the keys it
  names, so a key published by any other issuer is never trusted. RS256, PS256
  and ES256 (P-256) are accepted, and the token header must name the same `alg`
  as its key.

- **Breaking: `RakomiAuth.signUp()` gained a required `consent` parameter.** `/v1/auth/register` has always
  required `consent: boolean`. Existing `signUp` calls no longer compile until they pass it (see
  `MIGRATION.md`); at runtime every prior call was rejected `400`, so no call that used to work
  behaves differently.
- **`RakomiAuth`/`RakomiProvider` gained an optional `clientId` field** — the OAuth 2.1
  public-client id for the browser/PKCE social sign-in flow, distinct from `publishableKey` (which
  authenticates the native `/v1/auth/*` endpoints and carries no authority for `/oauth/authorize` /
  `/oauth/token`). Additive: existing constructor calls compile unchanged. **Fails closed** when
  unset — `signInWithProvider`/`performSocialSignIn` return a typed `SdkError(code: invalidConfig)`
  without opening a browser or making a network call, and `RakomiSignInForm`/`RakomiSignInButton`
  render no provider buttons at all rather than ones that can never complete.

- The tenant's publishable key is sent, as `X-API-Key`. It was accepted by the
  controller and then never put on a request — the header appeared nowhere in the
  package — so every first-party auth call was answered `401 auth/missing_api_key`
  before its body was considered.
- The second-factor step posts `mfa_challenge_token` to `/v1/auth/mfa/verify-login`.
  It used to post `challenge_id` to `/v1/auth/mfa/totp/verify`: measured against a
  running API, that path answers 404 and that field name is rejected
  `400 validation/invalid_request` by the endpoint that does exist.
- The login response is read with the keys the API sends. It signals a second
  factor with `next_step: "mfa_verify"` and names the challenge
  `mfa_challenge_token`; reading `next_action`/`challenge_id` matched nothing on
  the wire, so the MFA branch could never be taken and the response fell through
  to sign-in completion with no tokens in it.
## [0.1.0] - 2026-08-26

First public release.

API version: /v1

### Added

- `RakomiProvider` widget with `InheritedNotifier`-based state management.
- `RakomiAuth.instance` per-provider-tree accessor (not a process-global singleton).
- Async API: `signIn`, `signUp`, `signOut`, `signInWithProvider`, `signInWithMagicLink`,
  `signInWithEmailOtp`, `verifyMfa`, `getUser`, `getToken`, `refreshTokens`,
  `hasValidSession`, `unlockWithBiometric`.
- Streams: `authStateChanges` (sealed `AuthState`) and `events` (fine-grained `AuthEvent`
  enum) — both broadcast, multi-listener, late-subscriber-drop semantics.
- Pre-built widgets: `RakomiAuthGate`, `RakomiSignInForm`, `RakomiSignInButton`,
  `RakomiUserAvatar`. Material + Cupertino styling, WCAG 2.2 AA compliance, branding
  contrast validation.
- Native adapter: pluggable `RakomiNativeAdapter` abstraction with default wiring of
  `flutter_secure_storage` v10, `flutter_web_auth_2` v5, `app_links` v7, `local_auth` v3,
  `connectivity_plus` v7, `package:http` v1.6, `package:crypto` v3.
- RFC 8252 OAuth/PKCE compliance (system browser only, **no `WebView`**).
  PKCE S256 mandatory, `code_verifier` 32 bytes from CSPRNG,
  `state` 32 bytes secure-random + single-use + constant-time compare.
- RFC 9700 §4.4 mix-up defense: `iss` validation against configured issuer.
- Offline JWKS verification (RS256 hardcoded; rejects `none`, `HS256`, `HS384`, `HS512`).
  ETag-aware cache, 24h TTL, 16KB payload cap, `kid`-miss-driven single retry.
- Clock-skew probe (±5 min cap, fail-closed on anomaly).
- AppState-driven token refresh (single in-flight `Completer<Session>` dedup,
  60s lead-time `kDefaultRefreshLeadtime`).
- Connectivity-aware refresh queue with 2s/8s/30s exponential backoff.
- iOS Keychain post-uninstall fresh-install detection (Keychain residue purge).
- MFA TOTP flow with `next_action: 'verify_mfa'` step-up handling.
- Storage namespace `rakomi.v1.<purpose>.<tenantId>` (v1 reserved for future migration).
- W3C Trace Context propagation (opt-in via `Zone.current[#traceparent]`).
- Optional certificate pinning, enforced at TLS handshake time: when
  `RakomiProvider(certificateFingerprints:)` is supplied, every HTTPS request to
  a non-loopback host on iOS and Android is checked against the configured pins.
  Multiple pins are supported; ship a backup pin alongside the current one so a
  CDN certificate rotation does not force an SDK update. Web is not pinned —
  transport security there is the browser's.

### Security

- All cryptographic primitives use platform CSPRNG (`Random.secure()`).
- Constant-time comparison for `state`, `code` and `nonce` validation.
- Refresh token persisted only in `flutter_secure_storage` (Keychain on iOS,
  RSA-OAEP-wrapped AES-GCM via KeyStore on Android, AES-GCM-encrypted `localStorage`
  on Web — see README "Web security considerations").
- Access token in-memory only.
- Token redaction in `SdkError.toString()` (regex-based JWT shape detection).
- No telemetry, no token logging.

### Fixed

- `example/lib/main.dart` no longer passes `RakomiProvider(biometric: true, ...)` —
  that constructor parameter never shipped in a public release (it was accepted but
  wired to nothing, and was removed pre-publish), so the example would not compile
  against the SDK it ships alongside. The example now demonstrates the real API
  instead: `RakomiProvider.of(context).unlockWithBiometric(reason:)`, an on-demand,
  application-triggered re-confirmation — not a mount-time gate.
