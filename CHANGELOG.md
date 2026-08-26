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
