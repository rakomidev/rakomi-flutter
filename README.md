# rakomi_flutter

[![pub.dev](https://img.shields.io/pub/v/rakomi_flutter.svg)](https://pub.dev/packages/rakomi_flutter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The official **Rakomi** SDK for Flutter — RFC 8252-compliant OAuth/PKCE,
platform-native secure storage, biometric unlock, MFA (TOTP), offline-tolerant
JWKS verification. Targets iOS, Android, and Flutter Web.

## Quickstart (<15 lines)

```dart
import 'package:flutter/material.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

void main() => runApp(MaterialApp(home: RakomiProvider(
  publishableKey: 'pk_live_…',
  redirectUri: 'myapp://callback',
  child: RakomiAuthGate(
    signedIn: (ctx, user) => RakomiUserAvatar(),
    signedOut: (ctx) => RakomiSignInForm(
      providers: [SocialProvider.google, SocialProvider.apple],
    ),
  ),
)));
```

## What this SDK gives you

- **EU-based operator**: Rakomi is operated by CRE8EVE Sp. z o.o., incorporated
  in Poland. Primary infrastructure and database hosting are in the EU. Some
  optional, tenant-enabled integrations involve processing outside the EU; the
  full sub-processor list, the processing locations and the transfer safeguards
  relied upon are set out in the Data Processing Agreement, which is the
  authoritative source — this README makes no transfer determination.
- **Multi-tenant by design**: the tenant boundary is enforced at the JWT issuer
  level, with row-level-security-backed storage at the API. A single set of
  credentials serves many tenants; no per-tenant project is required.
- **Open standards**: OAuth 2.0, OIDC, PKCE S256, JWT/JWKS, RS256 — no
  proprietary token format, no cookies, no session affinity.
- **Documented security posture**: coordinated vulnerability disclosure via
  `security@rakomi.com` (see `SECURITY.md`), and vulnerability records kept
  under 10-year retention.

## OIDC vs OAuth 2.0 in Rakomi

The SDK consumes **OAuth 2.0** access tokens (RS256-signed JWTs). `id_token`
handling for full OIDC compliance is planned and does not ship today.

## Tenant scope vs OAuth scopes

Tenant binding is encoded in the **JWT claim** `tenant_id`, NOT in OAuth
`scope` strings. Each tenant has its own publishable key (which derives the
storage namespace and the issuer URL).

## Why not `flutter_appauth` underneath?

`flutter_appauth` is iOS+Android only and has no Web target. We use
`flutter_web_auth_2` directly because it provides a single API across
iOS / Android / Web, and the system browser semantics are identical
across the three platforms (RFC 8252 / popup `postMessage`).

## OAuth 2.1 readiness

- PKCE-mandatory (S256). No plain fallback.
- No implicit flow. No password-grant for new clients.
- Aligned with `draft-ietf-oauth-v2-1`.

## Privacy considerations (RFC 6973)

- The SDK does NOT log tokens.
- The SDK does NOT collect device telemetry by default.
- The SDK does NOT issue cookies.

## Token lifetimes

- Access token: ~15 min (server-side configurable, see API canonical docs).
- Refresh token: ~7 d (server-side configurable).
- Single in-flight refresh dedup via Dart `Completer` — never two concurrent
  refreshes for the same provider tree.

## No cookies / no CSRF in SDK

Bearer tokens only. The SDK adds `Authorization: Bearer <access>` headers and
nothing else. No cookies, no CSRF defense needed at the SDK layer.

## Custom URL scheme caveats

On Android, custom URL schemes are first-come-first-serve at the OS level —
a malicious sibling app can register the same scheme and intercept the OAuth
callback. The recommended remediation is **Universal Links** (Android App
Links). This SDK currently supports custom schemes only; Universal Links
support is planned.

## Provisioning & code-signing

- iOS: register your scheme in `Info.plist > CFBundleURLTypes`. For Universal
  Links, see [Apple Associated Domains](https://developer.apple.com/documentation/Xcode/supporting-associated-domains).
- Android: register your scheme in `AndroidManifest.xml > intent-filter`. For
  Android App Links, see [Android App Links](https://developer.android.com/training/app-links).

### iOS `Info.plist` snippet

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleTypeRole</key>
    <string>Editor</string>
    <key>CFBundleURLName</key>
    <string>your.app.bundle.id</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <!-- Replace `myapp` with the scheme you passed to RakomiProvider(redirectUri:). -->
      <string>myapp</string>
    </array>
  </dict>
</array>
```

### Android `AndroidManifest.xml` snippet

```xml
<activity android:name=".MainActivity" android:launchMode="singleTask">
  <intent-filter android:autoVerify="false">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <!-- Replace `myapp` with the scheme you passed to RakomiProvider(redirectUri:). -->
    <data android:scheme="myapp" android:host="callback" />
  </intent-filter>
</activity>
```

### Publishable-key acquisition

Sign in to your tenant dashboard at https://dashboard.rakomi.com → **API keys**
panel → **Create publishable key**. Copy the `pk_live_…` (or `pk_test_…`)
prefix into `RakomiProvider(publishableKey:)`.

## Threat model

The SDK defends against the OWASP MASVS v2 V2 (storage) / V3 (cryptography) /
V4 (authentication) classes by construction. Residual risks NOT mitigated by
the SDK:

- **Rooted/jailbroken device**: Keychain/Keystore extraction is possible.
  Mitigation is consumer-app responsibility (e.g. `freerasp` / `RootBeer`).
- **Device PIN bypass**: on a stolen device with no passcode set, stored
  credentials remain readable once the device has been unlocked at least once.
  The SDK surfaces `BiometricUnavailable(reason: 'no_device_passcode')` so the
  application can react. Credentials are stored device-only and are therefore
  NOT carried into an iCloud or iTunes backup.
- **Screen-overlay attack (Android clickjacking)**: consumer apps SHOULD set
  `WindowManager.LayoutParams.FLAG_SECURE` on the auth Activity.
- **Keylogger**: outside the SDK's threat model — biometric paths bypass
  password input on supported platforms.
- **App-switcher screenshot leak**: consumer-app responsibility — set
  `FLAG_SECURE` (Android) / `UIWindow.privacyOverlay` (iOS) when
  authenticated state is visible.
- **MITM on managed networks**: optional `RakomiProvider(certificateFingerprints:)`
  pins server certificates on mobile (Web ignored — browser TLS).

## Transport security

`RakomiProvider(apiBaseUrl:)` requires `https://`. Exactly one exception exists,
for local development, and it is enforced in the constructor: an `http://` URL
is accepted only when the host is exactly `localhost`, or is written as four
dot-separated numbers beginning `127.` or `10.`. Any other `http://` URL is
rejected with an `ArgumentError` before the provider is built.

⚠ `10.0.0.0/8` is a **private LAN range, not loopback** — traffic to it leaves
the device. Treat that exception as a development convenience only, and never
point a production build at a plaintext `http://` address.

Optional certificate pinning (`RakomiProvider(certificateFingerprints:)`)
applies to `https://` requests to non-loopback hosts on iOS and Android; on Web
it is ignored, because transport security is the browser's.

## Web security considerations

`flutter_secure_storage` v10 on Flutter Web stores the refresh token in
`localStorage` with AES-GCM encryption (key derived from a per-origin random
secret in IndexedDB). This is **NOT OS-level secure storage** — a successful
XSS in your app reads the token. Mitigations:

- Content Security Policy with `script-src 'self'` (no inline JS).
- `Trusted Types` if your bundler emits sinks.
- Treat Web differently: shorter token lifetimes, more aggressive refresh.

## Compliance posture

- **CRA** (Reg. 2024/2847): coordinated vulnerability disclosure via
  `security@rakomi.com`. The disclosure process, the timelines we commit to and
  the record-keeping are described in `SECURITY.md`.
- **GDPR Art. 17** (right to erasure): `signOut()` clears local + this
  tenant's JWKS cache; fresh-install detection PURGES Keychain residue.
- **GDPR Art. 25** (privacy by design): non-blocking mount, no telemetry, no
  token logging, secure-storage namespacing.
- **GDPR Art. 32** (technical measures): Keychain/EncryptedSharedPreferences
  encryption-at-rest; RS256; CSPRNG; HTTPS required for the API base URL, with
  a development-only `http://` exception (see "Transport security" below);
  redacted error strings.
- **NIS2** (Reg. 2022/2555): coordinated vulnerability disclosure — see
  `SECURITY.md`.
- **PSD2 / PSD3**: the SDK can carry a TOTP factor (possession) and a biometric
  factor (inherence), when the API operator configures factor binding. Whether a
  given deployment satisfies strong customer authentication is a determination
  for the operator and their supervisor — the SDK does not make it and certifies
  nothing.
- **NIST SP 800-63B**: MAY meet AAL2 when the API operator configures factor
  binding. The SDK does not certify AAL2.
- **EUDI Wallet** (Reg. 2024/1183): a `SocialProvider.eudiWallet` enum value is
  reserved as a forward-compatibility hook. No wallet integration ships today.

## Audit logging

The SDK emits 32 distinct `AuthEvent` types via the broadcast Stream
`RakomiAuth.instance.events`. Consumer apps are responsible for forwarding to
their audit log. The SDK does NOT auto-forward to any sink (CRA + GDPR Art. 30).

Audit-significant events (recommended forwarding for SOC 2 / ISO 27001):

- `signedIn` / `signedOut` — record `userId + tenantId + ts`.
- `tokenReceived` / `refreshSucceeded` — record `userId + sessionId + ts`.
- `signInFailed` — record `email_hash + ip_hash + reason + ts`.
- `clockSkewDetected` / `biometricFailed` / `deepLinkReceived` —
  security-relevant; forward to SIEM.

## EUDI Wallet roadmap

The EU Digital Identity Wallet mandate begins **end-of-2026** (Reg. 2024/1183
implementing acts). When the bridge endpoint lands at the API, the
`SocialProvider.eudiWallet` enum value will be wired without a major version
bump. Consumer-side `switch` statements over `SocialProvider` MUST use a
`default:` clause to allow this additive enum extension.

## Stability policy

See `CHANGELOG.md` § "Stability policy". TL;DR: 0.x adapter changes
additive-only; breaking changes go to 0.(x+1).0 with `MIGRATION.md` entry.

## Publisher webhooks

`verifyPublisherWebhook` verifies Rakomi publisher-app webhook deliveries (Standard Webhooks
HMAC-SHA256, replay defence, key-rotation tolerance). See the canonical
[publisher-webhook receiver contract](https://docs.rakomi.dev/guides/publisher-webhooks/).

## License

MIT — see `LICENSE`.
