import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:http/http.dart' as http;

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../internal/issuer_jwks.dart' show discoveryOriginFor;
import '../internal/jwks_cache.dart';
import '../internal/jwt_verify.dart'
    show deriveDefaultIssuer, kRakomiPlatformAudienceDefault;
import '../internal/storage_keys.dart';
import '../native/adapter.dart';
import '../native/default_adapter.dart';
import '../oauth/deep_link_handler.dart';
import '../oauth/pkce.dart' show constantTimeStringEquals, randomOneTimeId;

/// `RakomiProvider` — root SDK widget. Mounts the auth controller, the
/// native adapter, the deep-link handler, and the AppLifecycle observer.
///
/// **Non-blocking mount**: the first frame emits
/// `AuthState.loading()` synchronously; secure-storage hydration runs via
/// `Future.microtask` in async `initState` body. NEVER `await` blocking
/// work in the synchronous prologue (cold-start budget — `flutter_secure_storage`
/// first-read costs 30–250ms).
///
/// **Constructor assertions**:
/// - `apiBaseUrl` MUST start with `https://` OR match the dev-loopback regex
///   (`http://(localhost|127\.|10\.)`).
/// - `redirectUri` scheme is platform-conditional (see `oauth/social_auth.dart`).
class RakomiProvider extends StatefulWidget {
  RakomiProvider({
    super.key,
    required this.publishableKey,
    required this.redirectUri,
    required this.child,
    this.apiBaseUrl,
    this.issuer,
    this.audience,
    this.tenantId,
    this.clientId,
    this.adapter,
    this.jwksUrl,
    this.refreshLeadtime = kDefaultRefreshLeadtime,
    this.freshAuthWindow = const Duration(seconds: 30),
    this.requireBiometricUnlock = false,
    this.biometricPromptReason = kDefaultBiometricPromptReason,
    this.certificateFingerprints,
  }) {
    final base = apiBaseUrl ?? 'https://api.rakomi.com';
    if (!_validBaseUrl(base)) {
      throw ArgumentError.value(
        base,
        'apiBaseUrl',
        'MUST be https:// or dev-loopback (http://localhost|127.|10.)',
      );
    }
    // The key set is the root of signature trust, so it gets the SAME
    // predicate as the API base URL. Left unvalidated, an `http://` value here
    // fetched the key set in plaintext and outside certificate pinning.
    final jwks = jwksUrl;
    if (jwks != null && !_validBaseUrl(jwks.toString())) {
      throw ArgumentError.value(
        jwks.toString(),
        'jwksUrl',
        'MUST be https:// or dev-loopback (http://localhost|127.|10.)',
      );
    }
  }

  final String publishableKey;
  final String redirectUri;
  final String? apiBaseUrl;
  final String? issuer;
  final String? audience;
  final String? tenantId;

  /// OAuth 2.1 public-client `client_id` for the browser/PKCE hosted-login
  /// flow (social sign-in / `RakomiSignInForm`'s provider buttons). Distinct
  /// from [publishableKey] — see `RakomiAuth.clientId`'s doc comment. Leave
  /// unset to disable the browser flow entirely: `RakomiSignInForm`/
  /// `RakomiSignInButton` then render no provider buttons at all, rather
  /// than a button that opens a browser session which can never complete.
  final String? clientId;
  final RakomiNativeAdapter? adapter;

  /// Override where signing keys are read from. Default: the `jwks_uri`
  /// named in the expected issuer's discovery document, so only that
  /// issuer's keys are trusted. Rare in production (a JWKS proxy or mirror).
  final Uri? jwksUrl;
  final Duration refreshLeadtime;

  /// How long a successful biometric prompt keeps the biometric lock open.
  /// Read only when [requireBiometricUnlock] is `true`; with the lock off it
  /// has no effect.
  ///
  /// Inside the window, hydration and token refreshes use the stored
  /// credential without prompting again. Once it has elapsed, the next
  /// operation that needs the stored credential prompts first.
  /// `Duration.zero` prompts on every such operation. A successful
  /// `RakomiAuth.unlockWithBiometric` also opens the window.
  final Duration freshAuthWindow;

  /// Opt-in biometric lock. Defaults to `false`, which keeps the stored
  /// credential usable without a prompt.
  ///
  /// When `true`, the SDK shows the system biometric prompt BEFORE it reads or
  /// uses the stored refresh credential: on `hydrate()` (cold start, when a
  /// stored session exists), on `getToken()` when it has to refresh, and on
  /// every refresh — unless a prompt already succeeded within
  /// [freshAuthWindow]. An access token already held in memory is returned
  /// without prompting.
  ///
  /// A cancelled, failed or unavailable prompt yields no token: `getToken()`
  /// and `refreshTokens()` resolve to `null` and the state becomes
  /// `AuthStateError` with `SdkErrorCode.biometricError` (reason
  /// `biometricCancelled`, `biometricLockout`, `biometricNotEnrolled` or
  /// `biometricUnavailable`). The stored credential is kept, so a later
  /// `getToken()` or `RakomiAuth.unlockWithBiometric` can retry.
  final bool requireBiometricUnlock;

  /// Reason shown in the system biometric dialog when the lock prompts.
  /// Localize it for your app.
  final String biometricPromptReason;

  final List<String>? certificateFingerprints;
  final Widget child;

  static bool _validBaseUrl(String url) {
    if (url.startsWith('https://')) return true;
    // Dev-loopback only: localhost (with optional:port/path) OR RFC 1918
    // 127.0.0.0/8 and 10.0.0.0/8. Anchored on host boundary so attackers
    // can't slip past via `localhost.evil.com` or `10.example.com`.
    final loopback = RegExp(
      r'^http://(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?(/|$)',
    );
    return loopback.hasMatch(url);
  }

  /// Resolve the nearest enclosing `RakomiProvider` from [context]. Throws
  /// if not found — use [maybeOf] for nullable lookup.
  static RakomiAuth of(BuildContext context) {
    final auth = maybeOf(context);
    if (auth == null) {
      throw StateError(
        'RakomiProvider.of(context) called outside RakomiProvider tree',
      );
    }
    return auth;
  }

  static RakomiAuth? maybeOf(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<_RakomiScope>();
    return scope?.auth;
  }

  @override
  State<RakomiProvider> createState() => _RakomiProviderState();
}

class _RakomiProviderState extends State<RakomiProvider> {
  RakomiAuth? _auth;
  RakomiNativeAdapter? _ownedAdapter;
  StreamSubscription<void>? _appResumedSub;
  DeepLinkOAuthHandler? _deepLinkHandler;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    final tenantId = widget.tenantId ?? widget.publishableKey;
    final base = widget.apiBaseUrl ?? 'https://api.rakomi.com';
    // Default expected `iss` is DERIVED from `apiBaseUrl`, not unconditionally
    // hardcoded to the platform constant: a tenant that has bound its own custom
    // domain as its issuer host is issued tokens whose `iss` is that host (RFC 8414
    // §3.3) — a custom domain is NOT routing-only. A PLATFORM host (`rakomi.com` /
    // any subdomain of it, or a local-dev host), by contrast, always expects the
    // frozen platform constant regardless of which platform host `apiBaseUrl` names —
    // the server's own `JWT_ISSUER` is frozen there in every environment, so deriving
    // the expectation from the host itself would reject every real token a
    // staging/dev deployment mints. See `deriveDefaultIssuer`'s doc comment for the
    // exact host classification. Mirrors `@rakomi/react-native`'s
    // `deriveDefaultIssuer` (`packages/react-native/src/internal/token-runtime.ts`).
    final issuer = widget.issuer ?? deriveDefaultIssuer(base);
    // default audience is the frozen platform
    // constant `https://api.rakomi.com` (= kRakomiPlatformAudienceDefault), independent
    // of `publishableKey` / `apiBaseUrl` — Rakomi user-flow access tokens never vary
    // `aud` with the resolved per-tenant `iss` (confirmed server-side). Customer-
    // supplied override preserved.
    final audience = widget.audience ?? kRakomiPlatformAudienceDefault;

    final adapter =
        widget.adapter ??
        (_ownedAdapter = DefaultRakomiNativeAdapter(
          certificateFingerprints: widget.certificateFingerprints,
        ));

    // Fresh-install detection — runs BEFORE any
    // hydration. If Keychain has a lifecycle ID but shared_preferences does
    // NOT, we treat this as a post-uninstall reinstall and PURGE all
    // rakomi.v1.* Keychain keys before any auth state read.
    await _freshInstallSweep(adapter, tenantId);

    final jwksCache = JwksCache(
      tenantId: tenantId,
      // Keys come from the expected issuer's own discovery document (jwks_uri),
      // unless an explicit jwksUrl override is configured.
      jwksUrl: widget.jwksUrl,
      issuer: widget.jwksUrl == null ? issuer : null,
      discoveryOrigin: widget.jwksUrl == null
          ? discoveryOriginFor(issuer, base)
          : null,
      storage: _AdapterStorageFacade(adapter),
      httpClient: adapter.httpClient as http.Client,
    );

    final auth = RakomiAuth(
      tenantId: tenantId,
      publishableKey: widget.publishableKey,
      apiBaseUrl: base,
      issuer: issuer,
      audience: audience,
      clientId: widget.clientId,
      adapter: adapter,
      jwksCache: jwksCache,
      refreshLeadtime: widget.refreshLeadtime,
      freshAuthWindow: widget.freshAuthWindow,
      requireBiometricUnlock: widget.requireBiometricUnlock,
      biometricPromptReason: widget.biometricPromptReason,
    );

    _appResumedSub = adapter.appResumed.listen((_) {
      auth.emitAppState(
        AuthEventType.appStateForeground,
        AuthEventSeverity.info,
      );
      // review finding #1254 (HIGH) — `refreshIfNeededOnResume()`, NOT
      // `refreshTokens()`: the latter forces a refresh (and, with the
      // biometric lock on, a re-prompt) on EVERY resume, even when the
      // in-memory access token is nowhere near expiry. On iOS the local_auth
      // Face ID / Touch ID sheet itself drives an inactive→resumed
      // transition, so that forced-refresh wiring turned a denied prompt
      // into an undismissable loop, and a `freshAuthWindow: Duration.zero`
      // setup into one even on a SUCCESSFUL unlock. See
      // `RakomiAuth.refreshIfNeededOnResume`'s own doc comment for the guards.
      auth.refreshIfNeededOnResume();
    });

    _deepLinkHandler = DeepLinkOAuthHandler(adapter: adapter, auth: auth);
    await _deepLinkHandler!.start();

    setState(() {
      _auth = auth;
    });

    // Non-blocking hydration via microtask.
    Future.microtask(auth.hydrate);
  }

  Future<void> _freshInstallSweep(
    RakomiNativeAdapter adapter,
    String tenantId,
  ) async {
    final keychainId = await adapter.storageRead(lifecycleIdKey(tenantId));
    final markerId = await adapter.markerRead(lifecycleMarkerKey(tenantId));
    // The pair is compared by VALUE, not merely for presence. Presence alone
    // let anything able to write `shared_preferences` suppress the purge by
    // storing an arbitrary non-null marker — and made the identifier's own
    // unguessability irrelevant, because nothing ever read it back.
    // `shared_preferences` is NOT secure storage, so the marker is the half an
    // attacker can reach; the Keychain half is the one they must match.
    final reinstalled =
        keychainId != null &&
        (markerId == null || !constantTimeStringEquals(keychainId, markerId));
    if (reinstalled) {
      // Post-uninstall reinstall — Keychain residue. PURGE everything in this
      // tenant's namespace BEFORE hydration runs.
      const prefix = '$kStorageNamespace.';
      final entries = await adapter.storageReadByPrefix(prefix);
      for (final key in entries.keys) {
        // Match the tenant segment exactly: keys are
        //   rakomi.v1.<purpose>.<tenantId>[.<extra>]
        // Substring `contains('.$tenantId')` would falsely match keys whose
        // tenant segment merely STARTS with this tenantId (e.g. `abc` vs
        // `abcdef`), violating multi-tenant isolation.
        final rest = key.startsWith(prefix)
            ? key.substring(prefix.length)
            : key;
        final dot = rest.indexOf('.');
        if (dot < 0) continue;
        final afterPurpose = rest.substring(dot + 1);
        if (afterPurpose == tenantId || afterPurpose.startsWith('$tenantId.')) {
          await adapter.storageDelete(key);
        }
      }
    }
    if (keychainId == null) {
      // Cold start — mint the lifecycle pair. The value is a 16-byte CSPRNG id
      // because the marker half lives in non-secure storage and is compared by
      // value above; a guessable id would let a forged marker match.
      //
      // Marker FIRST, deliberately: a process killed between the two writes
      // then leaves a marker with no Keychain id, which the branches above
      // treat as a normal cold start. The reverse order would leave a Keychain
      // id with no marker — indistinguishable from a post-uninstall reinstall,
      // and it would purge a user who uninstalled nothing.
      final id = randomOneTimeId();
      await adapter.markerWrite(lifecycleMarkerKey(tenantId), id);
      await adapter.storageWrite(lifecycleIdKey(tenantId), id);
    } else if (reinstalled) {
      // The purge above cleared the namespace; re-pair on the surviving id.
      await adapter.markerWrite(lifecycleMarkerKey(tenantId), keychainId);
    }
  }

  @override
  void dispose() {
    _appResumedSub?.cancel();
    _deepLinkHandler?.dispose();
    _auth?.dispose();
    _ownedAdapter?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final auth = _auth;
    if (auth == null) {
      // Pre-bootstrap frame. Render the child wrapped in a "loading" scope —
      // `RakomiAuthGate` consumes this to show the loading slot.
      return _RakomiScope(auth: null, child: widget.child);
    }
    return _RakomiScope(auth: auth, child: widget.child);
  }
}

class _RakomiScope extends InheritedWidget {
  const _RakomiScope({required this.auth, required super.child});

  final RakomiAuth? auth;

  @override
  bool updateShouldNotify(covariant _RakomiScope oldWidget) =>
      oldWidget.auth != auth;
}

class _AdapterStorageFacade implements JwksStorage {
  _AdapterStorageFacade(this._adapter);
  final RakomiNativeAdapter _adapter;

  @override
  Future<String?> readKey(String key) => _adapter.storageRead(key);

  @override
  Future<void> writeKey(String key, String value) =>
      _adapter.storageWrite(key, value);

  @override
  Future<void> deleteKey(String key) => _adapter.storageDelete(key);
}
