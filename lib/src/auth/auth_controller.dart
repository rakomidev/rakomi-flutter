import 'dart:async';
import 'dart:convert' show base64Url, jsonDecode, jsonEncode, utf8;

import 'package:flutter/foundation.dart' show ChangeNotifier;
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart' show parseHttpDate;

import '../internal/http_client.dart';
import '../internal/jwks_cache.dart';
import '../internal/jwt_verify.dart';
import '../internal/storage_keys.dart';
import '../internal/version.dart';
import '../native/adapter.dart';
import 'auth_event.dart';
import 'auth_state.dart';
import 'dpop_refresh.dart';
import 'dpop_session.dart';
import 'errors.dart';
import 'refresh_failure.dart';
import 'social_provider.dart';
import 'user.dart';

/// Refresh lead-time. The controller proactively refreshes a session when the
/// access-token's `exp` claim is within this window.
const Duration kDefaultRefreshLeadtime = Duration(seconds: 60);

/// Default reason shown in the system biometric dialog when
/// [RakomiAuth.requireBiometricUnlock] is on.
const String kDefaultBiometricPromptReason = 'Unlock to continue';

/// Per-`RakomiProvider`-tree auth accessor exposing the public async API +
/// state Stream + events Stream.
///
/// **Per-provider-tree semantics**: NOT a process-global singleton.
/// `RakomiProvider.of(context).auth` resolves to the nearest enclosing
/// `RakomiProvider`. Multiple providers in the same widget tree
/// (multi-tenant test harnesses) yield independent instances.
class RakomiAuth extends ChangeNotifier {
  RakomiAuth({
    required this.tenantId,
    required this.publishableKey,
    required this.apiBaseUrl,
    required this.issuer,
    required this.audience,
    required this.adapter,
    required this.jwksCache,
    this.clientId,
    Duration refreshLeadtime = kDefaultRefreshLeadtime,
    Duration freshAuthWindow = const Duration(seconds: 30),
    this.requireBiometricUnlock = false,
    this.biometricPromptReason = kDefaultBiometricPromptReason,
    DpopSession? dpopSession,
  }) : _refreshLeadtime = refreshLeadtime,
       _freshAuthWindow = freshAuthWindow,
       _dpopSession = dpopSession {
    _statesController = StreamController<AuthState>.broadcast();
    _eventsController = StreamController<AuthEvent>.broadcast();
    _statesController.add(_state);
    _emit(AuthEventType.initialized, AuthEventSeverity.info);
  }

  final String tenantId;
  final String publishableKey;
  final String apiBaseUrl;
  final String issuer;
  final String audience;

  /// The OAuth 2.1 `client_id` of a PUBLIC client registered for the browser/
  /// PKCE hosted-login flow (`RakomiAuth.signInWithProvider`,
  /// `performSocialSignIn`) — a distinct credential from [publishableKey],
  /// which authenticates the native `/v1/auth/*` password/passwordless/MFA
  /// endpoints and carries no authority for `/oauth/authorize` +
  /// `/oauth/token`. `null`/empty means the browser flow is not configured:
  /// the SDK fails closed (see `oauth/social_auth.dart`) rather than opening
  /// a browser session that can never complete.
  final String? clientId;
  final RakomiNativeAdapter adapter;
  final JwksCache jwksCache;
  final Duration _refreshLeadtime;
  final Duration _freshAuthWindow;

  /// Opt-in biometric lock; see `RakomiProvider.requireBiometricUnlock`. When
  /// `true`, the stored refresh credential is read or used only after a
  /// biometric prompt has succeeded within the fresh-auth window; a denied
  /// prompt yields no token and an `AuthStateError` with
  /// `SdkErrorCode.biometricError`. Defaults to `false`.
  final bool requireBiometricUnlock;

  /// Reason shown in the system biometric dialog when the lock prompts.
  final String biometricPromptReason;

  /// Optional DPoP binding handle. When a
  /// session is DPoP-bound, the refresh call attaches a fresh RFC 9449 proof. When
  /// absent / not bound, refresh is a plain Bearer call (no proof). The SAME
  /// handle (one native keypair) is observed at issuance and on every refresh —
  /// see [DpopSession]. The JS/Dart layer never holds the private key.
  final DpopSession? _dpopSession;

  /// The committed RFC 7638 thumbprint of the DPoP session keypair once the server
  /// has confirmed the binding (`null` for a Bearer/cold-start session). Read-only
  /// surface for diagnostics + the bound-state cross-check.
  String? get dpopBoundJkt => _dpopSession?.boundJkt;

  /// Whether the current session is DPoP sender-bound (server-confirmed).
  bool get isDpopBound => _dpopSession?.isBound ?? false;

  late final StreamController<AuthState> _statesController;
  late final StreamController<AuthEvent> _eventsController;

  AuthState _state = const AuthStateLoading();
  String? _accessToken;
  Session? _session;
  User? _user;

  /// Single in-flight refresh.
  Completer<Session>? _refreshInFlight;

  /// No refresh is sent before this instant: set from a transient failure's
  /// `Retry-After` (capped at [maxRefreshRetryAfter]). Until then a refresh
  /// attempt reports [_refreshHeldError] without touching the network.
  DateTime? _refreshHeldUntil;
  SdkError? _refreshHeldError;

  /// A cold-start restore whose refresh failed transiently. The stored
  /// credential was kept; the next successful refresh completes the restore.
  bool _restorePending = false;

  /// When the biometric lock last succeeded (read only while
  /// [requireBiometricUnlock] is on). A [Stopwatch], NOT [DateTime] — review
  /// finding #1254 (Medium): `DateTime.now().difference(last) < window` is
  /// also true when the difference is NEGATIVE, so setting the SYSTEM clock
  /// back after a real unlock keeps the "still fresh" window open
  /// indefinitely (until the wall clock catches back up), for as long as
  /// this controller instance stays alive. `Stopwatch` ticks are monotonic —
  /// immune to the device clock being changed underneath the app.
  Stopwatch? _lastBiometricUnlockStopwatch;

  /// When the biometric lock was last DENIED (cancelled/failed/lockout) — a
  /// short cooldown on the LIFECYCLE-driven auto-refresh only (never on an
  /// explicit `unlockWithBiometric()` call, which always re-prompts). Review
  /// finding #1254 (HIGH): on iOS the local_auth Face ID / Touch ID sheet
  /// itself drives an `inactive`→`resumed` transition, so wiring
  /// `AppLifecycleState.resumed` straight to an unconditional re-auth
  /// re-triggers the very prompt that just closed — a denial becomes an
  /// undismissable loop. This is a UX-cooldown, not a security boundary
  /// (denying access is still the safe default throughout), so a plain wall
  /// clock is acceptable here — the failure mode of a clock rollback is
  /// "prompts again sooner", never "skips the prompt".
  DateTime? _lastBiometricDenialAt;
  static const Duration _kBiometricDenialCooldown = Duration(seconds: 2);

  int _clockSkewMs = 0;
  bool _clockSkewLoaded = false;

  RakomiHttpClient get _http {
    final inner = adapter.httpClient;
    if (inner is! http.Client) {
      throw StateError('Adapter httpClient must be a package:http Client');
    }
    return RakomiHttpClient(inner, userAgent: rakomiFlutterUserAgent);
  }

  /// Headers for an `apiKeyAuth()`-protected endpoint (login, register,
  /// refresh, magic-link/email-OTP send, MFA verify-login). The publishable
  /// key travels as `X-API-Key` — the header the API's `apiKeyAuth()`
  /// middleware actually reads (`extractApiKey`, `middleware/auth.ts`), not
  /// a bespoke `X-Rakomi-*` name. [extra] is merged in (e.g. a `DPoP` proof
  /// on refresh) and wins on key collision.
  Map<String, String> _apiKeyHeaders([Map<String, String>? extra]) {
    return <String, String>{'X-API-Key': publishableKey, ...?extra};
  }

  AuthState get authState => _state;
  Stream<AuthState> get authStateChanges => _statesController.stream;
  Stream<AuthEvent> get events => _eventsController.stream;

  User? get user => _user;
  Session? get session => _session;

  Future<void> hydrate() => _hydrate(biometricChecked: false);

  Future<void> _hydrate({required bool biometricChecked}) async {
    try {
      final userJson = await adapter.storageRead(userKey(tenantId));
      final hasRefresh = await adapter.storageRead(refreshTokenKey(tenantId));
      if (hasRefresh == null) {
        _setState(const AuthStateUnauthenticated());
        _emit(AuthEventType.restoreFailed, AuthEventSeverity.info);
        return;
      }
      // Biometric lock: prompt before the stored credential is used. A denied
      // prompt keeps the credential and settles on a typed error.
      if (!biometricChecked) {
        final denied = await _requireBiometricUnlockIfConfigured();
        if (denied != null) {
          _emit(AuthEventType.restoreFailed, AuthEventSeverity.security);
          _setState(AuthStateError(denied));
          return;
        }
      }
      // Try to restore in-memory snapshot from cached user. Session is
      // re-derived from the next refresh — we do NOT trust persisted session
      // metadata for `exp` enforcement.
      if (userJson != null) {
        _user = User.fromJson(jsonDecode(userJson) as Map<String, Object?>);
      }
      // Force a refresh to validate the persisted refresh token end-to-end.
      try {
        _restorePending = true;
        await _refresh(biometricChecked: true);
        // A successful refresh emitted `restoreSucceeded` and cleared the
        // flag. A transient failure kept the stored credential and left the
        // flag set, so a later successful refresh completes this restore. A
        // definitive rejection signed out, which cleared it.
      } catch (e) {
        // `_refresh` reports its failures through state, not by throwing; an
        // unexpected throw says nothing about the credential, so keep it.
        _setState(
          AuthStateError(
            SdkError(
              code: SdkErrorCode.networkError,
              reason: SdkErrorReason.network,
              errorMessage: '$e',
              cause: e,
            ),
          ),
        );
      }
    } catch (e) {
      _emit(
        AuthEventType.restoreFailed,
        AuthEventSeverity.warning,
        errorMessage: '$e',
      );
      _setState(const AuthStateUnauthenticated());
    }
  }

  /// Returns `true` iff an in-memory access token exists, has not passed
  /// `exp`, and verifies against cached JWKS (offline-tolerant).
  Future<bool> hasValidSession() async {
    final token = _accessToken;
    final session = _session;
    if (token == null || session == null) return false;
    if (session.isExpired()) return false;
    return _verifyToken(token);
  }

  /// Get a current access token, refreshing if within [_refreshLeadtime] of
  /// expiry. JWT signature verification fires only on refresh-completion +
  /// [hasValidSession].
  ///
  /// Review finding #1254 (Medium): a denied/failed biometric prompt now
  /// resolves to `null` here, matching the documented contract (provider.dart
  /// / configuration.mdx / authentication.mdx / CHANGELOG). Before this fix,
  /// `_refresh()` failing on the biometric-lock branch left `_accessToken`
  /// untouched, so a token already inside `_refreshLeadtime` of `exp` — the
  /// ONLY case that reaches this branch — was handed back to the caller
  /// possibly-expired, silently, while `authState` had already moved to
  /// `AuthStateError(biometricError)`. Scoped to the biometric-error state
  /// specifically (not every `_refresh()` failure) so an unrelated transient
  /// network error keeps its existing, separately-covered behaviour.
  Future<String?> getToken() async {
    final token = _accessToken;
    final session = _session;
    if (token != null &&
        session != null &&
        !session.isExpiringSoon(leadtime: _refreshLeadtime)) {
      return token;
    }
    await _refresh();
    final state = _state;
    if (state is AuthStateError &&
        state.error.code == SdkErrorCode.biometricError) {
      return null;
    }
    return _accessToken;
  }

  /// Force a refresh — useful for a caller that must guarantee a round trip
  /// (e.g. right after a server-side revoke). Always re-prompts for
  /// biometric unlock when the lock is on and the fresh-auth window has
  /// lapsed — do NOT wire this to a lifecycle event; see
  /// [refreshIfNeededOnResume] for that.
  Future<Session?> refreshTokens() => _refresh();

  /// Called by the lifecycle observer on `AppLifecycleState.resumed`.
  ///
  /// Review finding #1254 (HIGH). Unlike [refreshTokens], this does NOT force
  /// a refresh: it defers to [getToken], which only talks to the network (and
  /// so only prompts for biometric unlock) when the in-memory token is
  /// actually within [_refreshLeadtime] of expiry — restoring the documented
  /// "an access token already held in memory is returned without prompting"
  /// contract across the `resumed` edge. Two additional guards close the
  /// loop the finding describes, because on iOS the local_auth Face ID /
  /// Touch ID sheet itself drives an `inactive`→`resumed` transition:
  /// - a refresh already in flight (its own biometric prompt may be the very
  ///   thing that just caused this `resumed` event) is never duplicated —
  ///   `getToken()`/`_refresh()`'s existing single-flight guard handles this;
  /// - a prompt denied within the last [_kBiometricDenialCooldown] is not
  ///   immediately retried, so cancelling once does not become undismissable.
  /// An explicit [unlockWithBiometric] call always re-prompts regardless.
  Future<void> refreshIfNeededOnResume() async {
    final deniedAt = _lastBiometricDenialAt;
    if (deniedAt != null &&
        DateTime.now().difference(deniedAt) < _kBiometricDenialCooldown) {
      return;
    }
    await getToken();
  }

  Future<AuthState> signIn({required String email, required String password}) {
    _emit(AuthEventType.signInAttempted, AuthEventSeverity.info);
    return _signInPasswordFlow(email: email, password: password);
  }

  Future<AuthState> signUp({
    required String email,
    required String password,
    required bool consent,
  }) {
    _emit(AuthEventType.signInAttempted, AuthEventSeverity.info);
    return _signUpFlow(email: email, password: password, consent: consent);
  }

  /// End the session on the server (best effort, never awaited by the local
  /// sign-out), then clear it locally.
  ///
  /// A session issued to an OAuth client revokes its refresh token at
  /// `/oauth/revoke` (RFC 7009) with its `client_id`, which needs no access
  /// token. A first-party session calls `/v1/auth/logout` with its access
  /// token (`DPoP` and a proof when the session is bound).
  Future<void> signOut() async {
    final refresh = await adapter.storageRead(refreshTokenKey(tenantId));
    final clientId = await adapter.storageRead(oauthClientIdKey(tenantId));
    // Capture the access token BEFORE `_localSignOut()` clears it —
    // `/v1/auth/logout` is `jwtAuth()`-guarded (Bearer access token), not
    // `apiKeyAuth()`, so a null token here means the revoke call is skipped
    // rather than sent unauthenticated.
    final accessToken = _accessToken;
    if (refresh != null && clientId != null && clientId.isNotEmpty) {
      unawaited(_revokeClientRefreshToken(refresh, clientId));
    } else if (refresh != null && accessToken != null) {
      unawaited(_logoutFirstParty(accessToken));
    }
    await _localSignOut();
    _emit(AuthEventType.signedOut, AuthEventSeverity.info);
  }

  /// Programmatic social sign-in entry point.
  ///
  /// This stub is intentionally unimplemented because the OAuth flow needs a
  /// `redirectUri` (platform-conditional scheme guard, RFC 8252). Use the
  /// top-level [performSocialSignIn] function from `package:rakomi_flutter`
  /// instead — it accepts `redirectUri` and applies the scheme guard. Or
  /// embed [RakomiSignInButton] / [RakomiSignInForm] which read the
  /// `redirectUri` configured on the enclosing [RakomiProvider].
  Future<AuthState> signInWithProvider(SocialProvider provider) async {
    throw UnsupportedError(
      'RakomiAuth.signInWithProvider() requires a redirectUri. '
      'Call performSocialSignIn(auth, provider, redirectUri: ...) instead, '
      'or use RakomiSignInButton/RakomiSignInForm widgets.',
    );
  }

  /// Wired by `oauth/mfa.dart` extension.
  Future<AuthState> verifyMfa(String code) async {
    throw UnsupportedError(
      'RakomiAuth.verifyMfa() requires a challengeId. '
      'Call auth.verifyMfaImpl(code, challengeId: ...) — the extension method '
      'from `package:rakomi_flutter` (RakomiMfaFlow).',
    );
  }

  Future<AuthState> signInWithMagicLink(String email) async {
    // Path is `/v1/auth/magic-link` — the API has no `/send` suffix (that
    // shape belongs to the dashboard-only `/v1/auth/dashboard/magic-link`,
    // a different, noAuth()-guarded route this SDK never calls).
    final r = await _http.postJson(
      Uri.parse('$apiBaseUrl/v1/auth/magic-link'),
      <String, Object?>{'email': email},
      headers: _apiKeyHeaders(),
    );
    if (r.statusCode != 200 && r.statusCode != 202) {
      return _emitErrorState(
        const SdkError(
          code: SdkErrorCode.networkError,
          reason: SdkErrorReason.network,
        ),
      );
    }
    return _state;
  }

  Future<AuthState> signInWithEmailOtp(String email) async {
    // Path is `/v1/auth/email-otp` — no `/send` suffix.
    final r = await _http.postJson(
      Uri.parse('$apiBaseUrl/v1/auth/email-otp'),
      <String, Object?>{'email': email},
      headers: _apiKeyHeaders(),
    );
    if (r.statusCode != 200 && r.statusCode != 202) {
      return _emitErrorState(
        const SdkError(
          code: SdkErrorCode.networkError,
          reason: SdkErrorReason.network,
        ),
      );
    }
    return _state;
  }

  Future<bool> unlockWithBiometric({String reason = 'Unlock'}) async {
    final result = await adapter.requestBiometric(reason: reason);
    if (result is BiometricSuccess) {
      _lastBiometricUnlockStopwatch = Stopwatch()..start();
      await _hydrate(biometricChecked: true);
      return _state is AuthStateAuthenticated;
    }
    final reasonEnum = switch (result) {
      BiometricCancelled() => SdkErrorReason.biometricCancelled,
      BiometricLockout() => SdkErrorReason.biometricLockout,
      BiometricNotEnrolled() => SdkErrorReason.biometricNotEnrolled,
      BiometricUnavailable() => SdkErrorReason.biometricUnavailable,
      BiometricSuccess() => SdkErrorReason.unknown,
    };
    _lastBiometricDenialAt = DateTime.now();
    _emit(AuthEventType.biometricFailed, AuthEventSeverity.security);
    _setState(
      AuthStateError(
        SdkError(code: SdkErrorCode.biometricError, reason: reasonEnum),
      ),
    );
    return false;
  }

  // ─── Internals ──────────────────────────────────────────────────────── //

  /// When [requireBiometricUnlock] is on, require a biometric success within
  /// the fresh-auth window before the stored credential is read or used.
  /// Returns `null` to proceed, or the typed error that stops the operation.
  ///
  /// Review finding #1254 (Medium): the "still fresh" check runs on a
  /// [Stopwatch] (monotonic), not [DateTime.now()] (wall clock) — see
  /// [_lastBiometricUnlockStopwatch]'s own doc comment for the clock-rollback
  /// scenario this closes.
  Future<SdkError?> _requireBiometricUnlockIfConfigured() async {
    if (!requireBiometricUnlock) return null;
    final sw = _lastBiometricUnlockStopwatch;
    if (sw != null && sw.elapsed < _freshAuthWindow) {
      return null;
    }
    final result = await adapter.requestBiometric(
      reason: biometricPromptReason,
    );
    if (result is BiometricSuccess) {
      _lastBiometricUnlockStopwatch = Stopwatch()..start();
      return null;
    }
    _lastBiometricDenialAt = DateTime.now();
    _emit(AuthEventType.biometricFailed, AuthEventSeverity.security);
    return SdkError(
      code: SdkErrorCode.biometricError,
      reason: switch (result) {
        BiometricCancelled() => SdkErrorReason.biometricCancelled,
        BiometricLockout() => SdkErrorReason.biometricLockout,
        BiometricNotEnrolled() => SdkErrorReason.biometricNotEnrolled,
        BiometricUnavailable() => SdkErrorReason.biometricUnavailable,
        BiometricSuccess() => SdkErrorReason.unknown,
      },
    );
  }

  /// [biometricChecked] is true only when the caller has just passed the
  /// biometric lock itself (hydration), so one cold start prompts once.
  Future<Session?> _refresh({bool biometricChecked = false}) async {
    if (_refreshInFlight != null) return _refreshInFlight!.future;
    final heldUntil = _refreshHeldUntil;
    if (heldUntil != null && DateTime.now().isBefore(heldUntil)) {
      // The server asked for a pause (`Retry-After`). Report the same transient
      // error without sending the stored credential again.
      _emit(
        AuthEventType.refreshFailed,
        AuthEventSeverity.warning,
        errorMessage: 'retry_after_pending',
      );
      final held = _refreshHeldError;
      if (held != null && _state is! AuthStateAuthenticated) {
        _setState(AuthStateError(held));
      }
      return null;
    }
    final completer = Completer<Session>();
    _refreshInFlight = completer;
    // The initiating caller observes the outcome via this method's own return
    // value (a `Session?` / a thrown error from `hydrate`); the shared `completer`
    // future is what CONCURRENT callers await for single-flight dedup. Register a
    // no-op error sink so a failed refresh whose error is reported through the
    // method return (not the completer) does not surface as an unhandled async
    // error in the zone. Concurrent `await completer.future` callers each register
    // their own listener and still receive the error.
    unawaited(
      completer.future.then<void>((_) {}, onError: (Object e, StackTrace s) {}),
    );
    try {
      _emit(AuthEventType.refreshStarted, AuthEventSeverity.info);
      // Biometric lock: prompt BEFORE the stored credential is read.
      if (!biometricChecked) {
        final denied = await _requireBiometricUnlockIfConfigured();
        if (denied != null) {
          _emit(
            AuthEventType.refreshFailed,
            AuthEventSeverity.security,
            errorMessage: denied.reason.wire,
          );
          _setState(AuthStateError(denied));
          completer.completeError(denied);
          return null;
        }
      }
      final token = await adapter.storageRead(refreshTokenKey(tenantId));
      if (token == null) {
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.info,
          errorMessage: 'no_refresh_token',
        );
        await _localSignOut();
        completer.completeError(const _NoRefreshToken());
        return null;
      }
      // when the session is DPoP-bound,
      // route through `refreshWithDpop` (attach a fresh RFC 9449 proof + single
      // bounded nonce retry + three-class taxonomy). Otherwise a plain Bearer
      // refresh. The single-flight guard above is set BEFORE any async signing,
      // so the TOCTOU window is pinned.
      final exchange = await _exchangeWithOneImmediateRetry(token);

      // A 5xx after which the server may already have rotated the token, or a
      // transport failure (the answer may have been lost after the rotation),
      // and the one immediate retry did not settle it: the outcome is unknown.
      // Presenting the token again later would be a reuse if it was rotated,
      // and a reuse revokes every session of the user — so end the session
      // here and let the user sign in again.
      final uncertainStatus = exchange.uncertainAfterStatus;
      if (uncertainStatus != null) {
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: 'refresh_outcome_unknown',
        );
        await _localSignOut();
        completer.completeError(
          SdkError(
            code: SdkErrorCode.refreshFailed,
            reason: SdkErrorReason.unknown,
            httpStatus: uncertainStatus == _noResponseStatus
                ? null
                : uncertainStatus,
            errorMessage: 'refresh_outcome_unknown',
          ),
        );
        return null;
      }

      // A DPoP signer failure is terminal — NEVER a silent proof-less Bearer
      // retry. Surface it as a distinct, rollback-actionable error.
      if (exchange.dpopError != null) {
        final dpopErr = exchange.dpopError!;
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: dpopErr.code,
        );
        // A network-class failure (transport, 5xx/429/408, or a non-definitive
        // 4xx) keeps the session, the stored refresh token and the DPoP key.
        if (dpopErr.errorClass == DpopRefreshErrorClass.network) {
          _failRefreshKeepingSession(
            completer,
            status: dpopErr.statusCode ?? 0,
            oauthError: dpopErr.oauthError,
            retryAfterHeader: dpopErr.retryAfter,
          );
          return null;
        }
        // `invalid_dpop_proof` (incl. cold-start re-bind) /
        // `invalid_refresh_token` ⇒ full local sign-out → re-login re-binds a
        // fresh key. `dpop_prover_unavailable` ⇒ same (no usable session).
        await _localSignOut();
        completer.completeError(
          SdkError(
            code: dpopErr.errorClass == DpopRefreshErrorClass.network
                ? SdkErrorCode.networkError
                : SdkErrorCode.refreshFailed,
            reason: switch (dpopErr.errorClass) {
              DpopRefreshErrorClass.invalidRefreshToken =>
                SdkErrorReason.refreshRevoked,
              DpopRefreshErrorClass.network => SdkErrorReason.network,
              // Both prover-unavailable and proof-rejected map to a re-bind path;
              // the distinct wire code is carried on `errorMessage` for telemetry.
              _ => SdkErrorReason.unknown,
            },
            errorMessage: dpopErr.code,
          ),
        );
        return null;
      }

      final status = exchange.statusCode;
      final body = exchange.body;
      final accessToken = body?['access_token'] as String?;
      if (status >= 200 && status < 300 && accessToken == null) {
        // A success the SDK cannot use: the server consumed the presented
        // refresh token, so presenting it again would be a reuse, which
        // revokes every session of the user. End the session locally.
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: 'refresh_response_unreadable',
        );
        await _localSignOut();
        completer.completeError(
          SdkError(
            code: SdkErrorCode.refreshFailed,
            reason: SdkErrorReason.refreshRevoked,
            httpStatus: status,
            errorMessage: 'refresh_response_unreadable',
          ),
        );
        return null;
      }
      if (status < 200 || status >= 300) {
        final kind = classifyRefreshFailure(status, exchange.oauthError);
        if (kind == RefreshFailureKind.definitive) {
          _emit(
            AuthEventType.refreshFailed,
            AuthEventSeverity.security,
            errorMessage: 'auth_error_$status',
          );
          await _localSignOut();
          completer.completeError(
            SdkError(
              code: SdkErrorCode.refreshFailed,
              reason: status == 401 && exchange.oauthError == null
                  ? SdkErrorReason.refreshExpired
                  : SdkErrorReason.refreshRevoked,
              httpStatus: status,
              errorMessage: exchange.oauthError,
            ),
          );
          return null;
        }
        _failRefreshKeepingSession(
          completer,
          status: status,
          oauthError: exchange.oauthError,
          retryAfterHeader: exchange.retryAfter,
        );
        return null;
      }
      final refreshToken = body!['refresh_token'] as String? ?? token;
      if (!await _verifyToken(accessToken!)) {
        // The server has rotated the stored refresh token; keeping the old one
        // would make the next refresh a reuse. End the session locally.
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: 'access_token_verify_failed',
        );
        await _localSignOut();
        completer.completeError(
          const SdkError(
            code: SdkErrorCode.refreshFailed,
            reason: SdkErrorReason.unknown,
            errorMessage: 'access_token_verify_failed',
          ),
        );
        return null;
      }
      try {
        await adapter.storageWrite(refreshTokenKey(tenantId), refreshToken);
      } catch (e) {
        // Persistence failed → don't claim authenticated. Surfacing
        // AuthStateAuthenticated below would silently mask the failure,
        // and the next cold-start hydrate would find no refresh token.
        final err = SdkError(
          code: SdkErrorCode.storageError,
          reason: SdkErrorReason.unknown,
          errorMessage: 'storage_write_failed',
          cause: e,
        );
        _setState(AuthStateError(err));
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: 'storage_write_failed',
        );
        completer.completeError(err);
        return null;
      }
      _accessToken = accessToken;
      _session = _sessionFromAccessToken(accessToken);
      _user ??= _placeholderUserFromToken(accessToken);
      unawaited(_refreshUserSnapshot());
      _refreshHeldUntil = null;
      _refreshHeldError = null;
      _setState(AuthStateAuthenticated(_user!, _session!));
      _emit(AuthEventType.refreshSucceeded, AuthEventSeverity.info);
      if (_restorePending) {
        _restorePending = false;
        _emit(AuthEventType.restoreSucceeded, AuthEventSeverity.info);
      }
      completer.complete(_session!);
      return _session;
    } catch (e, st) {
      // Catch-all for anything not already converted to a typed `SdkError`
      // above (an unexpected exception from a dependency, not a modeled HTTP/
      // decode outcome). Every OTHER failure branch in this method emits an
      // audit event, updates `authState`, and completes with a typed
      // `SdkError` — this fallback must uphold the same contract instead of
      // leaving the caller stuck (no state change) and handing a concurrent
      // `await`er a raw, untyped exception (`errors.dart`'s own documented
      // invariant: errors never throw across the public API surface).
      if (!completer.isCompleted) {
        final err = SdkError(
          code: SdkErrorCode.networkError,
          reason: SdkErrorReason.network,
          errorMessage: '$e',
          cause: e,
        );
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.warning,
          errorMessage: '$e',
        );
        _setState(AuthStateError(err));
        completer.completeError(err, st);
      }
      return null;
    } finally {
      _refreshInFlight = null;
    }
  }

  /// One refresh with the 5xx policy: a status for which
  /// [isRefreshRetryOnceStatus] holds, or a transport failure (no response
  /// arrived; [_noResponseStatus]), is retried once, immediately — with a
  /// fresh proof from the same DPoP key on a bound session — and only while the
  /// first answer arrived within [refreshRetryOnceDeadline]. A retry that is
  /// neither a success nor a definitive rejection (another 5xx, a 503, a 429, a
  /// transport failure, a prover failure) yields an exchange carrying
  /// [_RefreshExchange.uncertainAfterStatus]. Never a third request.
  Future<_RefreshExchange> _exchangeWithOneImmediateRetry(
    String refreshToken,
  ) async {
    final started = DateTime.now();
    final first = await _performRefreshExchange(refreshToken);
    final status = _retryOnceStatusOf(first);
    if (status == null) return first;
    if (DateTime.now().difference(started) > refreshRetryOnceDeadline) {
      return _RefreshExchange(statusCode: status, uncertainAfterStatus: status);
    }
    final second = await _performRefreshExchange(refreshToken);
    if (_isSettledExchange(second)) return second;
    return _RefreshExchange(statusCode: status, uncertainAfterStatus: status);
  }

  int? _retryOnceStatusOf(_RefreshExchange e) {
    final dpopErr = e.dpopError;
    if (dpopErr != null) {
      if (dpopErr.errorClass != DpopRefreshErrorClass.network) return null;
      final s = dpopErr.statusCode;
      // A network-class failure without a status is a transport failure.
      if (s == null) return _noResponseStatus;
      return isRefreshRetryOnceStatus(s) ? s : null;
    }
    if (e.networkFailure) return _noResponseStatus;
    return isRefreshRetryOnceStatus(e.statusCode) ? e.statusCode : null;
  }

  /// A success (including a 2xx the SDK cannot read, which ends the session
  /// downstream) or a rejection that ends the session.
  bool _isSettledExchange(_RefreshExchange e) {
    final dpopErr = e.dpopError;
    if (dpopErr != null) {
      return dpopErr.errorClass == DpopRefreshErrorClass.invalidRefreshToken ||
          dpopErr.errorClass == DpopRefreshErrorClass.invalidDpopProof;
    }
    if (e.statusCode >= 200 && e.statusCode < 300) return true;
    return classifyRefreshFailure(e.statusCode, e.oauthError) ==
        RefreshFailureKind.definitive;
  }

  /// Perform the `POST /v1/auth/refresh` exchange, attaching a DPoP proof IFF the
  /// session is DPoP-bound. Captures clock skew off the response, normalizes the
  /// outcome, and (on the bound path) applies the single bounded nonce retry +
  /// three-class taxonomy via [refreshWithDpop].
  ///
  /// Returns a [_RefreshExchange] carrying either an HTTP status + parsed body
  /// (the existing downstream logic handles verify/persist/state) or a
  /// [DpopRefreshError] (the bound-path three-class failure — handled distinctly
  /// by the caller, never as a silent Bearer downgrade).
  Future<_RefreshExchange> _performRefreshExchange(String refreshToken) async {
    // A session issued to an OAuth client refreshes at the token endpoint with
    // its client_id (RFC 6749 §6); the API refuses it at /v1/auth/refresh.
    final storedClientId = await adapter.storageRead(
      oauthClientIdKey(tenantId),
    );
    final clientId = (storedClientId == null || storedClientId.isEmpty)
        ? null
        : storedClientId;
    final endpoint = clientId != null
        ? '$apiBaseUrl/oauth/token'
        : '$apiBaseUrl/v1/auth/refresh';

    // The poster performs ONE HTTP attempt: optionally with a `DPoP` proof header.
    // It captures clock skew, reads the `DPoP-Nonce` response header, and decodes
    // the RFC 6749 §5.2 `error` from a non-200 body. NEVER logs token/proof bytes.
    Future<TokenPostResult> post({
      required String refreshToken,
      String? dpopProof,
    }) async {
      late final http.Response response;
      final headers = _apiKeyHeaders(
        dpopProof != null ? <String, String>{'DPoP': dpopProof} : null,
      );
      try {
        response = clientId != null
            ? await _http.postForm(Uri.parse(endpoint), <String, String>{
                'grant_type': 'refresh_token',
                'refresh_token': refreshToken,
                'client_id': clientId,
              }, headers: headers)
            : await _http.postJson(Uri.parse(endpoint), <String, Object?>{
                'refresh_token': refreshToken,
              }, headers: headers);
      } catch (_) {
        return const TokenPostResult(statusCode: 0, networkFailure: true);
      }
      _captureClockSkew(response);
      final nonce = response.headers['dpop-nonce'];
      if (response.statusCode >= 200 && response.statusCode < 300) {
        // An unreadable success is reported as a 2xx without tokens; the
        // caller ends the session (the token was consumed), never re-sends it.
        try {
          final body = decodeJsonBody(response);
          return TokenPostResult(
            statusCode: response.statusCode,
            tokenType: body['token_type'] as String?,
            accessToken: body['access_token'] as String?,
            refreshToken: body['refresh_token'] as String?,
            dpopNonce: nonce,
          );
        } catch (_) {
          return TokenPostResult(
            statusCode: response.statusCode,
            dpopNonce: nonce,
          );
        }
      }
      String? oauthError;
      try {
        oauthError = refreshErrorCode(
          jsonDecode(utf8.decode(response.bodyBytes)),
        );
      } catch (_) {
        /* non-JSON error body */
      }
      return TokenPostResult(
        statusCode: response.statusCode,
        oauthError: oauthError,
        dpopNonce: nonce,
        retryAfter: _headerOf(response, 'retry-after'),
      );
    }

    final session = _dpopSession;
    if (session == null || !session.isBound) {
      // Bearer path — single plain POST, no proof. Preserve the EXACT prior
      // shape (status + parsed 200 body) so downstream verify/persist is identical.
      final result = await post(refreshToken: refreshToken);
      if (result.networkFailure) {
        return const _RefreshExchange(
          statusCode: _noResponseStatus,
          networkFailure: true,
        );
      }
      // Still let the session observe a Bearer issuance so a
      // server downgrade is recorded even on the Bearer branch.
      await session?.observeTokenType(result.tokenType, attachedProof: false);
      return _RefreshExchange(
        statusCode: result.statusCode,
        body: result.isOk ? _bodyOf(result) : null,
        oauthError: result.oauthError,
        retryAfter: result.retryAfter,
      );
    }

    // Bound path — the full DPoP decision logic (proof attach + nonce retry +
    // three-class taxonomy). A signer failure is terminal (no Bearer fallback).
    final outcome = await refreshWithDpop(
      post: post,
      tokenEndpoint: endpoint,
      refreshToken: refreshToken,
      session: session,
    );
    if (!outcome.isOk) {
      return _RefreshExchange(statusCode: 0, dpopError: outcome.error);
    }
    return _RefreshExchange(statusCode: 200, body: _bodyOf(outcome.tokens!));
  }

  /// Re-assemble a 200 body map from a [TokenPostResult] so the downstream
  /// verify/persist path is byte-identical regardless of the Bearer/DPoP branch.
  Map<String, Object?> _bodyOf(TokenPostResult r) => <String, Object?>{
    if (r.accessToken != null) 'access_token': r.accessToken,
    if (r.refreshToken != null) 'refresh_token': r.refreshToken,
    if (r.tokenType != null) 'token_type': r.tokenType,
  };

  Future<bool> _verifyToken(String token) async {
    try {
      var keys = await jwksCache.getKeys();
      final verifier = JwtVerifier(
        expectedIssuer: issuer,
        expectedAudience: audience,
      );
      var result = verifier.verify(
        token: token,
        jwks: keys,
        clockSkewMs: _clockSkewMs,
      );
      if (result is JwtVerifyError &&
          result.reason == JwtVerifyErrorReason.kidMiss) {
        await jwksCache.invalidate();
        keys = await jwksCache.getKeys(forceRefresh: true);
        result = verifier.verify(
          token: token,
          jwks: keys,
          clockSkewMs: _clockSkewMs,
        );
      }
      return result is JwtVerifyOk;
    } catch (_) {
      return false;
    }
  }

  Map<String, Object?> _decodeJwtPayload(String token) {
    final parts = token.split('.');
    final pad = (4 - parts[1].length % 4) % 4;
    return jsonDecode(utf8.decode(base64Url.decode(parts[1] + ('=' * pad))))
        as Map<String, Object?>;
  }

  Session _sessionFromAccessToken(String token) {
    final payload = _decodeJwtPayload(token);
    return Session(
      id: payload['sid'] as String? ?? payload['jti'] as String? ?? 'unknown',
      userId: payload['sub'] as String? ?? '',
      tenantId: tenantId,
      issuedAt: DateTime.fromMillisecondsSinceEpoch(
        ((payload['iat'] as int?) ?? 0) * 1000,
        isUtc: true,
      ),
      expiresAt: DateTime.fromMillisecondsSinceEpoch(
        ((payload['exp'] as int?) ?? 0) * 1000,
        isUtc: true,
      ),
    );
  }

  User _placeholderUserFromToken(String token) =>
      User.fromJson(_decodeJwtPayload(token));

  Future<void> _refreshUserSnapshot() async {
    try {
      final token = _accessToken;
      if (token == null) return;
      final r = await _http.getJson(
        Uri.parse('$apiBaseUrl/v1/auth/me'),
        headers: <String, String>{'Authorization': 'Bearer $token'},
      );
      if (r.statusCode == 200) {
        _user = User.fromJson(decodeJsonBody(r));
        await adapter.storageWrite(userKey(tenantId), r.body);
        _emit(AuthEventType.userUpdated, AuthEventSeverity.info);
        _setState(AuthStateAuthenticated(_user!, _session!));
      }
    } catch (_) {
      /* best-effort */
    }
  }

  void _captureClockSkew(http.Response r) {
    if (_clockSkewLoaded) return;
    final dateHeader = r.headers['date'];
    if (dateHeader == null) return;
    try {
      final serverTime = parseHttpDate(dateHeader).toUtc();
      final deviceTime = DateTime.now().toUtc();
      final skew = serverTime.difference(deviceTime).inMilliseconds;
      _clockSkewMs = skew.clamp(-5 * 60 * 1000, 5 * 60 * 1000);
      _clockSkewLoaded = true;
      adapter.storageWrite(clockSkewKey(tenantId), '$_clockSkewMs');
      if (skew.abs() > 60 * 1000) {
        _emit(
          AuthEventType.clockSkewDetected,
          AuthEventSeverity.security,
          metadata: <String, Object?>{'skewMs': skew},
        );
      }
    } catch (_) {
      /* unparseable Date header */
    }
  }

  Future<AuthState> _signInPasswordFlow({
    required String email,
    required String password,
  }) async {
    try {
      final r = await _http.postJson(
        Uri.parse('$apiBaseUrl/v1/auth/login'),
        <String, Object?>{'email': email, 'password': password},
        headers: _apiKeyHeaders(),
      );
      _captureClockSkew(r);
      if (r.statusCode == 401) {
        return _emitErrorState(
          const SdkError(
            code: SdkErrorCode.signInFailed,
            reason: SdkErrorReason.unknown,
            errorMessage: 'invalid_credentials',
          ),
        );
      }
      if (r.statusCode != 200) {
        return _emitErrorState(
          const SdkError(
            code: SdkErrorCode.signInFailed,
            reason: SdkErrorReason.network,
          ),
        );
      }
      final body = decodeJsonBody(r);
      // The MFA-challenge branch of the login response union is
      // `{next_step: "mfa_verify", mfa_challenge_token, expires_in,
      // available_methods}` — NOT `next_action`/`challenge_id`.
      if (body['next_step'] == 'mfa_verify') {
        _emit(AuthEventType.componentStepChanged, AuthEventSeverity.info);
        return _emitErrorState(
          SdkError(
            code: SdkErrorCode.mfaStepUpRequired,
            reason: SdkErrorReason.unknown,
            errorMessage: body['mfa_challenge_token'] as String?,
          ),
        );
      }
      return _completeSignIn(body);
    } catch (e) {
      return _emitErrorState(
        SdkError(
          code: SdkErrorCode.networkError,
          reason: SdkErrorReason.network,
          errorMessage: '$e',
        ),
      );
    }
  }

  Future<AuthState> _signUpFlow({
    required String email,
    required String password,
    required bool consent,
  }) async {
    try {
      final r = await _http.postJson(
        Uri.parse('$apiBaseUrl/v1/auth/register'),
        <String, Object?>{
          'email': email,
          'password': password,
          'consent': consent,
        },
        headers: _apiKeyHeaders(),
      );
      _captureClockSkew(r);
      if (r.statusCode != 200 && r.statusCode != 201) {
        return _emitErrorState(
          const SdkError(
            code: SdkErrorCode.signInFailed,
            reason: SdkErrorReason.network,
          ),
        );
      }
      final body = decodeJsonBody(r);
      // `/v1/auth/register` answers `{message, next_step?}` with NO tokens —
      // the address has to be verified first. A tenant that skips
      // verification could in principle return tokens directly, so still
      // prefer completing sign-in when they ARE present; otherwise settle on
      // signedOut rather than claiming a session the response never granted.
      if (body['access_token'] is String && body['refresh_token'] is String) {
        return _completeSignIn(body);
      }
      _emit(
        AuthEventType.componentStepChanged,
        AuthEventSeverity.info,
        metadata: <String, Object?>{
          'step': 'registration_pending',
          'message': body['message'],
          'nextStep': body['next_step'],
        },
      );
      _setState(const AuthStateUnauthenticated());
      return _state;
    } catch (e) {
      return _emitErrorState(
        SdkError(
          code: SdkErrorCode.networkError,
          reason: SdkErrorReason.network,
          errorMessage: '$e',
        ),
      );
    }
  }

  /// Complete a sign-in given an `access_token`/`refresh_token` response.
  /// Used by password / OAuth / magic-link / OTP / MFA verify paths.
  ///
  /// [oauthClientId] names the OAuth client the tokens were issued to: the
  /// `client_id` of an authorization-code exchange at `/oauth/token`. Pass
  /// `null` for tokens from a first-party `/v1/auth/*` endpoint. The API
  /// refreshes a client's session only at `/oauth/token` with that
  /// `client_id`, so a wrong value ends the session at its first refresh.
  Future<AuthState> completeSignIn(
    Map<String, Object?> body, {
    required String? oauthClientId,
  }) => _completeSignIn(body, oauthClientId: oauthClientId);

  Future<AuthState> _completeSignIn(
    Map<String, Object?> body, {
    String? oauthClientId,
  }) async {
    final access = body['access_token'] as String?;
    final refresh = body['refresh_token'] as String?;
    if (access == null || refresh == null) {
      return _emitErrorState(
        const SdkError(
          code: SdkErrorCode.signInFailed,
          reason: SdkErrorReason.unknown,
          errorMessage: 'token_missing',
        ),
      );
    }
    if (!await _verifyToken(access)) {
      return _emitErrorState(
        const SdkError(
          code: SdkErrorCode.signInFailed,
          reason: SdkErrorReason.unknown,
          errorMessage: 'access_token_verify_failed',
        ),
      );
    }
    try {
      // The client marker goes first, so a stored refresh token is never
      // paired with another session's marker; if it cannot be written the
      // refresh token is not stored either.
      await adapter.storageDelete(oauthClientIdKey(tenantId));
      if (oauthClientId != null) {
        await adapter.storageWrite(oauthClientIdKey(tenantId), oauthClientId);
      }
      await adapter.storageWrite(refreshTokenKey(tenantId), refresh);
    } catch (e) {
      await adapter.storageDelete(refreshTokenKey(tenantId));
      return _emitErrorState(
        SdkError(
          code: SdkErrorCode.storageError,
          reason: SdkErrorReason.unknown,
          errorMessage: 'storage_write_failed',
          cause: e,
        ),
      );
    }
    // A new session from sign-in: any restore left pending by a transiently
    // failed cold start is moot, and a Retry-After hold that applied to the
    // previous refresh token does not apply to this one.
    _restorePending = false;
    _refreshHeldUntil = null;
    _refreshHeldError = null;
    _accessToken = access;
    _session = _sessionFromAccessToken(access);
    _user = _placeholderUserFromToken(access);
    await adapter.storageWrite(userKey(tenantId), jsonEncode(_user!.toJson()));
    _setState(AuthStateAuthenticated(_user!, _session!));
    _emit(AuthEventType.signedIn, AuthEventSeverity.info);
    unawaited(_refreshUserSnapshot());
    return _state;
  }

  /// `POST /v1/auth/logout` is `jwtAuth()`-guarded and reads NOTHING from
  /// the body (session/user come from the access token the middleware
  /// verified). A DPoP-bound access token travels as `DPoP` with a proof.
  Future<void> _logoutFirstParty(String accessToken) async {
    try {
      final url = '$apiBaseUrl/v1/auth/logout';
      var headers = <String, String>{'Authorization': 'Bearer $accessToken'};
      final session = _dpopSession;
      if (session != null && session.isBound) {
        final proof = await session.resolveProof('POST', url);
        headers = <String, String>{
          'Authorization': 'DPoP $accessToken',
          'DPoP': proof,
        };
      }
      await _http.postJson(
        Uri.parse(url),
        const <String, Object?>{},
        headers: headers,
      );
    } catch (_) {
      /* best-effort */
    }
  }

  /// RFC 7009 revocation of an OAuth client session's refresh token: a public
  /// client authenticates by its `client_id` alone. Ends the server session
  /// even when no access token is held.
  Future<void> _revokeClientRefreshToken(
    String refreshToken,
    String clientId,
  ) async {
    try {
      await _http
          .postForm(Uri.parse('$apiBaseUrl/oauth/revoke'), <String, String>{
            'token': refreshToken,
            'token_type_hint': 'refresh_token',
            'client_id': clientId,
          });
    } catch (_) {
      /* best-effort */
    }
  }

  /// A refresh failed without ending the session: a transient failure (status
  /// `0` for a transport failure, 5xx/429/408) or a 4xx that is not a
  /// definitive rejection. The stored refresh token and any DPoP binding are
  /// kept. A held session stays authenticated; any other state (a cold start)
  /// settles on the typed error so the app is not left waiting.
  void _failRefreshKeepingSession(
    Completer<Session> completer, {
    required int status,
    String? oauthError,
    String? retryAfterHeader,
  }) {
    final now = DateTime.now();
    final transient =
        classifyRefreshFailure(status, oauthError) ==
        RefreshFailureKind.transient;
    final retryAfter = transient
        ? parseRetryAfter(retryAfterHeader, now)
        : null;
    final err = SdkError(
      code: transient ? SdkErrorCode.networkError : SdkErrorCode.refreshFailed,
      reason: transient ? SdkErrorReason.network : SdkErrorReason.unknown,
      errorMessage: status == 0 ? 'network_failure' : 'http_$status',
      httpStatus: status == 0 ? null : status,
      retryAfter: retryAfter,
    );
    if (retryAfter != null && retryAfter > Duration.zero) {
      _refreshHeldUntil = now.add(refreshHoldFor(retryAfter));
      _refreshHeldError = err;
    }
    _emit(
      AuthEventType.refreshFailed,
      AuthEventSeverity.warning,
      errorMessage: err.errorMessage,
    );
    if (_state is! AuthStateAuthenticated) {
      _setState(AuthStateError(err));
    }
    completer.completeError(err);
  }

  Future<void> _localSignOut() async {
    _restorePending = false;
    _accessToken = null;
    _session = null;
    _user = null;
    await adapter.storageDelete(refreshTokenKey(tenantId));
    await adapter.storageDelete(oauthClientIdKey(tenantId));
    await adapter.storageDelete(userKey(tenantId));
    await adapter.storageDelete(sessionKey(tenantId));
    // sibling RakomiProvider mounts (other
    // tenants) MUST be unaffected. Storage keys are tenant-scoped, so we
    // only nuke this tenant's data.
    await jwksCache.invalidate();
    _setState(const AuthStateUnauthenticated());
  }

  AuthStateError _emitErrorState(SdkError error) {
    _emit(
      AuthEventType.signInFailed,
      AuthEventSeverity.security,
      errorMessage: error.toString(),
    );
    final s = AuthStateError(error);
    _setState(s);
    return s;
  }

  /// Internal seam — exposed to extensions (oauth, mfa). NOT part of the
  /// public surface.
  void emitAppState(
    AuthEventType type,
    AuthEventSeverity severity, {
    String? errorMessage,
    Map<String, Object?>? metadata,
  }) {
    _emit(type, severity, errorMessage: errorMessage, metadata: metadata);
  }

  /// Internal seam — exposed to extensions (oauth, mfa). NOT part of the
  /// public surface.
  void setState(AuthState s) => _setState(s);

  void _setState(AuthState s) {
    _state = s;
    _statesController.add(s);
    notifyListeners();
  }

  void _emit(
    AuthEventType type,
    AuthEventSeverity severity, {
    String? errorMessage,
    Map<String, Object?>? metadata,
  }) {
    _eventsController.add(
      AuthEvent(
        type: type,
        severity: severity,
        errorMessage: errorMessage,
        metadata: metadata,
      ),
    );
  }

  @override
  void dispose() {
    _statesController.close();
    _eventsController.close();
    super.dispose();
  }
}

class _NoRefreshToken implements Exception {
  const _NoRefreshToken();
  @override
  String toString() => 'No refresh token persisted';
}

/// Normalized outcome of one refresh exchange — either an HTTP status (+ 200
/// body) for the common path, or a [DpopRefreshError] for the bound-path
/// three-class taxonomy. `statusCode == 0` with no [dpopError] is a network
/// failure on the Bearer branch.
/// Case-insensitive header lookup (RFC 9110 §5.1). `dart:io` lower-cases
/// response header names; other clients need not.
String? _headerOf(http.Response response, String lowerName) {
  final direct = response.headers[lowerName];
  if (direct != null) return direct;
  for (final e in response.headers.entries) {
    if (e.key.toLowerCase() == lowerName) return e.value;
  }
  return null;
}

class _RefreshExchange {
  const _RefreshExchange({
    required this.statusCode,
    this.body,
    this.dpopError,
    this.oauthError,
    this.retryAfter,
    this.uncertainAfterStatus,
    this.networkFailure = false,
  });

  final int statusCode;
  final Map<String, Object?>? body;
  final DpopRefreshError? dpopError;
  final String? oauthError;
  final String? retryAfter;

  /// Set when the refresh outcome is unknown: the first request failed with
  /// this status ([_noResponseStatus] when no response arrived) and the one
  /// immediate retry did not settle it.
  final int? uncertainAfterStatus;

  /// `true` when no response arrived (a transport failure).
  final bool networkFailure;
}

/// The status a refresh exchange carries when no response arrived.
const int _noResponseStatus = 0;
