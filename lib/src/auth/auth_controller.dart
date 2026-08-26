import 'dart:async';
import 'dart:convert' show base64Url, jsonDecode, jsonEncode, utf8;

import 'package:flutter/foundation.dart' show ChangeNotifier;
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart' show parseHttpDate;

import '../internal/http_client.dart';
import '../internal/jwks_cache.dart';
import '../internal/jwt_verify.dart';
import '../internal/storage_keys.dart';
import '../native/adapter.dart';
import 'auth_event.dart';
import 'auth_state.dart';
import 'dpop_refresh.dart';
import 'dpop_session.dart';
import 'errors.dart';
import 'social_provider.dart';
import 'user.dart';

/// Refresh lead-time. The controller proactively refreshes a session when the
/// access-token's `exp` claim is within this window.
const Duration kDefaultRefreshLeadtime = Duration(seconds: 60);

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
    Duration refreshLeadtime = kDefaultRefreshLeadtime,
    Duration freshAuthWindow = const Duration(seconds: 30),
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
  final RakomiNativeAdapter adapter;
  final JwksCache jwksCache;
  final Duration _refreshLeadtime;
  // ignore: unused_field
  final Duration _freshAuthWindow;

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

  int _clockSkewMs = 0;
  bool _clockSkewLoaded = false;

  RakomiHttpClient get _http {
    final inner = adapter.httpClient;
    if (inner is! http.Client) {
      throw StateError('Adapter httpClient must be a package:http Client');
    }
    return RakomiHttpClient(inner, userAgent: 'rakomi_flutter/0.1.0');
  }

  AuthState get authState => _state;
  Stream<AuthState> get authStateChanges => _statesController.stream;
  Stream<AuthEvent> get events => _eventsController.stream;

  User? get user => _user;
  Session? get session => _session;

  Future<void> hydrate() async {
    try {
      final userJson = await adapter.storageRead(userKey(tenantId));
      final hasRefresh = await adapter.storageRead(refreshTokenKey(tenantId));
      if (hasRefresh == null) {
        _setState(const AuthStateUnauthenticated());
        _emit(AuthEventType.restoreFailed, AuthEventSeverity.info);
        return;
      }
      // Try to restore in-memory snapshot from cached user. Session is
      // re-derived from the next refresh — we do NOT trust persisted session
      // metadata for `exp` enforcement.
      if (userJson != null) {
        _user = User.fromJson(jsonDecode(userJson) as Map<String, Object?>);
      }
      // Force a refresh to validate the persisted refresh token end-to-end.
      try {
        await _refresh();
        if (_state is AuthStateAuthenticated) {
          _emit(AuthEventType.restoreSucceeded, AuthEventSeverity.info);
        }
      } catch (_) {
        await _localSignOut();
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
  Future<String?> getToken() async {
    final token = _accessToken;
    final session = _session;
    if (token != null &&
        session != null &&
        !session.isExpiringSoon(leadtime: _refreshLeadtime)) {
      return token;
    }
    await _refresh();
    return _accessToken;
  }

  /// Force a refresh — useful for AppState.resumed paths.
  Future<Session?> refreshTokens() => _refresh();

  Future<AuthState> signIn({required String email, required String password}) {
    _emit(AuthEventType.signInAttempted, AuthEventSeverity.info);
    return _signInPasswordFlow(email: email, password: password);
  }

  Future<AuthState> signUp({required String email, required String password}) {
    _emit(AuthEventType.signInAttempted, AuthEventSeverity.info);
    return _signUpFlow(email: email, password: password);
  }

  Future<void> signOut() async {
    final refresh = await adapter.storageRead(refreshTokenKey(tenantId));
    if (refresh != null) {
      unawaited(_revokeServerSide(refresh));
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
      'from `package:rakomi_flutter/src/oauth/mfa.dart`.',
    );
  }

  Future<AuthState> signInWithMagicLink(String email) async {
    final r = await _http.postJson(
      Uri.parse('$apiBaseUrl/v1/auth/magic-link/send'),
      <String, Object?>{'email': email},
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
    final r = await _http.postJson(
      Uri.parse('$apiBaseUrl/v1/auth/email-otp/send'),
      <String, Object?>{'email': email},
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
      await hydrate();
      return _state is AuthStateAuthenticated;
    }
    final reasonEnum = switch (result) {
      BiometricCancelled() => SdkErrorReason.biometricCancelled,
      BiometricLockout() => SdkErrorReason.biometricLockout,
      BiometricNotEnrolled() => SdkErrorReason.biometricNotEnrolled,
      BiometricUnavailable() => SdkErrorReason.biometricUnavailable,
      BiometricSuccess() => SdkErrorReason.unknown,
    };
    _emit(AuthEventType.biometricFailed, AuthEventSeverity.security);
    _setState(
      AuthStateError(
        SdkError(code: SdkErrorCode.biometricError, reason: reasonEnum),
      ),
    );
    return false;
  }

  // ─── Internals ──────────────────────────────────────────────────────── //

  Future<Session?> _refresh() async {
    if (_refreshInFlight != null) return _refreshInFlight!.future;
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
      final exchange = await _performRefreshExchange(token);

      // A DPoP signer failure is terminal — NEVER a silent proof-less Bearer
      // retry. Surface it as a distinct, rollback-actionable error.
      if (exchange.dpopError != null) {
        final dpopErr = exchange.dpopError!;
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: dpopErr.code,
        );
        // `invalid_dpop_proof` (incl. cold-start re-bind) /
        // `invalid_refresh_token` ⇒ full local sign-out → re-login re-binds a
        // fresh key. `dpop_prover_unavailable` ⇒ same (no usable session).
        if (dpopErr.errorClass != DpopRefreshErrorClass.network) {
          await _localSignOut();
        }
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
      if (status == 401 || status == 403) {
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.security,
          errorMessage: 'auth_error_$status',
        );
        await _localSignOut();
        completer.completeError(
          SdkError(
            code: SdkErrorCode.refreshFailed,
            reason: status == 401
                ? SdkErrorReason.refreshExpired
                : SdkErrorReason.refreshRevoked,
          ),
        );
        return null;
      }
      if (status != 200) {
        _emit(
          AuthEventType.refreshFailed,
          AuthEventSeverity.warning,
          errorMessage: 'http_$status',
        );
        completer.completeError(
          const SdkError(
            code: SdkErrorCode.networkError,
            reason: SdkErrorReason.network,
          ),
        );
        return null;
      }
      final body = exchange.body!;
      final accessToken = body['access_token'] as String?;
      final refreshToken = body['refresh_token'] as String? ?? token;
      if (accessToken == null) {
        completer.completeError(
          const SdkError(
            code: SdkErrorCode.refreshFailed,
            reason: SdkErrorReason.unknown,
            errorMessage: 'access_token_missing',
          ),
        );
        return null;
      }
      if (!await _verifyToken(accessToken)) {
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
      _setState(AuthStateAuthenticated(_user!, _session!));
      _emit(AuthEventType.refreshSucceeded, AuthEventSeverity.info);
      completer.complete(_session!);
      return _session;
    } catch (e, st) {
      if (!completer.isCompleted) completer.completeError(e, st);
      return null;
    } finally {
      _refreshInFlight = null;
    }
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
    final endpoint = '$apiBaseUrl/v1/auth/refresh';

    // The poster performs ONE HTTP attempt: optionally with a `DPoP` proof header.
    // It captures clock skew, reads the `DPoP-Nonce` response header, and decodes
    // the RFC 6749 §5.2 `error` from a non-200 body. NEVER logs token/proof bytes.
    Future<TokenPostResult> post({
      required String refreshToken,
      String? dpopProof,
    }) async {
      late final http.Response response;
      try {
        response = await _http.postJson(
          Uri.parse(endpoint),
          <String, Object?>{'refresh_token': refreshToken},
          headers: dpopProof != null
              ? <String, String>{'DPoP': dpopProof}
              : null,
        );
      } catch (_) {
        return const TokenPostResult(statusCode: 0, networkFailure: true);
      }
      _captureClockSkew(response);
      final nonce = response.headers['dpop-nonce'];
      if (response.statusCode == 200) {
        final body = decodeJsonBody(response);
        return TokenPostResult(
          statusCode: 200,
          tokenType: body['token_type'] as String?,
          accessToken: body['access_token'] as String?,
          refreshToken: body['refresh_token'] as String?,
          dpopNonce: nonce,
        );
      }
      String? oauthError;
      try {
        final body = decodeJsonBody(response);
        oauthError = body['error'] as String?;
      } catch (_) {
        /* non-JSON error body */
      }
      return TokenPostResult(
        statusCode: response.statusCode,
        oauthError: oauthError,
        dpopNonce: nonce,
      );
    }

    final session = _dpopSession;
    if (session == null || !session.isBound) {
      // Bearer path — single plain POST, no proof. Preserve the EXACT prior
      // shape (status + parsed 200 body) so downstream verify/persist is identical.
      final result = await post(refreshToken: refreshToken);
      if (result.networkFailure) {
        return const _RefreshExchange(statusCode: 0);
      }
      // Still let the session observe a Bearer issuance so a
      // server downgrade is recorded even on the Bearer branch.
      await session?.observeTokenType(result.tokenType, attachedProof: false);
      return _RefreshExchange(
        statusCode: result.statusCode,
        body: result.isOk ? _bodyOf(result) : null,
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
      var result = verifier.verifyRs256(
        token: token,
        jwks: keys,
        clockSkewMs: _clockSkewMs,
      );
      if (result is JwtVerifyError &&
          result.reason == JwtVerifyErrorReason.kidMiss) {
        await jwksCache.invalidate();
        keys = await jwksCache.getKeys(forceRefresh: true);
        result = verifier.verifyRs256(
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
      if (body['next_action'] == 'verify_mfa') {
        _emit(AuthEventType.componentStepChanged, AuthEventSeverity.info);
        return _emitErrorState(
          SdkError(
            code: SdkErrorCode.mfaStepUpRequired,
            reason: SdkErrorReason.unknown,
            errorMessage: body['challenge_id'] as String?,
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
  }) async {
    try {
      final r = await _http.postJson(
        Uri.parse('$apiBaseUrl/v1/auth/register'),
        <String, Object?>{'email': email, 'password': password},
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
      return _completeSignIn(decodeJsonBody(r));
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

  /// Internal: complete a sign-in given an `access_token`/`refresh_token`
  /// response from the API. Used by password / OAuth / magic-link / OTP /
  /// MFA verify paths.
  Future<AuthState> completeSignIn(Map<String, Object?> body) =>
      _completeSignIn(body);

  Future<AuthState> _completeSignIn(Map<String, Object?> body) async {
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
      await adapter.storageWrite(refreshTokenKey(tenantId), refresh);
    } catch (e) {
      return _emitErrorState(
        SdkError(
          code: SdkErrorCode.storageError,
          reason: SdkErrorReason.unknown,
          errorMessage: 'storage_write_failed',
          cause: e,
        ),
      );
    }
    _accessToken = access;
    _session = _sessionFromAccessToken(access);
    _user = _placeholderUserFromToken(access);
    await adapter.storageWrite(userKey(tenantId), jsonEncode(_user!.toJson()));
    _setState(AuthStateAuthenticated(_user!, _session!));
    _emit(AuthEventType.signedIn, AuthEventSeverity.info);
    unawaited(_refreshUserSnapshot());
    return _state;
  }

  Future<void> _revokeServerSide(String refreshToken) async {
    try {
      await _http.postJson(
        Uri.parse('$apiBaseUrl/v1/auth/logout'),
        <String, Object?>{'refresh_token': refreshToken},
      );
    } catch (_) {
      /* best-effort */
    }
  }

  Future<void> _localSignOut() async {
    _accessToken = null;
    _session = null;
    _user = null;
    await adapter.storageDelete(refreshTokenKey(tenantId));
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
class _RefreshExchange {
  const _RefreshExchange({required this.statusCode, this.body, this.dpopError});

  final int statusCode;
  final Map<String, Object?>? body;
  final DpopRefreshError? dpopError;
}
