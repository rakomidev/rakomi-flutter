import 'dart:async';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:http/http.dart' as http;

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../auth/auth_state.dart';
import '../auth/errors.dart';
import '../auth/social_provider.dart';
import '../internal/http_client.dart';
import '../internal/version.dart';
import 'oauth_state.dart';

/// OAuth/PKCE flow orchestration — standard RFC 8252 browser-based
/// Authorization Code + PKCE (RFC 7636 S256), the SAME contract
/// `@rakomi/react-native`'s `startSocialSignIn` uses:
///
/// 1. Resolve the hosted-login `authorization_endpoint` — live OIDC
///    discovery (`GET {apiBaseUrl}/.well-known/openid-configuration`) first,
///    falling back to the platform's `api.` → `accounts.` host-naming
///    convention (frozen path `/authorize`) only when discovery is
///    unreachable. The routing host that answers `/v1/auth/*` is NOT always
///    the host that renders a login page — sending the system browser to
///    the wrong one lands on a JSON API response instead of a login form.
/// 2. Open the system browser (`RakomiNativeAdapter.launchSystemBrowser`) at
///    `{authorization_endpoint}?response_type=code&client_id=…&redirect_uri=
///    …&state=…&code_challenge=…&code_challenge_method=S256&provider=…`.
/// 3. On the redirect callback, validate `state` (persisted, single-use,
///    constant-time) and the optional `iss` (RFC 9700 §4.4 mix-up defense).
/// 4. Exchange the code at `POST {apiBaseUrl}/oauth/token`
///    (`application/x-www-form-urlencoded`, RFC 6749 §4.1.3) —
///    `grant_type=authorization_code`, `code`, `code_verifier`,
///    `redirect_uri`, `client_id`. No `X-API-Key`: a PUBLIC OAuth client
///    proves itself with PKCE alone (RFC 6749 §2.1 + OAuth 2.1 §4.1.1), the
///    same as every other Rakomi SDK's browser flow.
///
/// **Fails closed** when `RakomiAuth.clientId` is not configured — no
/// browser is opened and no network call is made; the caller gets a typed
/// `SdkError(code: invalidConfig)` instead of a browser session that can
/// never complete. `RakomiSignInForm`/`RakomiSignInButton` check the same
/// condition to avoid rendering a button that would only hit this path.
extension RakomiOAuthFlow on RakomiAuth {
  Future<AuthState> signInWithProviderImpl(
    SocialProvider provider, {
    required String redirectUri,
  }) async {
    final id = clientId;
    if (id == null || id.isEmpty) {
      return _failClosed('oauth_client_id_missing');
    }

    emitAppState(
      AuthEventType.signInAttempted,
      AuthEventSeverity.info,
      metadata: <String, Object?>{'provider': provider.wire},
    );

    final inner = adapter.httpClient;
    if (inner is! http.Client) {
      throw StateError('Adapter httpClient must be a package:http Client');
    }
    final httpClient = RakomiHttpClient(
      inner,
      userAgent: rakomiFlutterUserAgent,
    );

    final resolved = await _resolveAuthorizationEndpoint(
      httpClient,
      apiBaseUrl,
    );
    final endpoint = resolved.endpoint;
    if (endpoint == null) {
      return _failClosed(
        resolved.error ?? 'oauth_authorization_endpoint_unresolved',
      );
    }

    final persisted = PersistedOAuthState(tenantId: tenantId, adapter: adapter);
    final bundle = await persisted.begin();

    // RFC 6749 §4.1.1 authorization request + RFC 7636 PKCE. `provider` is an
    // OPTIONAL hint (mirrors `@rakomi/sdk-core`'s `buildAuthorizationUrl`) —
    // the hosted login page renders its own picker regardless.
    final base = Uri.parse(endpoint);
    final authorizeUrl = base.replace(
      queryParameters: <String, String>{
        ...base.queryParameters,
        'response_type': 'code',
        'client_id': id,
        'redirect_uri': redirectUri,
        'state': bundle.state,
        'code_challenge': bundle.challenge,
        'code_challenge_method': 'S256',
        'provider': provider.wire,
      },
    );

    final String callbackUrl;
    try {
      final scheme = Uri.parse(redirectUri).scheme;
      callbackUrl = await adapter.launchSystemBrowser(
        authorizeUrl,
        callbackScheme: scheme,
      );
    } on Exception catch (e) {
      final msg = '$e';
      final reason =
          msg.contains('CANCELED') ||
              msg.contains('CANCELLED') ||
              msg.contains('cancel')
          ? SdkErrorReason.oauthUserCancelled
          : SdkErrorReason.oauthProviderError;
      final state = AuthStateError(
        SdkError(
          code: SdkErrorCode.oauthCallbackError,
          reason: reason,
          errorMessage: reason == SdkErrorReason.oauthUserCancelled
              ? null
              : 'system_browser_unavailable',
        ),
      );
      setState(state);
      emitAppState(
        AuthEventType.signInFailed,
        AuthEventSeverity.security,
        errorMessage: state.error.toString(),
      );
      return state;
    }

    return _consumeCallback(
      callback: Uri.parse(callbackUrl),
      persisted: persisted,
      oneTimeId: bundle.oneTimeId,
      redirectUri: redirectUri,
      clientId: id,
    );
  }

  /// Fail closed: no browser opened, no network call made. Typed, emitted,
  /// audited — never a thrown exception (`errors.dart`'s own contract).
  AuthState _failClosed(String errorMessage) {
    final state = AuthStateError(
      SdkError(
        code: SdkErrorCode.invalidConfig,
        reason: SdkErrorReason.unknown,
        errorMessage: errorMessage,
      ),
    );
    setState(state);
    emitAppState(
      AuthEventType.signInFailed,
      AuthEventSeverity.warning,
      errorMessage: errorMessage,
    );
    return state;
  }

  Future<AuthState> _consumeCallback({
    required Uri callback,
    required PersistedOAuthState persisted,
    required String oneTimeId,
    required String redirectUri,
    required String clientId,
  }) async {
    final params = callback.queryParameters;
    final providerError = params['error'];
    if (providerError != null) {
      final state = AuthStateError(
        SdkError(
          code: SdkErrorCode.oauthCallbackError,
          reason: SdkErrorReason.oauthProviderError,
          providerError: providerError,
          errorMessage: params['error_description'],
        ),
      );
      setState(state);
      return state;
    }

    final code = params['code'];
    final returnedState = params['state'];
    // The callback carries `code`/`state` per RFC 6749 §4.1.2 — never a
    // `one_time_id` (that was this SDK's own, since-removed bespoke
    // endpoint's invention). The in-flight `oneTimeId` this method was
    // called with is the correlation key; it is a local variable, never
    // read off the (attacker-influenced) callback URL.
    if (code == null || returnedState == null) {
      const state = AuthStateError(
        SdkError(
          code: SdkErrorCode.oauthCallbackError,
          reason: SdkErrorReason.oauthMissingParams,
        ),
      );
      setState(state);
      return state;
    }

    // RFC 9700 §4.4 mix-up defense: validate `iss` if present.
    final iss = params['iss'];
    if (iss != null && iss != issuer) {
      const state = AuthStateError(
        SdkError(
          code: SdkErrorCode.oauthCallbackError,
          reason: SdkErrorReason.oauthStateMismatch,
          errorMessage: 'iss_mismatch',
        ),
      );
      setState(state);
      return state;
    }

    final validation = await persisted.validateAndConsume(
      oneTimeId: oneTimeId,
      callbackState: returnedState,
    );
    if (!validation.ok) {
      const state = AuthStateError(
        SdkError(
          code: SdkErrorCode.csrfMismatch,
          reason: SdkErrorReason.oauthStateMismatch,
        ),
      );
      setState(state);
      return state;
    }

    // Exchange the code at the standard RFC 6749 §4.1.3 token endpoint —
    // form-urlencoded, PKCE `code_verifier` in place of a client secret.
    try {
      final inner = adapter.httpClient;
      if (inner is! http.Client) {
        throw StateError('Adapter httpClient must be a package:http Client');
      }
      final r = await RakomiHttpClient(inner, userAgent: rakomiFlutterUserAgent)
          .postForm(Uri.parse('$apiBaseUrl/oauth/token'), <String, String>{
            'grant_type': 'authorization_code',
            'code': code,
            'code_verifier': validation.verifier!,
            'redirect_uri': redirectUri,
            'client_id': clientId,
          });
      if (r.statusCode != 200) {
        String? oauthError;
        String? oauthErrorDescription;
        try {
          final body = decodeJsonBody(r);
          oauthError = body['error'] as String?;
          oauthErrorDescription = body['error_description'] as String?;
        } catch (_) {
          /* non-JSON error body */
        }
        final state = AuthStateError(
          SdkError(
            code: SdkErrorCode.codeExchangeFailed,
            reason: SdkErrorReason.network,
            providerError: oauthError,
            errorMessage: oauthErrorDescription ?? 'http_${r.statusCode}',
          ),
        );
        setState(state);
        return state;
      }
      // The session is this client's: it refreshes at /oauth/token with it.
      return completeSignIn(decodeJsonBody(r), oauthClientId: clientId);
    } catch (e) {
      final state = AuthStateError(
        SdkError(
          code: SdkErrorCode.codeExchangeFailed,
          reason: SdkErrorReason.network,
          errorMessage: '$e',
        ),
      );
      setState(state);
      return state;
    }
  }
}

/// Resolve the `authorization_endpoint` a browser navigation must target.
/// Never throws; a resolution failure comes back as `error`, never a guess.
Future<({String? endpoint, String? error})> _resolveAuthorizationEndpoint(
  RakomiHttpClient http,
  String apiBaseUrl,
) async {
  try {
    final r = await http.getJson(
      Uri.parse('$apiBaseUrl/.well-known/openid-configuration'),
    );
    if (r.statusCode == 200) {
      final doc = decodeJsonBody(r);
      final endpoint = doc['authorization_endpoint'];
      if (endpoint is String && endpoint.isNotEmpty) {
        return (endpoint: endpoint, error: null);
      }
    }
  } catch (_) {
    // Live discovery unreachable/malformed — fall through to the
    // deterministic fallback below.
  }
  final fallback = _deriveAccountsAuthorizeFallback(apiBaseUrl);
  if (fallback != null) return (endpoint: fallback, error: null);
  return (
    endpoint: null,
    error: 'oauth_authorization_endpoint_unresolved: $apiBaseUrl',
  );
}

/// Deterministic `api.` → `accounts.` host-naming fallback (frozen path
/// `/authorize`), used ONLY when live discovery is unreachable. Never
/// invents a mapping — a host whose leading label is not `api` has no
/// documented convention to fall back to.
String? _deriveAccountsAuthorizeFallback(String apiBaseUrl) {
  final uri = Uri.tryParse(apiBaseUrl);
  if (uri == null || uri.host.isEmpty) return null;
  if (!RegExp(r'^api([.-]|$)').hasMatch(uri.host)) return null;
  final accountsHost = uri.host.replaceFirst(RegExp('^api'), 'accounts');
  final portSuffix = uri.hasPort ? ':${uri.port}' : '';
  return 'https://$accountsHost$portSuffix/authorize';
}

/// Public facade for `RakomiAuth.signInWithProvider`. Resolves the redirect
/// URI from the configured provider, validates the platform-conditional
/// scheme guard, and delegates to [RakomiOAuthFlow.signInWithProviderImpl].
Future<AuthState> performSocialSignIn(
  RakomiAuth auth,
  SocialProvider provider, {
  required String redirectUri,
}) async {
  // Platform-conditional scheme guard.
  // - Mobile (iOS/Android): scheme MUST be a custom URL scheme; reject
  //   http/https/javascript/data/file/vbscript/about.
  // - Web: https:// is permitted (popup `postMessage` flow).
  // - All platforms: javascript/data/file/vbscript/about always rejected.
  final uri = Uri.tryParse(redirectUri);
  if (uri == null) {
    throw ArgumentError.value(redirectUri, 'redirectUri', 'Not a valid URI');
  }
  final scheme = uri.scheme.toLowerCase();
  const banned = <String>{'javascript', 'data', 'file', 'vbscript', 'about'};
  if (banned.contains(scheme)) {
    throw ArgumentError.value(
      redirectUri,
      'redirectUri',
      'Banned scheme: $scheme',
    );
  }
  if (!kIsWeb) {
    if (scheme == 'http' || scheme == 'https') {
      throw ArgumentError.value(
        redirectUri,
        'redirectUri',
        'On mobile/desktop, redirectUri MUST be a custom URL scheme — got $scheme',
      );
    }
  }
  return auth.signInWithProviderImpl(provider, redirectUri: redirectUri);
}
