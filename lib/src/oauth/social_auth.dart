import 'dart:async';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:http/http.dart' as http;

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../auth/auth_state.dart';
import '../auth/errors.dart';
import '../auth/social_provider.dart';
import '../internal/http_client.dart';
import 'oauth_state.dart';

/// OAuth/PKCE flow orchestration. Wires the system browser
/// (`flutter_web_auth_2`), persisted state (`OAuthState`), PKCE primitives,
/// and the `/v1/auth/oauth/callback` token-exchange endpoint.
///
/// Cross-flow parity with `@rakomi/react-native`'s `startSocialSignIn`.
extension RakomiOAuthFlow on RakomiAuth {
  Future<AuthState> signInWithProviderImpl(
    SocialProvider provider, {
    required String redirectUri,
  }) async {
    emitAppState(
      AuthEventType.signInAttempted,
      AuthEventSeverity.info,
      metadata: <String, Object?>{'provider': provider.wire},
    );

    final persisted = PersistedOAuthState(tenantId: tenantId, adapter: adapter);
    final bundle = await persisted.begin();

    // Build authorize URL — server-side handles per-provider authorize-URL
    // construction and redirects to the provider's authorize endpoint. We
    // hand off the system browser to `/v1/auth/oauth/<provider>/start`
    // with our state + code_challenge.
    final start = Uri.parse('$apiBaseUrl/v1/auth/oauth/${provider.wire}/start')
        .replace(
          queryParameters: <String, String>{
            'state': bundle.state,
            'code_challenge': bundle.challenge,
            'code_challenge_method': 'S256',
            'redirect_uri': redirectUri,
            'one_time_id': bundle.oneTimeId,
            'tenant_id': tenantId,
          },
        );

    final String callbackUrl;
    try {
      final scheme = Uri.parse(redirectUri).scheme;
      callbackUrl = await adapter.launchSystemBrowser(
        start,
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
      provider: provider,
      redirectUri: redirectUri,
    );
  }

  Future<AuthState> _consumeCallback({
    required Uri callback,
    required PersistedOAuthState persisted,
    required SocialProvider provider,
    required String redirectUri,
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
    final oneTimeId = params['one_time_id'];
    if (code == null || returnedState == null || oneTimeId == null) {
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

    // Exchange the code via the API's canonical OAuth callback endpoint.
    try {
      final inner = adapter.httpClient;
      if (inner is! http.Client) {
        throw StateError('Adapter httpClient must be a package:http Client');
      }
      final r = await RakomiHttpClient(inner, userAgent: 'rakomi_flutter/0.1.0')
          .postJson(
            Uri.parse('$apiBaseUrl/v1/auth/oauth/callback'),
            <String, Object?>{
              'provider': provider.wire,
              'code': code,
              'code_verifier': validation.verifier,
              'redirect_uri': redirectUri,
              'tenant_id': tenantId,
            },
          );
      if (r.statusCode != 200) {
        final state = AuthStateError(
          SdkError(
            code: SdkErrorCode.codeExchangeFailed,
            reason: SdkErrorReason.network,
            errorMessage: 'http_${r.statusCode}',
          ),
        );
        setState(state);
        return state;
      }
      return completeSignIn(decodeJsonBody(r));
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
