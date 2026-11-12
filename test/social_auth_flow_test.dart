// Story flutter-poc-app-authenticates-with-rakomi-flutter-sdk (bundle-80), operator follow-up
// 2026-09-06: the social/browser flow called endpoints that never existed
// (`/v1/auth/oauth/<provider>/start`, `/v1/auth/oauth/callback`) — the same class of door the
// iOS PoC recorded and left unfixed. Rewritten to the standard RFC 8252 browser + RFC 7636 PKCE
// contract `@rakomi/react-native`'s `startSocialSignIn` already uses: an authorization request
// to a discovered/derived `authorization_endpoint`, and a form-urlencoded RFC 6749 §4.1.3
// exchange at `POST {apiBaseUrl}/oauth/token`. These tests assert the wire contract AND the
// fail-closed "not configured" behavior end to end.

import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';
import 'helpers/test_rsa_key.dart';

const String _kTenant = 'acme';
const String _kRedirectUri = 'com.rakomi.quickstart://callback';
const String _kIssuer = 'https://api.rakomi.test';
const String _kAudience = 'pk_test_demo';

String _signAccessToken() {
  final privateKey = testRsaPrivateKey();
  final now = DateTime.now().toUtc();
  final jwt = djw.JWT(
    <String, Object?>{
      'iss': _kIssuer,
      'aud': _kAudience,
      'sub': 'usr_001',
      'iat': now.millisecondsSinceEpoch ~/ 1000,
      'exp':
          now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
    },
    header: <String, Object?>{'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'},
  );
  return jwt.sign(privateKey, algorithm: djw.JWTAlgorithm.RS256);
}

class _NullJwksStorage implements JwksStorage {
  final Map<String, String> _m = {};
  @override
  Future<String?> readKey(String key) async => _m[key];
  @override
  Future<void> writeKey(String key, String value) async => _m[key] = value;
  @override
  Future<void> deleteKey(String key) async => _m.remove(key);
}

/// A fake adapter whose `launchSystemBrowser` records the exact authorize URL
/// the SDK built and, unless told to fail, synthesizes a REAL callback that
/// echoes the `state` the SDK generated — exactly what a browser completing
/// a real authorization request would do. This is what lets a test assert
/// the round trip without a live server: the state/PKCE correlation is
/// exercised for real, only the browser and the two HTTP legs are faked.
class _RecordingBrowserAdapter extends FakeRakomiNativeAdapter {
  Uri? capturedAuthorizeUrl;
  String? forcedCallbackQuery;
  Object? forcedLaunchError;

  @override
  Future<String> launchSystemBrowser(
    Uri url, {
    required String callbackScheme,
  }) async {
    capturedAuthorizeUrl = url;
    if (forcedLaunchError != null) throw forcedLaunchError!;
    final state = url.queryParameters['state']!;
    final query = forcedCallbackQuery ?? 'code=auth_code_xyz&state=$state';
    return '$_kRedirectUri?$query';
  }
}

({
  RakomiAuth auth,
  _RecordingBrowserAdapter adapter,
  List<http.Request> requests,
})
_buildAuth({
  required String apiBaseUrl,
  String? clientId,
  Map<String, http.Response Function(http.Request)> handlers = const {},
}) {
  final requests = <http.Request>[];
  final adapter = _RecordingBrowserAdapter();
  final jwksBody = testJwksBody();
  adapter.mockClient = http_test.MockClient((http.Request r) async {
    requests.add(r);
    if (r.url.path == '/.well-known/jwks.json') {
      return http.Response(
        jwksBody,
        200,
        headers: <String, String>{'content-type': 'application/json'},
      );
    }
    if (r.url.path == '/v1/auth/me') {
      return http.Response('{}', 200);
    }
    final handler = handlers[r.url.path];
    if (handler != null) return handler(r);
    return http.Response('{}', 404);
  });
  final jwks = JwksCache(
    tenantId: _kTenant,
    jwksUrl: Uri.parse('$apiBaseUrl/.well-known/jwks.json'),
    storage: _NullJwksStorage(),
    httpClient: adapter.mockClient,
  );
  final auth = RakomiAuth(
    tenantId: _kTenant,
    publishableKey: 'pk_test',
    apiBaseUrl: apiBaseUrl,
    issuer: _kIssuer,
    audience: _kAudience,
    clientId: clientId,
    adapter: adapter,
    jwksCache: jwks,
  );
  return (auth: auth, adapter: adapter, requests: requests);
}

http.Response _discoveryOk(String authorizationEndpoint) => http.Response(
  jsonEncode(<String, Object?>{
    'authorization_endpoint': authorizationEndpoint,
  }),
  200,
  headers: <String, String>{'content-type': 'application/json'},
);

http.Response _tokenOk() => http.Response(
  jsonEncode(<String, Object?>{
    'access_token': _signAccessToken(),
    'refresh_token': 'v1.refresh.oauth',
    'expires_in': 900,
    'token_type': 'Bearer',
  }),
  200,
  headers: <String, String>{'content-type': 'application/json'},
);

void main() {
  group('fail-closed — no configured clientId', () {
    test(
      'signInWithProviderImpl returns invalidConfig, opens no browser, makes no network call',
      () async {
        final built = _buildAuth(apiBaseUrl: 'https://api.example.com');
        final state = await performSocialSignIn(
          built.auth,
          SocialProvider.google,
          redirectUri: _kRedirectUri,
        );
        expect(state, isA<AuthStateError>());
        final error = (state as AuthStateError).error;
        expect(error.code, SdkErrorCode.invalidConfig);
        expect(error.errorMessage, 'oauth_client_id_missing');
        // No browser was launched: the fake adapter's default (no forced
        // result) would throw a DIFFERENT error (oauthCallbackError /
        // oauthUserCancelled) if the flow had reached that call — getting
        // invalidConfig instead proves it never did.
        expect(built.adapter.capturedAuthorizeUrl, isNull);
        expect(built.requests, isEmpty);
      },
    );
  });

  group('authorization_endpoint resolution', () {
    test(
      'live discovery success — the browser is opened at the DISCOVERED endpoint',
      () async {
        final built = _buildAuth(
          apiBaseUrl: 'https://api.example.com',
          clientId: 'oauth_client_test',
          handlers: {
            '/.well-known/openid-configuration': (r) =>
                _discoveryOk('https://accounts.example.com/authorize'),
            '/oauth/token': (r) => _tokenOk(),
          },
        );
        await performSocialSignIn(
          built.auth,
          SocialProvider.google,
          redirectUri: _kRedirectUri,
        );
        final url = built.adapter.capturedAuthorizeUrl;
        expect(url, isNotNull);
        expect(url!.origin, 'https://accounts.example.com');
        expect(url.path, '/authorize');
      },
    );

    test(
      'discovery unreachable — falls back to the api.->accounts. host convention',
      () async {
        final built = _buildAuth(
          apiBaseUrl: 'https://api.example.com',
          clientId: 'oauth_client_test',
          handlers: {
            // discovery 404s — no handler registered for it, default 404.
            '/oauth/token': (r) => _tokenOk(),
          },
        );
        await performSocialSignIn(
          built.auth,
          SocialProvider.google,
          redirectUri: _kRedirectUri,
        );
        final url = built.adapter.capturedAuthorizeUrl;
        expect(url, isNotNull);
        expect(url!.origin, 'https://accounts.example.com');
        expect(url.path, '/authorize');
      },
    );

    test(
      'discovery unreachable AND no api./accounts. convention (e.g. local dev) '
      '— fails closed with a typed error, opens no browser',
      () async {
        final built = _buildAuth(
          apiBaseUrl: 'http://localhost:3001',
          clientId: 'oauth_client_test',
        );
        final state = await performSocialSignIn(
          built.auth,
          SocialProvider.google,
          redirectUri: _kRedirectUri,
        );
        expect(state, isA<AuthStateError>());
        expect(
          (state as AuthStateError).error.code,
          SdkErrorCode.invalidConfig,
        );
        expect(built.adapter.capturedAuthorizeUrl, isNull);
      },
    );
  });

  group('authorize request shape', () {
    test(
      'carries response_type, client_id, redirect_uri, PKCE, and a provider hint',
      () async {
        final built = _buildAuth(
          apiBaseUrl: 'https://api.example.com',
          clientId: 'oauth_client_test',
          handlers: {
            '/.well-known/openid-configuration': (r) =>
                _discoveryOk('https://accounts.example.com/authorize'),
            '/oauth/token': (r) => _tokenOk(),
          },
        );
        await performSocialSignIn(
          built.auth,
          SocialProvider.github,
          redirectUri: _kRedirectUri,
        );
        final params = built.adapter.capturedAuthorizeUrl!.queryParameters;
        expect(params['response_type'], 'code');
        expect(params['client_id'], 'oauth_client_test');
        expect(params['redirect_uri'], _kRedirectUri);
        expect(params['code_challenge_method'], 'S256');
        expect(params['code_challenge'], isNotEmpty);
        expect(params['state'], isNotEmpty);
        expect(params['provider'], 'github');
      },
    );
  });

  group('code exchange — POST /oauth/token', () {
    test(
      'form-urlencoded RFC 6749 §4.1.3 body, no X-API-Key, no tenant_id',
      () async {
        final built = _buildAuth(
          apiBaseUrl: 'https://api.example.com',
          clientId: 'oauth_client_test',
          handlers: {
            '/.well-known/openid-configuration': (r) =>
                _discoveryOk('https://accounts.example.com/authorize'),
            '/oauth/token': (r) => _tokenOk(),
          },
        );
        final state = await performSocialSignIn(
          built.auth,
          SocialProvider.google,
          redirectUri: _kRedirectUri,
        );
        final call = built.requests.firstWhere(
          (r) => r.url.path == '/oauth/token',
        );
        expect(
          call.headers['content-type'],
          startsWith('application/x-www-form-urlencoded'),
        );
        expect(call.headers.containsKey('X-API-Key'), isFalse);
        final body = Uri(query: call.body).queryParameters;
        expect(body['grant_type'], 'authorization_code');
        expect(body['code'], 'auth_code_xyz');
        expect(body['redirect_uri'], _kRedirectUri);
        expect(body['client_id'], 'oauth_client_test');
        expect(body.containsKey('code_verifier'), isTrue);
        expect(body.containsKey('tenant_id'), isFalse);
        expect(state, isA<AuthStateAuthenticated>());
      },
    );

    test(
      'an RFC 6749 §5.2 error body maps to codeExchangeFailed with providerError',
      () async {
        final built = _buildAuth(
          apiBaseUrl: 'https://api.example.com',
          clientId: 'oauth_client_test',
          handlers: {
            '/.well-known/openid-configuration': (r) =>
                _discoveryOk('https://accounts.example.com/authorize'),
            '/oauth/token': (r) => http.Response(
              jsonEncode(<String, Object?>{
                'error': 'invalid_grant',
                'error_description': 'code expired',
              }),
              400,
            ),
          },
        );
        final state = await performSocialSignIn(
          built.auth,
          SocialProvider.google,
          redirectUri: _kRedirectUri,
        );
        expect(state, isA<AuthStateError>());
        final error = (state as AuthStateError).error;
        expect(error.code, SdkErrorCode.codeExchangeFailed);
        expect(error.providerError, 'invalid_grant');
      },
    );
  });
}
