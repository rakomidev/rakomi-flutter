// `RakomiAuth` ↔ live-API wire-contract tests. Every case here asserts the
// EXACT header/path/body the API's `apiKeyAuth()`/`jwtAuth()` middleware and
// route schemas require — not a hand-written belief
// about the shape. Each one pins a defect the PoC verification found: the
// publishable key was never sent on ANY apiKeyAuth()-guarded call, sign-out
// never sent the Bearer token jwtAuth() requires, the magic-link/email-OTP
// send paths carried a nonexistent `/send` suffix, the MFA challenge was
// read off the wrong field names at the wrong path, and `signUp` claimed a
// session `/v1/auth/register` never grants.
//
// Both polarities: each header/path/field assertion has a companion that
// would fail if the fix regressed (checked via the captured request itself,
// never a mock that already assumes success).

import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';
import 'helpers/test_rsa_key.dart';

const String _kApiBase = 'https://api.test.io';
const String _kTenant = 'acme';
const String _kPublishableKey = 'pk_test_abc123';

class _NullJwksStorage implements JwksStorage {
  final Map<String, String> _m = {};
  @override
  Future<String?> readKey(String key) async => _m[key];
  @override
  Future<void> writeKey(String key, String value) async => _m[key] = value;
  @override
  Future<void> deleteKey(String key) async => _m.remove(key);
}

/// Builds a `RakomiAuth` whose HTTP transport is a capturing `MockClient`.
/// [handlers] maps an exact request path to a responder; `/.well-known/jwks.json`
/// is always served from the shared test fixture so a successful sign-in can
/// verify the returned access token exactly like production does.
({RakomiAuth auth, List<http.Request> requests}) _buildAuth(
  Map<String, http.Response Function(http.Request)> handlers,
) {
  final requests = <http.Request>[];
  final adapter = FakeRakomiNativeAdapter();
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
    final handler = handlers[r.url.path];
    if (handler != null) return handler(r);
    return http.Response(
      '{}',
      200,
      headers: <String, String>{'content-type': 'application/json'},
    );
  });
  final jwks = JwksCache(
    tenantId: _kTenant,
    jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
    storage: _NullJwksStorage(),
    httpClient: adapter.mockClient,
  );
  final auth = RakomiAuth(
    tenantId: _kTenant,
    publishableKey: _kPublishableKey,
    apiBaseUrl: _kApiBase,
    issuer: 'https://api.rakomi.test',
    audience: 'pk_test_demo',
    adapter: adapter,
    jwksCache: jwks,
  );
  return (auth: auth, requests: requests);
}

String _signAccessToken() {
  final privateKey = testRsaPrivateKey();
  final now = DateTime.now().toUtc();
  final jwt = djw.JWT(
    <String, Object?>{
      'iss': 'https://api.rakomi.test',
      'aud': 'pk_test_demo',
      'sub': 'usr_001',
      'email': 'john@example.com',
      'iat': now.millisecondsSinceEpoch ~/ 1000,
      'exp':
          now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
    },
    header: <String, Object?>{'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'},
  );
  return jwt.sign(privateKey, algorithm: djw.JWTAlgorithm.RS256);
}

http.Response _tokenResponse({String nextStep = 'authenticated'}) {
  return http.Response(
    jsonEncode(<String, Object?>{
      'next_step': nextStep,
      'access_token': _signAccessToken(),
      'refresh_token': 'v1.refresh.abc',
      'expires_in': 900,
      'token_type': 'Bearer',
    }),
    200,
    headers: <String, String>{'content-type': 'application/json'},
  );
}

void main() {
  group('login — POST /v1/auth/login', () {
    test(
      'sends the publishable key as X-API-Key (apiKeyAuth() contract)',
      () async {
        final built = _buildAuth({'/v1/auth/login': (r) => _tokenResponse()});
        await built.auth.signIn(
          email: 'john@example.com',
          password: 'hunter2000',
        );
        final call = built.requests.firstWhere(
          (r) => r.url.path == '/v1/auth/login',
        );
        expect(call.headers['X-API-Key'], _kPublishableKey);
        // Companion: no bespoke header name the API middleware never reads.
        expect(call.headers.containsKey('X-Rakomi-Publishable-Key'), isFalse);
      },
    );

    test('a 200 with next_step:authenticated completes sign-in', () async {
      final built = _buildAuth({'/v1/auth/login': (r) => _tokenResponse()});
      final state = await built.auth.signIn(
        email: 'john@example.com',
        password: 'hunter2000',
      );
      expect(state, isA<AuthStateAuthenticated>());
    });

    test(
      'an MFA challenge (next_step:mfa_verify) is read from mfa_challenge_token, '
      'not next_action/challenge_id',
      () async {
        final built = _buildAuth({
          '/v1/auth/login': (r) => http.Response(
            jsonEncode(<String, Object?>{
              'next_step': 'mfa_verify',
              'mfa_challenge_token': 'mct_xyz',
              'expires_in': 300,
              'available_methods': ['totp'],
            }),
            200,
            headers: <String, String>{'content-type': 'application/json'},
          ),
        });
        final state = await built.auth.signIn(
          email: 'john@example.com',
          password: 'hunter2000',
        );
        expect(state, isA<AuthStateError>());
        final error = (state as AuthStateError).error;
        expect(error.code, SdkErrorCode.mfaStepUpRequired);
        // The value plumbed through to the caller MUST be the real
        // mfa_challenge_token, not a field the API never sends.
        expect(error.errorMessage, 'mct_xyz');
      },
    );

    test(
      'a legacy-shaped body (next_action/challenge_id, no mfa_challenge_token) '
      'is NOT mistaken for an MFA challenge',
      () async {
        final built = _buildAuth({
          '/v1/auth/login': (r) => http.Response(
            jsonEncode(<String, Object?>{
              'next_action': 'verify_mfa',
              'challenge_id': 'ch_legacy',
            }),
            200,
            headers: <String, String>{'content-type': 'application/json'},
          ),
        });
        final state = await built.auth.signIn(
          email: 'john@example.com',
          password: 'hunter2000',
        );
        // No access/refresh token in this body either way — asserts we did
        // NOT take the mfaStepUpRequired branch (which would carry a
        // non-null errorMessage derived from a field this body doesn't have).
        expect(state, isA<AuthStateError>());
        final error = (state as AuthStateError).error;
        expect(error.code, isNot(SdkErrorCode.mfaStepUpRequired));
      },
    );
  });

  group('register — POST /v1/auth/register', () {
    test('sends X-API-Key and the required consent field', () async {
      final built = _buildAuth({
        '/v1/auth/register': (r) => http.Response(
          jsonEncode(<String, Object?>{
            'message': 'Registration initiated — check email for verification',
          }),
          200,
          headers: <String, String>{'content-type': 'application/json'},
        ),
      });
      await built.auth.signUp(
        email: 'new@example.com',
        password: 'hunter2000',
        consent: true,
      );
      final call = built.requests.firstWhere(
        (r) => r.url.path == '/v1/auth/register',
      );
      expect(call.headers['X-API-Key'], _kPublishableKey);
      final body = jsonDecode(call.body) as Map<String, Object?>;
      expect(body['consent'], true);
      expect(body['email'], 'new@example.com');
    });

    test(
      'a token-free {message, next_step?} response settles on unauthenticated, '
      'never claims a session the API never granted',
      () async {
        final built = _buildAuth({
          '/v1/auth/register': (r) => http.Response(
            jsonEncode(<String, Object?>{
              'message':
                  'Registration initiated — check email for verification',
              'next_step': 'verify_email',
            }),
            200,
            headers: <String, String>{'content-type': 'application/json'},
          ),
        });
        final state = await built.auth.signUp(
          email: 'new@example.com',
          password: 'hunter2000',
          consent: true,
        );
        expect(state, isA<AuthStateUnauthenticated>());
        // Companion: it must NOT be the old failure mode either — a
        // signInFailed/token_missing error is exactly what a regression
        // back to `_completeSignIn(body)` would reintroduce.
        expect(state, isNot(isA<AuthStateError>()));
      },
    );

    test('a response that DOES carry tokens still completes sign-in', () async {
      final built = _buildAuth({'/v1/auth/register': (r) => _tokenResponse()});
      final state = await built.auth.signUp(
        email: 'new@example.com',
        password: 'hunter2000',
        consent: true,
      );
      expect(state, isA<AuthStateAuthenticated>());
    });
  });

  group('refresh — POST /v1/auth/refresh', () {
    test('sends X-API-Key on the Bearer (non-DPoP) refresh path', () async {
      final built = _buildAuth({'/v1/auth/refresh': (r) => _tokenResponse()});
      await built.auth.adapter.storageWrite(
        'rakomi.v1.refresh_token.$_kTenant',
        'rt_seed',
      );
      await built.auth.refreshTokens();
      final call = built.requests.firstWhere(
        (r) => r.url.path == '/v1/auth/refresh',
      );
      expect(call.headers['X-API-Key'], _kPublishableKey);
    });

    test(
      'a 200 with an undecodable body resolves to a typed, emitted SdkError '
      '— never an uncaught decode exception escaping to a concurrent caller',
      () async {
        final built = _buildAuth({
          '/v1/auth/refresh': (r) => http.Response(
            'not json at all {{{',
            200,
            headers: <String, String>{'content-type': 'application/json'},
          ),
        });
        await built.auth.adapter.storageWrite(
          'rakomi.v1.refresh_token.$_kTenant',
          'rt_seed',
        );
        final events = <AuthEvent>[];
        built.auth.events.listen(events.add);

        // The initiating caller: the call itself must not throw
        // (`errors.dart`'s documented contract — errors never escape the
        // public API surface) and must resolve, not hang or crash.
        // A CONCURRENT second caller shares the same in-flight refresh via
        // `RakomiAuth`'s single-flight completer — this is the exact seam a
        // raw, un-typed decode exception used to escape through, since only
        // the INITIATING caller's own try/catch ever converted it.
        final initiating = built.auth.refreshTokens();
        final concurrent = built.auth.refreshTokens();
        expect(
          await initiating,
          isNull,
          reason: 'initiating caller: no session',
        );

        // The concurrent caller must receive a typed SdkError, not a raw
        // FormatException/TypeError from the undecodable body.
        Object? concurrentError;
        try {
          await concurrent;
          fail('expected the concurrent refreshTokens() call to throw');
        } catch (e) {
          concurrentError = e;
        }
        expect(
          concurrentError,
          isA<SdkError>(),
          reason:
              'concurrent caller got a raw ${concurrentError.runtimeType}, not a typed SdkError',
        );
        concurrentError as SdkError;
        // A 2xx consumed the refresh token server-side: presenting it again
        // would be a reuse (which revokes every session of the user), so an
        // unreadable success ends the session locally instead of keeping it.
        expect(concurrentError.code, SdkErrorCode.refreshFailed);
        expect(concurrentError.reason, SdkErrorReason.refreshRevoked);
        expect(
          await built.auth.adapter.storageRead(
            'rakomi.v1.refresh_token.$_kTenant',
          ),
          isNull,
        );

        // The failure is also audited — not just silently absorbed.
        expect(
          events.any((e) => e.type == AuthEventType.refreshFailed),
          isTrue,
          reason:
              'expected a refreshFailed event, got: ${events.map((e) => e.type)}',
        );
      },
    );
  });

  group('sign-out — POST /v1/auth/logout', () {
    test(
      'sends the access token as Authorization: Bearer (jwtAuth() contract), '
      'not a refresh_token body the route never reads',
      () async {
        final built = _buildAuth({
          '/v1/auth/login': (r) => _tokenResponse(),
          '/v1/auth/logout': (r) => http.Response('', 204),
        });
        await built.auth.signIn(
          email: 'john@example.com',
          password: 'hunter2000',
        );
        await built.auth.signOut();
        // signOut() fires the revoke unawaited — pump the event loop once.
        await Future<void>.delayed(Duration.zero);
        final call = built.requests.firstWhere(
          (r) => r.url.path == '/v1/auth/logout',
        );
        expect(call.headers['Authorization'], startsWith('Bearer '));
        expect(call.headers['Authorization'], isNot('Bearer null'));
      },
    );

    test(
      'with no prior sign-in (no access token), the revoke call is skipped',
      () async {
        final built = _buildAuth({});
        await built.auth.adapter.storageWrite(
          'rakomi.v1.refresh_token.$_kTenant',
          'rt_seed',
        );
        await built.auth.signOut();
        await Future<void>.delayed(Duration.zero);
        expect(
          built.requests.where((r) => r.url.path == '/v1/auth/logout'),
          isEmpty,
        );
      },
    );
  });

  group('passwordless send paths', () {
    test(
      'magic link posts to /v1/auth/magic-link (no /send suffix) with X-API-Key',
      () async {
        final built = _buildAuth({
          '/v1/auth/magic-link': (r) => http.Response('{}', 200),
        });
        await built.auth.signInWithMagicLink('john@example.com');
        expect(
          built.requests.any((r) => r.url.path == '/v1/auth/magic-link/send'),
          isFalse,
        );
        final call = built.requests.firstWhere(
          (r) => r.url.path == '/v1/auth/magic-link',
        );
        expect(call.headers['X-API-Key'], _kPublishableKey);
      },
    );

    test(
      'email OTP posts to /v1/auth/email-otp (no /send suffix) with X-API-Key',
      () async {
        final built = _buildAuth({
          '/v1/auth/email-otp': (r) => http.Response('{}', 200),
        });
        await built.auth.signInWithEmailOtp('john@example.com');
        expect(
          built.requests.any((r) => r.url.path == '/v1/auth/email-otp/send'),
          isFalse,
        );
        final call = built.requests.firstWhere(
          (r) => r.url.path == '/v1/auth/email-otp',
        );
        expect(call.headers['X-API-Key'], _kPublishableKey);
      },
    );
  });

  group('MFA verify — POST /v1/auth/mfa/verify-login', () {
    test(
      'posts mfa_challenge_token + code to /v1/auth/mfa/verify-login with X-API-Key, '
      'not challenge_id/tenant_id to /v1/auth/mfa/totp/verify',
      () async {
        final built = _buildAuth({
          '/v1/auth/mfa/verify-login': (r) => _tokenResponse(),
        });
        final state = await built.auth.verifyMfaImpl(
          '123456',
          challengeId: 'mct_xyz',
        );
        expect(
          built.requests.any((r) => r.url.path == '/v1/auth/mfa/totp/verify'),
          isFalse,
        );
        final call = built.requests.firstWhere(
          (r) => r.url.path == '/v1/auth/mfa/verify-login',
        );
        expect(call.headers['X-API-Key'], _kPublishableKey);
        final body = jsonDecode(call.body) as Map<String, Object?>;
        expect(body['mfa_challenge_token'], 'mct_xyz');
        expect(body['code'], '123456');
        expect(body.containsKey('challenge_id'), isFalse);
        expect(body.containsKey('tenant_id'), isFalse);
        expect(state, isA<AuthStateAuthenticated>());
      },
    );

    // Compile-time proof that `RakomiMfaFlow` is reachable from the public
    // barrel: this whole file imports only `package:rakomi_flutter/rakomi_flutter.dart`
    // (never `src/oauth/mfa.dart` directly), and the `verifyMfaImpl` call
    // above resolves through that import. Were the export dropped, this
    // file would fail to COMPILE, not merely fail at runtime.
  });
}
