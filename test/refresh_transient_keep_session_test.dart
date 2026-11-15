// A refresh failure only ends the session when the server definitively rejected
// the grant: a 4xx naming `invalid_grant`, `invalid_client`, `invalid_token`,
// `unauthorized_client` or `access_denied`, a 403 naming `user_blocked` or
// `pending_parental_consent`, a bare 401, or a 2xx the SDK cannot use (the
// token was consumed; re-sending it would be a reuse). A 5xx other than 503
// and 521-523 is retried once at once; if that retry does not settle it the
// outcome is unknown and the session ends. A transport failure (no response;
// the answer may have been lost after the rotation) gets the same one retry.
// A 503, 521-523, 429 or 408 is transient: the stored refresh
// token and the DPoP binding are kept, the error is typed (`networkError`, with
// the HTTP status and the server's `Retry-After`), and no further refresh is
// sent before the `Retry-After` instant (capped at 120 s).
//
// Covers the Bearer path, the DPoP-bound path, a cold start, and Retry-After in
// both RFC 9110 forms (delta-seconds and HTTP-date).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:http_parser/http_parser.dart' show formatHttpDate;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/auth/refresh_failure.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';
import 'helpers/test_rsa_key.dart';

const String _kApiBase = 'https://api.rakomi.test';
const String _kTenant = 'acme';
const String _kAudience = 'pk_test_demo';
const String _kRefreshKey = 'rakomi.v1.refresh_token.$_kTenant';
const String _kStoredRefresh = 'rt_stored_credential';

class _MemoryJwksStorage implements JwksStorage {
  final Map<String, String> _m = {};
  @override
  Future<String?> readKey(String key) async => _m[key];
  @override
  Future<void> writeKey(String key, String value) async => _m[key] = value;
  @override
  Future<void> deleteKey(String key) async => _m.remove(key);
}

class _StubSigner implements NativeDpopSigner {
  @override
  Future<({String x, String y})> publicCoordinates() async {
    String coord(int salt) {
      final b = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        b[i] = (salt + i) & 0xff;
      }
      return base64UrlNoPad(b);
    }

    return (x: coord(1), y: coord(2));
  }

  @override
  Future<Uint8List> signEs256(Uint8List signingInput) async {
    final d = sha256.convert(signingInput).bytes;
    final out = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      out[i] = d[i % d.length];
    }
    return out;
  }
}

late djw.RSAPrivateKey _privateKey;
late String _jwksBody;

String _signAccessToken() {
  final now = DateTime.now().toUtc();
  return djw
      .JWT(
        <String, Object?>{
          'iss': _kApiBase,
          'aud': _kAudience,
          'sub': 'usr_001',
          'iat': now.millisecondsSinceEpoch ~/ 1000,
          'exp':
              now.add(const Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
        },
        header: <String, Object?>{'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'},
      )
      .sign(_privateKey, algorithm: djw.JWTAlgorithm.RS256);
}

http.Response _json(
  int status, [
  Map<String, Object?>? body,
  Map<String, String>? headers,
]) => http.Response(
  jsonEncode(body ?? <String, Object?>{}),
  status,
  headers: <String, String>{'content-type': 'application/json', ...?headers},
);

class _Harness {
  _Harness(this.auth, this.adapter, this.refreshCalls, this.events);
  final RakomiAuth auth;
  final FakeRakomiNativeAdapter adapter;
  final List<http.Request> refreshCalls;
  final List<AuthEvent> events;

  Future<String?> storedRefreshToken() => adapter.storageRead(_kRefreshKey);
}

/// [responses] answer successive `POST /v1/auth/refresh` calls in order; the
/// last one repeats.
Future<_Harness> _build(
  List<http.Response Function()> responses, {
  DpopSession? dpopSession,
  http.Response Function()? login,
}) async {
  final calls = <http.Request>[];
  final adapter = FakeRakomiNativeAdapter();
  adapter.mockClient = http_test.MockClient((http.Request r) async {
    if (r.url.path == '/.well-known/jwks.json') {
      return http.Response(
        _jwksBody,
        200,
        headers: <String, String>{'content-type': 'application/json'},
      );
    }
    if (r.url.path == '/v1/auth/refresh') {
      calls.add(r);
      final i = calls.length - 1;
      return responses[i < responses.length ? i : responses.length - 1]();
    }
    if (r.url.path == '/v1/auth/login' && login != null) return login();
    return _json(200);
  });
  await adapter.storageWrite(_kRefreshKey, _kStoredRefresh);
  final auth = RakomiAuth(
    tenantId: _kTenant,
    publishableKey: 'pk_test',
    apiBaseUrl: _kApiBase,
    issuer: _kApiBase,
    audience: _kAudience,
    adapter: adapter,
    jwksCache: JwksCache(
      tenantId: _kTenant,
      jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
      storage: _MemoryJwksStorage(),
      httpClient: adapter.mockClient,
    ),
    dpopSession: dpopSession,
  );
  final events = <AuthEvent>[];
  auth.events.listen(events.add);
  return _Harness(auth, adapter, calls, events);
}

Future<DpopSession> _boundSession() async {
  final s = DpopSession(
    prover: NativeKeystoreDpopProver(signer: _StubSigner()),
    baseUrl: _kApiBase,
  );
  await s.observeTokenType('DPoP', attachedProof: true);
  return s;
}

SdkError _errorOf(AuthState state) {
  expect(state, isA<AuthStateError>());
  return (state as AuthStateError).error;
}

void main() {
  setUpAll(() {
    _privateKey = testRsaPrivateKey();
    _jwksBody = testJwksBody();
  });

  group('Bearer refresh', () {
    test('503 keeps the stored refresh token and never signs out', () async {
      final h = await _build([() => _json(503)]);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), _kStoredRefresh);
      expect(h.auth.authState, isNot(isA<AuthStateUnauthenticated>()));
      h.auth.dispose();
    });

    test('429 is transient and carries the status', () async {
      final h = await _build([() => _json(429)]);
      await h.auth.hydrate();
      final err = _errorOf(h.auth.authState);
      expect(err.code, SdkErrorCode.networkError);
      expect(err.reason, SdkErrorReason.network);
      expect(err.httpStatus, 429);
      expect(await h.storedRefreshToken(), _kStoredRefresh);
      h.auth.dispose();
    });

    test('400 invalid_grant is definitive: signs out', () async {
      final h = await _build([
        () => _json(400, <String, Object?>{'error': 'invalid_grant'}),
      ]);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), isNull);
      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      h.auth.dispose();
    });

    test('bare 401 is definitive: signs out', () async {
      final h = await _build([() => _json(401)]);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), isNull);
      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      h.auth.dispose();
    });

    test('403 without a definitive OAuth error keeps the session', () async {
      final h = await _build([() => _json(403)]);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), _kStoredRefresh);
      expect(h.auth.authState, isNot(isA<AuthStateUnauthenticated>()));
      h.auth.dispose();
    });

    // The API answers a refresh for a blocked account, or one held pending
    // parental consent, with a 403 whose problem+json `code` names the reason
    // (and revokes the session server-side). That is definitive.
    for (final body in <Map<String, Object?>>[
      <String, Object?>{'code': 'auth/user_blocked', 'status': 403},
      <String, Object?>{'code': 'user_blocked'},
      <String, Object?>{
        'error': <String, Object?>{'code': 'auth/user_blocked'},
      },
      <String, Object?>{'code': 'auth/pending_parental_consent'},
    ]) {
      test('403 ${jsonEncode(body)} is definitive: signs out', () async {
        final h = await _build([() => _json(403, body)]);
        await h.auth.refreshTokens();
        expect(await h.storedRefreshToken(), isNull);
        expect(h.auth.authState, isA<AuthStateUnauthenticated>());
        h.auth.dispose();
      });
    }

    test('403 with a code that is not definitive keeps the session', () async {
      final h = await _build([
        () => _json(403, <String, Object?>{'code': 'http/403'}),
      ]);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), _kStoredRefresh);
      expect(h.auth.authState, isNot(isA<AuthStateUnauthenticated>()));
      h.auth.dispose();
    });

    // A 2xx means the server consumed the presented refresh token. Re-sending
    // it would be a reuse, which revokes every session of the user; an
    // unreadable success therefore ends the session locally, with no re-send.
    for (final entry in <String, http.Response Function()>{
      'a non-JSON body': () => http.Response('<html>', 200),
      'no access_token': () =>
          _json(200, <String, Object?>{'refresh_token': 'rt_rotated'}),
    }.entries) {
      test(
        'a 200 with ${entry.key} signs out and never re-sends the token',
        () async {
          final h = await _build([entry.value]);
          await h.auth.refreshTokens();
          expect(await h.storedRefreshToken(), isNull);
          expect(h.auth.authState, isA<AuthStateUnauthenticated>());
          await h.auth.getToken();
          expect(h.refreshCalls, hasLength(1));
          h.auth.dispose();
        },
      );
    }
  });

  group('DPoP-bound refresh', () {
    test('503 keeps the refresh token and the DPoP binding', () async {
      final session = await _boundSession();
      final h = await _build([() => _json(503)], dpopSession: session);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), _kStoredRefresh);
      expect(session.isBound, isTrue);
      expect(h.auth.authState, isNot(isA<AuthStateUnauthenticated>()));
      h.auth.dispose();
    });

    test(
      '503 carrying a DPoP-Nonce is still transient, not a proof rejection',
      () async {
        final session = await _boundSession();
        final h = await _build([
          () => _json(503, null, <String, String>{'dpop-nonce': 'n-1'}),
        ], dpopSession: session);
        await h.auth.refreshTokens();
        expect(await h.storedRefreshToken(), _kStoredRefresh);
        expect(h.auth.authState, isNot(isA<AuthStateUnauthenticated>()));
        expect(
          h.refreshCalls,
          hasLength(1),
          reason: 'a 503 is not a nonce challenge; it is not retried at once',
        );
        h.auth.dispose();
      },
    );

    test('403 auth/user_blocked on a bound session signs out', () async {
      final session = await _boundSession();
      final h = await _build([
        () => _json(403, <String, Object?>{'code': 'auth/user_blocked'}),
      ], dpopSession: session);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), isNull);
      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      h.auth.dispose();
    });

    test(
      'an unreadable 200 on a bound session signs out, no re-send',
      () async {
        final session = await _boundSession();
        final h = await _build([
          // A DPoP-Nonce header on a 2xx is not a challenge: no nonce retry.
          () => http.Response(
            '<html>',
            200,
            headers: <String, String>{'dpop-nonce': 'n-1'},
          ),
        ], dpopSession: session);
        await h.auth.refreshTokens();
        expect(await h.storedRefreshToken(), isNull);
        expect(h.auth.authState, isA<AuthStateUnauthenticated>());
        expect(h.refreshCalls, hasLength(1));
        h.auth.dispose();
      },
    );

    test('400 invalid_grant on a bound session still signs out', () async {
      final session = await _boundSession();
      final h = await _build([
        () => _json(400, <String, Object?>{'error': 'invalid_grant'}),
      ], dpopSession: session);
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), isNull);
      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      h.auth.dispose();
    });
  });

  group('a 5xx after which the token may already be rotated', () {
    http.Response ok([String tokenType = 'Bearer']) =>
        _json(200, <String, Object?>{
          'access_token': _signAccessToken(),
          'refresh_token': 'rt_rotated',
          'token_type': tokenType,
        });

    for (final status in <int>[500, 502, 520]) {
      test('$status is retried once at once with the same refresh token; '
          'the session continues', () async {
        final h = await _build([() => _json(status), ok]);
        await h.auth.refreshTokens();
        expect(h.refreshCalls, hasLength(2));
        for (final r in h.refreshCalls) {
          expect(
            (jsonDecode(r.body) as Map<String, Object?>)['refresh_token'],
            _kStoredRefresh,
          );
        }
        expect(await h.storedRefreshToken(), 'rt_rotated');
        expect(h.auth.authState, isA<AuthStateAuthenticated>());
        h.auth.dispose();
      });

      test('$status twice: the outcome is unknown, the session ends, and '
          'nothing is sent again', () async {
        final h = await _build([() => _json(status), () => _json(status)]);
        await h.auth.hydrate().catchError((Object _) {});
        expect(h.refreshCalls, hasLength(2));
        expect(await h.storedRefreshToken(), isNull);
        expect(h.auth.authState, isA<AuthStateUnauthenticated>());
        expect(
          h.events.map((e) => e.errorMessage),
          contains('refresh_outcome_unknown'),
        );
        await h.auth.refreshTokens();
        expect(h.refreshCalls, hasLength(2), reason: 'never a later resend');
        h.auth.dispose();
      });
    }

    test('500 then a 503 on the retry still ends the session', () async {
      final h = await _build([() => _json(500), () => _json(503)]);
      await h.auth.refreshTokens();
      expect(h.refreshCalls, hasLength(2));
      expect(await h.storedRefreshToken(), isNull);
      h.auth.dispose();
    });

    test('500 then invalid_grant signs out (re-login), never a loop', () async {
      final h = await _build([
        () => _json(500),
        () => _json(400, <String, Object?>{'error': 'invalid_grant'}),
      ]);
      await h.auth.refreshTokens();
      await h.auth.refreshTokens();
      expect(h.refreshCalls, hasLength(2));
      expect(await h.storedRefreshToken(), isNull);
      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      h.auth.dispose();
    });

    for (final status in <int>[503, 522]) {
      test('$status keeps the existing behaviour: one request, the session '
          'and the stored token kept', () async {
        final h = await _build([() => _json(status)]);
        await h.auth.refreshTokens();
        expect(h.refreshCalls, hasLength(1));
        expect(await h.storedRefreshToken(), _kStoredRefresh);
        expect(h.auth.authState, isNot(isA<AuthStateUnauthenticated>()));
        h.auth.dispose();
      });
    }

    test('on a bound session the retry carries a fresh proof (new jti) from '
        'the same key', () async {
      final session = await _boundSession();
      final h = await _build([
        () => _json(502),
        () => ok('DPoP'),
      ], dpopSession: session);
      await h.auth.refreshTokens();
      expect(h.refreshCalls, hasLength(2));
      Map<String, Object?> part(String jwt, int i) {
        final seg = jwt.split('.')[i];
        return jsonDecode(
              utf8.decode(base64Url.decode(base64Url.normalize(seg))),
            )
            as Map<String, Object?>;
      }

      final p1 = h.refreshCalls[0].headers['DPoP']!;
      final p2 = h.refreshCalls[1].headers['DPoP']!;
      expect(part(p2, 1)['jti'], isNot(part(p1, 1)['jti']));
      expect(part(p2, 0)['jwk'], part(p1, 0)['jwk']);
      expect(session.isBound, isTrue);
      h.auth.dispose();
    });

    // rakomi-7bd5de09ea-2 (HQ 2026-10-16): a transport failure is no longer
    // transient on its own — the answer may have been lost after the server
    // rotated the token — so it gets the one immediate retry, never a later one.
    http.Response dropped() => throw const SocketException('connection reset');

    test('a transport failure is retried once at once with the same refresh '
        'token; the session continues', () async {
      final h = await _build([dropped, ok]);
      await h.auth.refreshTokens();
      expect(h.refreshCalls, hasLength(2));
      for (final r in h.refreshCalls) {
        expect(
          (jsonDecode(r.body) as Map<String, Object?>)['refresh_token'],
          _kStoredRefresh,
        );
      }
      expect(await h.storedRefreshToken(), 'rt_rotated');
      expect(h.auth.authState, isA<AuthStateAuthenticated>());
      h.auth.dispose();
    });

    for (final entry in <String, http.Response Function()>{
      'a transport failure': dropped,
      'a 503': () => _json(503),
    }.entries) {
      test('a transport failure then ${entry.key}: the outcome is unknown, '
          'the session ends with refresh_outcome_unknown, nothing is sent '
          'again', () async {
        final h = await _build([dropped, entry.value]);
        Object? error;
        try {
          await h.auth.refreshTokens();
        } catch (e) {
          error = e;
        }
        expect(h.refreshCalls, hasLength(2));
        expect(await h.storedRefreshToken(), isNull);
        expect(h.auth.authState, isA<AuthStateUnauthenticated>());
        expect(
          h.events.map((e) => e.errorMessage),
          contains('refresh_outcome_unknown'),
        );
        if (error != null) {
          expect(error, isA<SdkError>());
          expect((error as SdkError).code, SdkErrorCode.refreshFailed);
          expect(error.errorMessage, 'refresh_outcome_unknown');
          expect(error.httpStatus, isNull, reason: 'no response arrived');
        }
        await h.auth.refreshTokens().catchError((Object _) => null);
        expect(h.refreshCalls, hasLength(2), reason: 'never a later resend');
        h.auth.dispose();
      });
    }

    test('a transport failure then invalid_grant signs out (re-login), never '
        'a loop', () async {
      final h = await _build([
        dropped,
        () => _json(400, <String, Object?>{'error': 'invalid_grant'}),
      ]);
      await h.auth.refreshTokens();
      await h.auth.refreshTokens();
      expect(h.refreshCalls, hasLength(2));
      expect(await h.storedRefreshToken(), isNull);
      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      h.auth.dispose();
    });

    test('on a bound session a transport failure is retried with a fresh '
        'proof (new jti) from the same key', () async {
      final session = await _boundSession();
      final h = await _build([dropped, () => ok('DPoP')], dpopSession: session);
      await h.auth.refreshTokens();
      expect(h.refreshCalls, hasLength(2));
      Map<String, Object?> part(String jwt, int i) {
        final seg = jwt.split('.')[i];
        return jsonDecode(
              utf8.decode(base64Url.decode(base64Url.normalize(seg))),
            )
            as Map<String, Object?>;
      }

      final p1 = h.refreshCalls[0].headers['DPoP']!;
      final p2 = h.refreshCalls[1].headers['DPoP']!;
      expect(part(p2, 1)['jti'], isNot(part(p1, 1)['jti']));
      expect(part(p2, 0)['jwk'], part(p1, 0)['jwk']);
      expect(h.auth.authState, isA<AuthStateAuthenticated>());
      h.auth.dispose();
    });

    test('retry-once statuses are every 5xx except 503 and 521-523', () {
      for (final s in <int>[500, 501, 502, 504, 520, 524, 599]) {
        expect(isRefreshRetryOnceStatus(s), isTrue, reason: '$s');
      }
      for (final s in <int>[503, 521, 522, 523, 429, 408, 400, 200, 0]) {
        expect(isRefreshRetryOnceStatus(s), isFalse, reason: '$s');
      }
    });
  });

  group('cold start', () {
    test('a 503 during hydrate keeps the credential and settles on a typed '
        'transient error; a later getToken() restores the session', () async {
      final h = await _build([
        () => _json(503),
        () => _json(200, <String, Object?>{
          'access_token': _signAccessToken(),
          'refresh_token': 'rt_rotated',
          'token_type': 'Bearer',
        }),
      ]);
      await h.auth.hydrate();

      final err = _errorOf(h.auth.authState);
      expect(err.code, SdkErrorCode.networkError);
      expect(err.httpStatus, 503);
      expect(await h.storedRefreshToken(), _kStoredRefresh);

      final token = await h.auth.getToken();
      expect(token, isNotNull);
      expect(h.auth.authState, isA<AuthStateAuthenticated>());
      expect(await h.storedRefreshToken(), 'rt_rotated');
      await Future<void>.delayed(Duration.zero);
      expect(
        h.events.map((e) => e.type),
        contains(AuthEventType.restoreSucceeded),
        reason: 'the deferred restore completes as a restore',
      );
      h.auth.dispose();
    });
  });

  group('restore after sign-in', () {
    test('a sign-in after a transiently failed restore is not reported as a '
        'restore on the next refresh', () async {
      final h = await _build(
        [
          () => _json(503),
          () => _json(200, <String, Object?>{
            'access_token': _signAccessToken(),
            'refresh_token': 'rt_rotated_2',
            'token_type': 'Bearer',
          }),
        ],
        login: () => _json(200, <String, Object?>{
          'access_token': _signAccessToken(),
          'refresh_token': 'rt_from_sign_in',
          'token_type': 'Bearer',
        }),
      );
      await h.auth.hydrate();
      expect(h.auth.authState, isA<AuthStateError>());

      await h.auth.signIn(email: 'a@example.com', password: 'pw');
      expect(h.auth.authState, isA<AuthStateAuthenticated>());
      await h.auth.refreshTokens();
      expect(await h.storedRefreshToken(), 'rt_rotated_2');
      await Future<void>.delayed(Duration.zero);
      final types = h.events.map((e) => e.type).toList();
      expect(types, contains(AuthEventType.signedIn));
      expect(types, contains(AuthEventType.refreshSucceeded));
      expect(
        types,
        isNot(contains(AuthEventType.restoreSucceeded)),
        reason: 'the session came from sign-in, not from a restore',
      );
      h.auth.dispose();
    });
  });

  group('Retry-After', () {
    test(
      'delta-seconds lands on the error and holds off the next refresh',
      () async {
        final h = await _build([
          () => _json(503, null, <String, String>{'Retry-After': '30'}),
        ]);
        await h.auth.hydrate();
        final err = _errorOf(h.auth.authState);
        expect(err.retryAfter, const Duration(seconds: 30));

        final token = await h.auth.getToken();
        expect(token, isNull);
        expect(
          h.refreshCalls,
          hasLength(1),
          reason: 'no refresh is sent before the Retry-After instant',
        );
        expect(await h.storedRefreshToken(), _kStoredRefresh);
        h.auth.dispose();
      },
    );

    test('an HTTP-date lands on the error as the remaining delay', () async {
      final at = DateTime.now().toUtc().add(const Duration(seconds: 90));
      final h = await _build([
        () => _json(429, null, <String, String>{
          'Retry-After': formatHttpDate(at),
        }),
      ]);
      await h.auth.hydrate();
      final err = _errorOf(h.auth.authState);
      expect(err.retryAfter, isNotNull);
      expect(err.retryAfter!.inSeconds, inInclusiveRange(85, 90));
      h.auth.dispose();
    });

    test('Retry-After: 0 does not hold off the next refresh', () async {
      final h = await _build([
        () => _json(503, null, <String, String>{'Retry-After': '0'}),
      ]);
      await h.auth.hydrate();
      await h.auth.getToken();
      expect(h.refreshCalls, hasLength(2));
      h.auth.dispose();
    });
  });

  group('classification helpers', () {
    test('transient statuses', () {
      for (final s in <int>[0, 408, 429, 500, 502, 503, 504]) {
        expect(
          classifyRefreshFailure(s, null),
          RefreshFailureKind.transient,
          reason: 'status $s',
        );
      }
      // A definitive code on a transient status is still transient.
      expect(
        classifyRefreshFailure(503, 'invalid_grant'),
        RefreshFailureKind.transient,
      );
    });

    test('definitive rejections', () {
      for (final code in <String>[
        'invalid_grant',
        'invalid_client',
        'invalid_token',
        'unauthorized_client',
        'access_denied',
      ]) {
        expect(
          classifyRefreshFailure(400, code),
          RefreshFailureKind.definitive,
          reason: code,
        );
      }
      expect(classifyRefreshFailure(401, null), RefreshFailureKind.definitive);
    });

    test('the refresh endpoint\'s session-ending 403 codes are definitive', () {
      for (final code in <String>['user_blocked', 'pending_parental_consent']) {
        expect(
          classifyRefreshFailure(403, code),
          RefreshFailureKind.definitive,
          reason: code,
        );
      }
    });

    test('refreshErrorCode reads error, code and nested error.code', () {
      expect(
        refreshErrorCode(<String, Object?>{'error': 'invalid_grant'}),
        'invalid_grant',
      );
      expect(
        refreshErrorCode(<String, Object?>{'code': 'auth/user_blocked'}),
        'user_blocked',
      );
      expect(
        refreshErrorCode(<String, Object?>{'code': 'USER_BLOCKED'}),
        'user_blocked',
      );
      expect(
        refreshErrorCode(<String, Object?>{
          'error': <String, Object?>{'code': 'auth/user_blocked'},
        }),
        'user_blocked',
      );
      // Only the `auth/` namespace is dropped.
      expect(
        refreshErrorCode(<String, Object?>{'code': 'billing/user_blocked'}),
        'billing/user_blocked',
      );
      expect(refreshErrorCode(<String, Object?>{}), isNull);
      expect(refreshErrorCode(<String, Object?>{'code': ''}), isNull);
      expect(refreshErrorCode('not a map'), isNull);
    });

    test('a Retry-After hold is capped at 120 s', () {
      expect(maxRefreshRetryAfter, const Duration(seconds: 120));
      expect(refreshHoldFor(const Duration(days: 1)), maxRefreshRetryAfter);
      expect(
        refreshHoldFor(const Duration(seconds: 121)),
        maxRefreshRetryAfter,
      );
      expect(
        refreshHoldFor(const Duration(seconds: 30)),
        const Duration(seconds: 30),
      );
    });

    test('other 4xx are neither', () {
      expect(classifyRefreshFailure(403, null), RefreshFailureKind.rejected);
      expect(
        classifyRefreshFailure(400, 'invalid_request'),
        RefreshFailureKind.rejected,
      );
      expect(classifyRefreshFailure(404, null), RefreshFailureKind.rejected);
    });

    test('Retry-After parsing never invents a delay', () {
      final now = DateTime.utc(2026, 10, 5, 12);
      expect(parseRetryAfter('17', now), const Duration(seconds: 17));
      expect(parseRetryAfter(' 5 ', now), const Duration(seconds: 5));
      expect(
        parseRetryAfter('Mon, 05 Oct 2026 12:01:00 GMT', now),
        const Duration(seconds: 60),
      );
      expect(
        parseRetryAfter('Mon, 05 Oct 2026 11:00:00 GMT', now),
        Duration.zero,
      );
      expect(parseRetryAfter(null, now), isNull);
      expect(parseRetryAfter('', now), isNull);
      expect(parseRetryAfter('soon', now), isNull);
      expect(parseRetryAfter('-5', now), isNull);
    });
  });
}
