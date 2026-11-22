// A session issued to an OAuth client (browser sign-in, authorization code)
// refreshes and ends at the OAuth endpoints, with its client_id.
//
// The API answers `/v1/auth/refresh` for such a session like an unknown token
// (it authenticates no client there), so the SDK records which client made the
// session, keeps that across a cold start, and refreshes it at `/oauth/token`
// (RFC 6749 §6). Sign-out revokes its refresh token at `/oauth/revoke`
// (RFC 7009). A first-party session keeps `/v1/auth/refresh`, and its sign-out
// calls `/v1/auth/logout` with the access token that route reads.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';
import 'helpers/test_rsa_key.dart';

const String _kApiBase = 'https://api.rakomi.test';
const String _kTenant = 'acme';
const String _kAudience = 'pk_test_demo';
const String _kClientId = 'client_browser_app';
const String _kRefreshKey = 'rakomi.v1.refresh_token.$_kTenant';
const String _kClientKey = 'rakomi.v1.oauth_client_id.$_kTenant';

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

String _accessToken() {
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

http.Response _json(int status, [Map<String, Object?>? body]) => http.Response(
  jsonEncode(body ?? <String, Object?>{}),
  status,
  headers: <String, String>{'content-type': 'application/json'},
);

http.Response _tokens({String tokenType = 'Bearer'}) =>
    _json(200, <String, Object?>{
      'access_token': _accessToken(),
      'refresh_token': 'rt_rotated',
      'token_type': tokenType,
      'expires_in': 3600,
    });

Map<String, Object?> _signInBody() => <String, Object?>{
  'access_token': _accessToken(),
  'refresh_token': 'rt_signed_in',
  'token_type': 'Bearer',
  'expires_in': 3600,
};

/// The JSON object in segment [index] of a compact JWT.
Map<String, Object?> _segment(String jwt, int index) {
  final part = jwt.split('.')[index];
  final pad = (4 - part.length % 4) % 4;
  return jsonDecode(utf8.decode(base64Url.decode(part + ('=' * pad))))
      as Map<String, Object?>;
}

class _Harness {
  _Harness(this.auth, this.adapter, this.requests);
  final RakomiAuth auth;
  final FakeRakomiNativeAdapter adapter;
  final List<http.Request> requests;

  List<http.Request> to(String path) =>
      requests.where((r) => r.url.path == path).toList();
}

/// [tokenEndpoint] answers `/oauth/token`, [firstParty] `/v1/auth/refresh`.
_Harness _build({
  FakeRakomiNativeAdapter? adapter,
  http.Response Function()? tokenEndpoint,
  http.Response Function()? firstParty,
  DpopSession? dpopSession,
}) {
  final requests = <http.Request>[];
  final a = adapter ?? FakeRakomiNativeAdapter();
  a.mockClient = http_test.MockClient((http.Request r) async {
    requests.add(r);
    switch (r.url.path) {
      case '/.well-known/jwks.json':
        return http.Response(
          _jwksBody,
          200,
          headers: <String, String>{'content-type': 'application/json'},
        );
      case '/oauth/token':
        return (tokenEndpoint ?? _tokens)();
      case '/v1/auth/refresh':
        return (firstParty ?? _tokens)();
      case '/v1/auth/logout':
        return http.Response('', 204);
      default:
        return _json(200);
    }
  });
  final auth = RakomiAuth(
    tenantId: _kTenant,
    publishableKey: 'pk_test',
    apiBaseUrl: _kApiBase,
    issuer: _kApiBase,
    audience: _kAudience,
    adapter: a,
    clientId: _kClientId,
    jwksCache: JwksCache(
      tenantId: _kTenant,
      jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
      storage: _MemoryJwksStorage(),
      httpClient: a.mockClient,
    ),
    dpopSession: dpopSession,
  );
  return _Harness(auth, a, requests);
}

Future<DpopSession> _boundSession() async {
  final s = DpopSession(
    prover: NativeKeystoreDpopProver(signer: _StubSigner()),
    baseUrl: _kApiBase,
  );
  await s.observeTokenType('DPoP', attachedProof: true);
  return s;
}

/// Let the unawaited server-side sign-out request run.
Future<void> _drain() async {
  for (var i = 0; i < 10; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

void main() {
  setUpAll(() {
    _privateKey = testRsaPrivateKey();
    _jwksBody = testJwksBody();
  });

  group('refresh routing', () {
    test(
      'a client session refreshes at /oauth/token with its client_id',
      () async {
        final h = _build();
        await h.auth.completeSignIn(_signInBody(), oauthClientId: _kClientId);
        expect(await h.adapter.storageRead(_kClientKey), _kClientId);

        await h.auth.refreshTokens();

        expect(h.to('/v1/auth/refresh'), isEmpty);
        final calls = h.to('/oauth/token');
        expect(calls, hasLength(1));
        expect(
          calls.single.headers['content-type'],
          startsWith('application/x-www-form-urlencoded'),
        );
        expect(calls.single.bodyFields, <String, String>{
          'grant_type': 'refresh_token',
          'refresh_token': 'rt_signed_in',
          'client_id': _kClientId,
        });
        expect(h.auth.authState, isA<AuthStateAuthenticated>());
        expect(await h.adapter.storageRead(_kRefreshKey), 'rt_rotated');
        h.auth.dispose();
      },
    );

    test('a first-party session refreshes at /v1/auth/refresh', () async {
      final h = _build();
      await h.auth.completeSignIn(_signInBody(), oauthClientId: null);
      expect(await h.adapter.storageRead(_kClientKey), isNull);

      await h.auth.refreshTokens();

      expect(h.to('/oauth/token'), isEmpty);
      final calls = h.to('/v1/auth/refresh');
      expect(calls, hasLength(1));
      expect(jsonDecode(calls.single.body), <String, Object?>{
        'refresh_token': 'rt_signed_in',
      });
      h.auth.dispose();
    });

    test(
      'a first-party sign-in after a client session drops the client',
      () async {
        final h = _build();
        await h.auth.completeSignIn(_signInBody(), oauthClientId: _kClientId);
        await h.auth.completeSignIn(_signInBody(), oauthClientId: null);

        await h.auth.refreshTokens();

        expect(h.to('/oauth/token'), isEmpty);
        expect(h.to('/v1/auth/refresh'), hasLength(1));
        h.auth.dispose();
      },
    );

    test('a cold start keeps the client routing', () async {
      final adapter = FakeRakomiNativeAdapter();
      final first = _build(adapter: adapter);
      await first.auth.completeSignIn(_signInBody(), oauthClientId: _kClientId);
      first.auth.dispose();

      // A new launch: a fresh controller over the same storage.
      final second = _build(adapter: adapter);
      await second.auth.hydrate();

      expect(second.auth.authState, isA<AuthStateAuthenticated>());
      expect(second.to('/v1/auth/refresh'), isEmpty);
      final calls = second.to('/oauth/token');
      expect(calls, hasLength(1));
      expect(calls.single.bodyFields['client_id'], _kClientId);
      expect(calls.single.bodyFields['refresh_token'], 'rt_signed_in');
      second.auth.dispose();
    });

    test(
      'a DPoP-bound client session signs its proof for /oauth/token',
      () async {
        final h = _build(
          dpopSession: await _boundSession(),
          tokenEndpoint: () => _tokens(tokenType: 'DPoP'),
        );
        await h.auth.completeSignIn(_signInBody(), oauthClientId: _kClientId);

        await h.auth.refreshTokens();

        final call = h.to('/oauth/token').single;
        final proof = call.headers['DPoP'] ?? call.headers['dpop'];
        expect(proof, isNotNull, reason: 'the bound session attached no proof');
        final claims = _segment(proof!, 1);
        expect(claims['htu'], '$_kApiBase/oauth/token');
        expect(claims['htm'], 'POST');
        h.auth.dispose();
      },
    );

    test('a rejected client refresh signs out and clears the client', () async {
      final h = _build(
        tokenEndpoint: () =>
            _json(400, <String, Object?>{'error': 'invalid_grant'}),
      );
      await h.auth.completeSignIn(_signInBody(), oauthClientId: _kClientId);

      await h.auth.refreshTokens();

      expect(h.auth.authState, isA<AuthStateUnauthenticated>());
      expect(await h.adapter.storageRead(_kRefreshKey), isNull);
      expect(await h.adapter.storageRead(_kClientKey), isNull);
      h.auth.dispose();
    });
  });

  group('sign-out', () {
    test(
      'a client session revokes its refresh token at /oauth/revoke',
      () async {
        final h = _build();
        await h.auth.completeSignIn(_signInBody(), oauthClientId: _kClientId);

        await h.auth.signOut();
        await _drain();

        expect(h.to('/v1/auth/logout'), isEmpty);
        final revoke = h.to('/oauth/revoke');
        expect(revoke, hasLength(1));
        expect(revoke.single.bodyFields, <String, String>{
          'token': 'rt_signed_in',
          'token_type_hint': 'refresh_token',
          'client_id': _kClientId,
        });
        expect(await h.adapter.storageRead(_kRefreshKey), isNull);
        expect(await h.adapter.storageRead(_kClientKey), isNull);
        expect(h.auth.authState, isA<AuthStateUnauthenticated>());
        h.auth.dispose();
      },
    );

    test(
      'a first-party session calls /v1/auth/logout with its access token',
      () async {
        final h = _build();
        final body = _signInBody();
        await h.auth.completeSignIn(body, oauthClientId: null);

        await h.auth.signOut();
        await _drain();

        expect(h.to('/oauth/revoke'), isEmpty);
        final logout = h.to('/v1/auth/logout').single;
        expect(
          logout.headers['Authorization'],
          'Bearer ${body['access_token']}',
        );
        expect(logout.body.contains('rt_signed_in'), isFalse);
        h.auth.dispose();
      },
    );

    test(
      'a DPoP-bound first-party session presents DPoP and a proof to logout',
      () async {
        final h = _build(dpopSession: await _boundSession());
        final body = _signInBody();
        await h.auth.completeSignIn(body, oauthClientId: null);

        await h.auth.signOut();
        await _drain();

        final logout = h.to('/v1/auth/logout').single;
        expect(logout.headers['Authorization'], 'DPoP ${body['access_token']}');
        final proof = logout.headers['DPoP'] ?? logout.headers['dpop'];
        expect(proof, isNotNull);
        expect(_segment(proof!, 1)['htu'], '$_kApiBase/v1/auth/logout');
        h.auth.dispose();
      },
    );
  });
}
