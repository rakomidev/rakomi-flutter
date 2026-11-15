import 'dart:convert';
import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' show MockClient;
import 'package:pointycastle/export.dart' as pce;
import 'package:rakomi_flutter/src/internal/issuer_jwks.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';
import 'package:rakomi_flutter/src/internal/jwt_verify.dart';
import 'helpers/test_rsa_key.dart';

/// Issuer-bound signing keys: keys come from the jwks_uri of the EXPECTED
/// issuer's discovery document, and a token's alg must equal its key's alg.
void main() {
  const issuer = 'https://auth.example.test/t/tn_abc/test';
  const audience = 'https://api.rakomi.com';
  const jwksUri = 'https://keys.example.test/t/tn_abc/test/jwks';

  late djw.RSAPrivateKey rsaPrivate;
  late Map<String, Object?> rsaJwk;
  late djw.ECPrivateKey ecPrivate;
  late Map<String, Object?> ecJwk;

  String b64(BigInt v, int length) {
    final bytes = Uint8List(length);
    var n = v;
    for (var i = length - 1; i >= 0; i--) {
      bytes[i] = (n & BigInt.from(0xff)).toInt();
      n = n >> 8;
    }
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  setUpAll(() {
    rsaPrivate = testRsaPrivateKey();
    rsaJwk = Map<String, Object?>.from(
      ((jsonDecode(testJwksBody()) as Map<String, Object?>)['keys'] as List)
              .first
          as Map<String, Object?>,
    );

    final params = pce.ECDomainParameters('prime256v1');
    final random = pce.FortunaRandom()
      ..seed(
        pce.KeyParameter(
          Uint8List.fromList(
            List<int>.generate(32, (_) => Random.secure().nextInt(256)),
          ),
        ),
      );
    final generator = pce.ECKeyGenerator()
      ..init(
        pce.ParametersWithRandom(pce.ECKeyGeneratorParameters(params), random),
      );
    final pair = generator.generateKeyPair();
    final pub = pair.publicKey;
    ecPrivate = djw.ECPrivateKey.raw(pair.privateKey);
    ecJwk = <String, Object?>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': b64(pub.Q!.x!.toBigInteger()!, 32),
      'y': b64(pub.Q!.y!.toBigInteger()!, 32),
    };
  });

  String sign(
    djw.JWTKey key,
    djw.JWTAlgorithm alg,
    String kid, {
    String iss = issuer,
  }) {
    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    return djw
        .JWT(
          <String, Object?>{
            'iss': iss,
            'aud': audience,
            'sub': 'u1',
            'iat': now,
            'exp': now + 600,
          },
          header: <String, Object?>{'alg': alg.name, 'typ': 'JWT', 'kid': kid},
        )
        .sign(key, algorithm: alg);
  }

  group('issuerDiscoveryUrls', () {
    test('RFC 8414 path insertion first, then OIDC append', () {
      expect(issuerDiscoveryUrls(issuer).map((u) => u.toString()).toList(), <
        String
      >[
        'https://auth.example.test/.well-known/oauth-authorization-server/t/tn_abc/test',
        'https://auth.example.test/t/tn_abc/test/.well-known/openid-configuration',
      ]);
    });

    test('a discovery origin replaces only the origin', () {
      expect(
        issuerDiscoveryUrls(
          'https://api.rakomi.com/t/tn_abc',
          discoveryOrigin: Uri.parse('http://localhost:3001'),
        ).first.toString(),
        'http://localhost:3001/.well-known/oauth-authorization-server/t/tn_abc',
      );
    });
  });

  group('extractJwksUri', () {
    test('accepts the exact issuer', () {
      expect(
        extractJwksUri(<String, Object?>{
          'issuer': issuer,
          'jwks_uri': jwksUri,
        }, issuer).toString(),
        jwksUri,
      );
    });

    test('refuses another issuer, a missing jwks_uri and plain http', () {
      expect(
        () => extractJwksUri(<String, Object?>{
          'issuer': 'https://auth.example.test',
          'jwks_uri': jwksUri,
        }, issuer),
        throwsA(isA<IssuerMismatchException>()),
      );
      expect(
        () => extractJwksUri(<String, Object?>{'issuer': issuer}, issuer),
        throwsFormatException,
      );
      expect(
        () => extractJwksUri(<String, Object?>{
          'issuer': issuer,
          'jwks_uri': 'http://keys.example.test/j',
        }, issuer),
        throwsFormatException,
      );
    });
  });

  group('discoveryOriginFor', () {
    test(
      'platform-family issuer → configured deployment; custom domain → itself',
      () {
        expect(
          discoveryOriginFor(
            'https://api.rakomi.com/t/x',
            'http://127.0.0.1:3001',
          ).toString(),
          'http://127.0.0.1:3001',
        );
        expect(
          discoveryOriginFor(
            'https://auth.example.test',
            'https://api.rakomi.com',
          ),
          isNull,
        );
        expect(
          discoveryOriginFor(
            'https://evilrakomi.com/t/x',
            'http://127.0.0.1:3001',
          ),
          isNull,
        );
      },
    );
  });

  group('JwksCache in issuer mode + JwtVerifier', () {
    late List<String> requested;

    JwksCache cacheServing(
      String documentIssuer,
      List<Map<String, Object?>> keys,
    ) {
      requested = <String>[];
      final client = MockClient((request) async {
        final url = request.url.toString();
        requested.add(url);
        if (url ==
            'https://auth.example.test/.well-known/oauth-authorization-server/t/tn_abc/test') {
          return http.Response(
            jsonEncode(<String, Object?>{
              'issuer': documentIssuer,
              'jwks_uri': jwksUri,
            }),
            200,
          );
        }
        if (url == jwksUri) {
          return http.Response(
            jsonEncode(<String, Object?>{'keys': keys}),
            200,
          );
        }
        return http.Response('', 404);
      });
      return JwksCache(
        tenantId: 't',
        issuer: issuer,
        storage: _MemoryStorage(),
        httpClient: client,
      );
    }

    const verifier = JwtVerifier(
      expectedIssuer: issuer,
      expectedAudience: audience,
    );

    test(
      'should-PASS: RS256, PS256 and ES256 tokens verify against the discovered jwks_uri',
      () async {
        final cache = cacheServing(issuer, <Map<String, Object?>>[
          {...rsaJwk, 'kid': 'k-rs', 'alg': 'RS256'},
          {...rsaJwk, 'kid': 'k-ps', 'alg': 'PS256'},
          {...ecJwk, 'kid': 'k-es', 'alg': 'ES256', 'use': 'sig'},
        ]);
        final keys = await cache.getKeys();
        expect(
          verifier.verify(
            token: sign(rsaPrivate, djw.JWTAlgorithm.RS256, 'k-rs'),
            jwks: keys,
          ),
          isA<JwtVerifyOk>(),
        );
        expect(
          verifier.verify(
            token: sign(rsaPrivate, djw.JWTAlgorithm.PS256, 'k-ps'),
            jwks: keys,
          ),
          isA<JwtVerifyOk>(),
        );
        expect(
          verifier.verify(
            token: sign(ecPrivate, djw.JWTAlgorithm.ES256, 'k-es'),
            jwks: keys,
          ),
          isA<JwtVerifyOk>(),
        );
        expect(requested, contains(jwksUri));
        expect(
          requested.any((u) => u.endsWith('/.well-known/jwks.json')),
          isFalse,
        );
      },
    );

    test(
      'should-FAIL: a kid not published by the expected issuer is a kid miss',
      () async {
        final keys = await cacheServing(issuer, <Map<String, Object?>>[
          {...rsaJwk, 'kid': 'k-rs'},
        ]).getKeys();
        final r = verifier.verify(
          token: sign(rsaPrivate, djw.JWTAlgorithm.RS256, 'k-other'),
          jwks: keys,
        );
        expect((r as JwtVerifyError).reason, JwtVerifyErrorReason.kidMiss);
      },
    );

    test(
      'should-FAIL: a header alg that differs from the key record alg is rejected',
      () async {
        final keys = await cacheServing(issuer, <Map<String, Object?>>[
          {...rsaJwk, 'kid': 'k-rs', 'alg': 'RS256'},
        ]).getKeys();
        final r = verifier.verify(
          token: sign(rsaPrivate, djw.JWTAlgorithm.PS256, 'k-rs'),
          jwks: keys,
        );
        expect((r as JwtVerifyError).reason, JwtVerifyErrorReason.algRejected);
      },
    );

    test(
      'should-FAIL: a discovery document naming another issuer is refused; no JWKS fetched',
      () async {
        final cache = cacheServing(
          'https://auth.example.test/t/tn_other',
          <Map<String, Object?>>[rsaJwk],
        );
        await expectLater(
          cache.getKeys(),
          throwsA(isA<IssuerMismatchException>()),
        );
        expect(requested, isNot(contains(jwksUri)));
      },
    );
  });
}

class _MemoryStorage implements JwksStorage {
  final Map<String, String> _data = <String, String>{};

  @override
  Future<void> deleteKey(String key) async => _data.remove(key);

  @override
  Future<String?> readKey(String key) async => _data[key];

  @override
  Future<void> writeKey(String key, String value) async => _data[key] = value;
}
