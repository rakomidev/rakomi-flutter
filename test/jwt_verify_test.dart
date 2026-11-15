import 'dart:convert';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/internal/jwt_verify.dart';
import 'helpers/test_rsa_key.dart';

/// Signs with the seeded RSA test key of `helpers/test_rsa_key.dart`.
void main() {
  late djw.RSAPrivateKey privateKey;
  late VerificationKey publicKey;
  late JwtVerifier verifier;

  setUpAll(() {
    privateKey = testRsaPrivateKey();
    final jwksJson = testJwksBody();
    final jwks = jsonDecode(jwksJson) as Map<String, Object?>;
    final firstKey = (jwks['keys'] as List).first as Map<String, Object?>;
    publicKey = verificationKeyFromJwk(firstKey)!;
    verifier = const JwtVerifier(
      expectedIssuer: 'https://api.rakomi.test',
      expectedAudience: 'pk_test_demo',
    );
  });

  String sign(
    Map<String, Object?> claims, {
    String alg = 'RS256',
    String kid = 'k1',
  }) {
    final jwt = djw.JWT(
      claims,
      header: <String, Object?>{'alg': alg, 'typ': 'JWT', 'kid': kid},
    );
    return jwt.sign(privateKey, algorithm: djw.JWTAlgorithm.RS256);
  }

  group('JWT verify (RS256 hardcoded)', () {
    test('happy path — valid claims pass', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_test_demo',
        'sub': 'usr_001',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      });
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
        now: now,
      );
      expect(r, isA<JwtVerifyOk>());
    });

    test(
      'alg_none_rejected — alg: none header rejected before signature check',
      () {
        const header = '{"alg":"none","typ":"JWT","kid":"k1"}';
        const payload =
            '{"iss":"https://api.rakomi.test","aud":"pk_test_demo","sub":"u","iat":1,"exp":99999999999}';
        String enc(String s) =>
            base64Url.encode(utf8.encode(s)).replaceAll('=', '');
        final token = '${enc(header)}.${enc(payload)}.';
        final r = verifier.verify(
          token: token,
          jwks: <String, VerificationKey>{'k1': publicKey},
        );
        expect(r, isA<JwtVerifyError>());
        expect(
          (r as JwtVerifyError).reason,
          equals(JwtVerifyErrorReason.algRejected),
        );
      },
    );

    test('alg_HS256_rejected', () {
      const header = '{"alg":"HS256","typ":"JWT","kid":"k1"}';
      const payload =
          '{"iss":"x","aud":"y","sub":"u","iat":1,"exp":99999999999}';
      String enc(String s) =>
          base64Url.encode(utf8.encode(s)).replaceAll('=', '');
      final token = '${enc(header)}.${enc(payload)}.signature';
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.algRejected),
      );
    });

    test('expired token rejected', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_test_demo',
        'sub': 'u',
        'iat':
            now.subtract(const Duration(hours: 2)).millisecondsSinceEpoch ~/
            1000,
        'exp':
            now.subtract(const Duration(hours: 1)).millisecondsSinceEpoch ~/
            1000,
      });
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
        now: now,
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.expired),
      );
    });

    test('iss mismatch rejected', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://evil.example',
        'aud': 'pk_test_demo',
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      });
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
        now: now,
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.issuerMismatch),
      );
    });

    test('aud scalar form accepted', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_test_demo',
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      });
      expect(
        verifier.verify(
          token: token,
          jwks: <String, VerificationKey>{'k1': publicKey},
          now: now,
        ),
        isA<JwtVerifyOk>(),
      );
    });

    test('aud array form accepted (RFC 7519 §4.1.3)', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': <String>['other_aud', 'pk_test_demo', 'third'],
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      });
      expect(
        verifier.verify(
          token: token,
          jwks: <String, VerificationKey>{'k1': publicKey},
          now: now,
        ),
        isA<JwtVerifyOk>(),
      );
    });

    test('aud mismatch rejected', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_other',
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      });
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
        now: now,
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.audienceMismatch),
      );
    });

    test('kid_miss returned when JWKS lacks the kid', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_test_demo',
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      }, kid: 'k_unknown');
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
        now: now,
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.kidMiss),
      );
    });

    test('clockSkewExcessive when skew > ±5min', () {
      final r = verifier.verify(
        token: 'a.b.c',
        jwks: <String, VerificationKey>{},
        clockSkewMs: 6 * 60 * 1000,
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.clockSkewExcessive),
      );
    });

    test('clockSkewMs at boundary ±300_000 still passes the cap check', () {
      // We don't assert verify-OK here (the iat/exp arithmetic depends on
      // adjusted-now); we just assert the skew offset is NOT clockSkewExcessive.
      const v = JwtVerifier(expectedIssuer: 'i', expectedAudience: 'a');
      final r = v.verify(
        token: 'a.b.c',
        jwks: const <String, VerificationKey>{},
        clockSkewMs: -5 * 60 * 1000,
      );
      // Whatever the outcome, it should NOT be clockSkewExcessive — that
      // proves the cap is `> 5min`, not `>= 5min`.
      expect(
        (r as JwtVerifyError).reason,
        isNot(equals(JwtVerifyErrorReason.clockSkewExcessive)),
      );
    });

    test('malformed token rejected', () {
      final r = verifier.verify(
        token: 'not.a.jwt.too.many.parts',
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.malformed),
      );
    });

    test('nbf in the future rejected', () {
      final now = DateTime.now().toUtc();
      final future = now.add(const Duration(hours: 1));
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_test_demo',
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'nbf': future.millisecondsSinceEpoch ~/ 1000,
        'exp': now.add(const Duration(hours: 2)).millisecondsSinceEpoch ~/ 1000,
      });
      final r = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
        now: now,
      );
      expect(
        (r as JwtVerifyError).reason,
        equals(JwtVerifyErrorReason.notYetValid),
      );
    });

    test('signingInputDigest computes SHA-256 of header.payload', () {
      final now = DateTime.now().toUtc();
      final token = sign(<String, Object?>{
        'iss': 'https://api.rakomi.test',
        'aud': 'pk_test_demo',
        'sub': 'u',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      });
      final parts = token.split('.');
      final expectedDigest = sha256
          .convert(utf8.encode('${parts[0]}.${parts[1]}'))
          .bytes;
      expect(JwtVerifier.signingInputDigest(token), equals(expectedDigest));
    });
  });

  group('verificationKeyFromJwk (allowlist at key import)', () {
    Map<String, Object?> rsaJwk() => Map<String, Object?>.from(
      ((jsonDecode(testJwksBody()) as Map<String, Object?>)['keys'] as List)
              .first
          as Map<String, Object?>,
    );
    const ecP256 = <String, Object?>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      'y': '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
    };

    test('accepts RS256, PS256 and ES256 (P-256) signing keys, alg bound', () {
      expect(publicKey.alg, 'RS256');
      expect(
        verificationKeyFromJwk({...rsaJwk(), 'kid': 'p', 'alg': 'PS256'})?.alg,
        'PS256',
      );
      expect(
        verificationKeyFromJwk({
          ...ecP256,
          'kid': 'e',
          'alg': 'ES256',
          'use': 'sig',
        })?.alg,
        'ES256',
      );
      final noUse = {...rsaJwk()}..remove('use');
      expect(verificationKeyFromJwk(noUse), isNotNull);
    });

    test(
      'rejects HMAC, unlabelled, mis-typed, wrong-curve, non-sig and kid-less keys',
      () {
        final rejected = <Map<String, Object?>>[
          {'kty': 'oct', 'kid': 'h', 'alg': 'HS256', 'k': 'c2VjcmV0'},
          {...rsaJwk()}..remove('alg'),
          {...ecP256, 'kid': 'x', 'alg': 'RS256'},
          {...ecP256, 'kid': 'y', 'alg': 'ES256', 'crv': 'P-384'},
          {...rsaJwk(), 'use': 'enc'},
          {...rsaJwk(), 'alg': 'RS512'},
          {...rsaJwk()}..remove('kid'),
        ];
        for (final jwk in rejected) {
          expect(verificationKeyFromJwk(jwk), isNull, reason: jsonEncode(jwk));
        }
      },
    );
  });
}
