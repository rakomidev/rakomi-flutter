import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/internal/jwt_verify.dart';
import 'helpers/test_rsa_key.dart';

/// Multi-issuer offline verification (`flutter-swift-sdks-need-the-same-
/// multi-issuer-offline-verification-fix`) — the SAME trust model
/// `@rakomi/react-native`'s `deriveDefaultIssuer` applies
/// (`packages/react-native/src/internal/token-runtime.ts`), ported for Dart.
///
/// `deriveDefaultIssuer` derives the default `expectedIssuer` FROM
/// `RakomiProvider.apiBaseUrl` instead of a hardcoded platform constant.
/// The second group below exercises [deriveDefaultIssuer] wired into the
/// REAL [JwtVerifier] exactly as `provider.dart`/`auth_controller.dart` wire
/// them at runtime — the same production matcher, never a stand-alone string
/// comparison (FMEA row 8).
void main() {
  late djw.RSAPrivateKey privateKey;
  late VerificationKey publicKey;

  setUpAll(() {
    privateKey = testRsaPrivateKey();
    final jwksJson = testJwksBody();
    final jwks = jsonDecode(jwksJson) as Map<String, Object?>;
    final firstKey = (jwks['keys'] as List).first as Map<String, Object?>;
    publicKey = verificationKeyFromJwk(firstKey)!;
  });

  String sign({required String iss, required String aud, String kid = 'k1'}) {
    final now = DateTime.now().toUtc();
    final jwt = djw.JWT(
      <String, Object?>{
        'iss': iss,
        'aud': aud,
        'sub': 'user-1',
        'iat': now.millisecondsSinceEpoch ~/ 1000,
        'exp':
            now.add(const Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
      },
      header: <String, Object?>{'alg': 'RS256', 'typ': 'JWT', 'kid': kid},
    );
    return jwt.sign(privateKey, algorithm: djw.JWTAlgorithm.RS256);
  }

  group('deriveDefaultIssuer — pure derivation', () {
    test('should-PASS: derives the issuer from a custom-domain baseUrl', () {
      expect(
        deriveDefaultIssuer('https://tenant-a.example.com'),
        equals('https://tenant-a.example.com'),
      );
    });

    test('strips a trailing slash', () {
      expect(
        deriveDefaultIssuer('https://tenant-a.example.com/'),
        equals('https://tenant-a.example.com'),
      );
    });

    test(
      'preserves a tenant-path-suffixed baseUrl (non-default environment)',
      () {
        expect(
          deriveDefaultIssuer('https://auth.acme.com/staging'),
          equals('https://auth.acme.com/staging'),
        );
        expect(
          deriveDefaultIssuer('https://auth.acme.com/staging/'),
          equals('https://auth.acme.com/staging'),
        );
      },
    );

    test(
      'backward-compat: a platform-hosted baseUrl derives the byte-identical '
      'frozen constant',
      () {
        expect(
          deriveDefaultIssuer('https://api.rakomi.com'),
          equals(kRakomiPlatformIssuerDefault),
        );
        expect(kRakomiPlatformIssuerDefault, equals('https://api.rakomi.com'));
      },
    );

    test('should-PASS: ANY rakomi.com subdomain is a platform host — frozen '
        'constant, never the subdomain itself (server JWT_ISSUER is frozen in '
        'every environment)', () {
      expect(
        deriveDefaultIssuer('https://accounts.rakomi.com'),
        equals(kRakomiPlatformIssuerDefault),
      );
      expect(
        deriveDefaultIssuer('https://rakomi.com'),
        equals(kRakomiPlatformIssuerDefault),
      );
      expect(
        deriveDefaultIssuer('https://a.b.rakomi.com'),
        equals(kRakomiPlatformIssuerDefault),
      );
    });

    test('should-PASS: localhost/127.0.0.1/::1 are platform hosts — frozen '
        'constant (local dev mints under the same frozen JWT_ISSUER)', () {
      expect(
        deriveDefaultIssuer('http://localhost:3001'),
        equals(kRakomiPlatformIssuerDefault),
      );
      expect(
        deriveDefaultIssuer('http://127.0.0.1:3001'),
        equals(kRakomiPlatformIssuerDefault),
      );
      expect(
        deriveDefaultIssuer('http://[::1]:3001'),
        equals(kRakomiPlatformIssuerDefault),
      );
    });

    test('should-FAIL plant: a confusable host that is NOT a rakomi.com '
        'subdomain is treated as a genuine custom host (iss = its own base '
        'URL), never silently folded into the platform constant — substring '
        'match, not label-boundary match, would misclassify both of these', () {
      // `evilrakomi.com` — ends with the literal characters "rakomi.com"
      // but is NOT `.rakomi.com` on a label boundary.
      expect(
        deriveDefaultIssuer('https://evilrakomi.com'),
        equals('https://evilrakomi.com'),
      );
      // `rakomi.com.evil.net` — CONTAINS "rakomi.com" but does not END
      // with it at all.
      expect(
        deriveDefaultIssuer('https://rakomi.com.evil.net'),
        equals('https://rakomi.com.evil.net'),
      );
    });

    test(
      'falls back to the frozen platform constant on an unparseable/absent baseUrl',
      () {
        expect(
          deriveDefaultIssuer('not a url'),
          equals(kRakomiPlatformIssuerDefault),
        );
        expect(deriveDefaultIssuer(null), equals(kRakomiPlatformIssuerDefault));
        expect(deriveDefaultIssuer(''), equals(kRakomiPlatformIssuerDefault));
      },
    );
  });

  group('deriveDefaultIssuer + JwtVerifier — the wired trust model '
      '(RakomiProvider parity)', () {
    test(
      'should-PASS: verifies a token whose iss equals the derived baseUrl issuer',
      () {
        final issuer = deriveDefaultIssuer('https://tenant-a.example.com');
        final verifier = JwtVerifier(
          expectedIssuer: issuer,
          expectedAudience: 'https://api.rakomi.com',
        );
        final token = sign(
          iss: 'https://tenant-a.example.com',
          aud: 'https://api.rakomi.com',
        );
        final result = verifier.verify(
          token: token,
          jwks: <String, VerificationKey>{'k1': publicKey},
        );
        expect(result, isA<JwtVerifyOk>());
      },
    );

    test('should-FAIL: rejects a token whose iss belongs to a DIFFERENT '
        'tenant baseUrl — same JWKS/keypair, forged iss', () {
      // Same keypair/JWKS as the should-PASS case above (planted into
      // the REAL verifier per FMEA row 9), only the token's `iss` claim
      // differs — isolates the iss check from key material.
      final issuer = deriveDefaultIssuer('https://tenant-a.example.com');
      final verifier = JwtVerifier(
        expectedIssuer: issuer,
        expectedAudience: 'https://api.rakomi.com',
      );
      final forged = sign(
        iss: 'https://tenant-b.example.com',
        aud: 'https://api.rakomi.com',
      );
      final result = verifier.verify(
        token: forged,
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(result, isA<JwtVerifyError>());
      expect(
        (result as JwtVerifyError).reason,
        JwtVerifyErrorReason.issuerMismatch,
      );
    });

    test('backward-compat: a platform-hosted tenant verifies unchanged '
        'against the frozen default', () {
      final issuer = deriveDefaultIssuer('https://api.rakomi.com');
      final verifier = JwtVerifier(
        expectedIssuer: issuer,
        expectedAudience: 'https://api.rakomi.com',
      );
      final token = sign(
        iss: 'https://api.rakomi.com',
        aud: 'https://api.rakomi.com',
      );
      final result = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(result, isA<JwtVerifyOk>());
    });

    test('backward-compat: omitting apiBaseUrl entirely still derives the '
        'platform default (a caller on an older SDK version)', () {
      final issuer = deriveDefaultIssuer(null);
      final verifier = JwtVerifier(
        expectedIssuer: issuer,
        expectedAudience: 'https://api.rakomi.com',
      );
      final token = sign(
        iss: 'https://api.rakomi.com',
        aud: 'https://api.rakomi.com',
      );
      final result = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(result, isA<JwtVerifyOk>());
    });

    test('should-PASS: a DIFFERENT rakomi.com platform host (e.g. a staging '
        'apiBaseUrl) still verifies a real platform token — this is the exact '
        'scenario the naive "expected iss = apiBaseUrl" design broke', () {
      final issuer = deriveDefaultIssuer('https://accounts.rakomi.com');
      final verifier = JwtVerifier(
        expectedIssuer: issuer,
        expectedAudience: 'https://api.rakomi.com',
      );
      // A REAL platform-minted token always carries the frozen iss,
      // regardless of which platform host the app is pointed at.
      final token = sign(
        iss: 'https://api.rakomi.com',
        aud: 'https://api.rakomi.com',
      );
      final result = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(result, isA<JwtVerifyOk>());
    });

    test('should-FAIL plant: a confusable non-platform host never accepts a '
        'genuine platform-issued token — evilrakomi.com is a distinct, '
        'untrusted issuer identity, not folded into the platform constant', () {
      final issuer = deriveDefaultIssuer('https://evilrakomi.com');
      expect(issuer, equals('https://evilrakomi.com'));
      final verifier = JwtVerifier(
        expectedIssuer: issuer,
        expectedAudience: 'https://api.rakomi.com',
      );
      // A genuine platform token — would pass against the REAL platform
      // constant, but must NOT pass here.
      final token = sign(
        iss: 'https://api.rakomi.com',
        aud: 'https://api.rakomi.com',
      );
      final result = verifier.verify(
        token: token,
        jwks: <String, VerificationKey>{'k1': publicKey},
      );
      expect(result, isA<JwtVerifyError>());
      expect(
        (result as JwtVerifyError).reason,
        JwtVerifyErrorReason.issuerMismatch,
      );
    });
  });
}
