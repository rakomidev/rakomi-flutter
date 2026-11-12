import 'dart:convert';

import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/oauth/pkce.dart';

void main() {
  group('PKCE primitives (RFC 7636)', () {
    test('generateVerifier produces 43-char base64url-no-pad string', () {
      final v = generateVerifier();
      expect(
        v.length,
        equals(43),
        reason: '32 random bytes base64url-no-pad = 43 chars exactly',
      );
      expect(v.contains('='), isFalse, reason: 'no = padding allowed');
      expect(
        RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(v),
        isTrue,
        reason: 'must use the base64url alphabet',
      );
    });

    test('s256Challenge — hash verifier ASCII octets, base64url no-pad', () {
      // Spec test vector — RFC 7636 Appendix B.
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      expect(s256Challenge(verifier), equals(expected));
    });

    test('s256_enforced — challenge is always SHA-256, never raw verifier', () {
      final v = generateVerifier();
      final c = s256Challenge(v);
      // The challenge MUST differ from the verifier (S256 transform).
      expect(c, isNot(equals(v)));
      // Sanity: challenge length matches base64url-no-pad of 32 bytes.
      expect(c.length, equals(43));
    });

    test('verifier uniqueness (CSPRNG entropy)', () {
      final s = <String>{};
      for (var i = 0; i < 100; i++) {
        s.add(generateVerifier());
      }
      expect(
        s.length,
        equals(100),
        reason: '100 verifiers must all be distinct (CSPRNG)',
      );
    });

    test('randomState produces 32-byte base64url-no-pad string', () {
      final s = randomState();
      expect(s.length, equals(43));
      expect(s.contains('='), isFalse);
    });

    test('randomOneTimeId produces 32-hex-char id', () {
      final id = randomOneTimeId();
      expect(id.length, equals(32));
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(id), isTrue);
    });

    test('state_compare_constant_time — equal strings ⇒ true', () {
      const a = 'EgoG_IiCnbV3RzojOlyXr3MvRZqV1xX4SjMlCT2-7Mk';
      expect(constantTimeStringEquals(a, a), isTrue);
    });

    test('state_compare_constant_time — single-byte diff ⇒ false', () {
      const a = 'EgoG_IiCnbV3RzojOlyXr3MvRZqV1xX4SjMlCT2-7Mk';
      const b = 'EgoG_IiCnbV3RzojOlyXr3MvRZqV1xX4SjMlCT2-7MX'; // last char
      expect(constantTimeStringEquals(a, b), isFalse);
    });

    test('state_compare_constant_time — length mismatch ⇒ false', () {
      expect(constantTimeStringEquals('abc', 'abcd'), isFalse);
    });

    test('challenge round-trip — verifier ASCII bytes hashed correctly', () {
      // Independent verification: build the challenge ourselves and compare.
      const verifier = 'test_verifier_value_for_round_trip_check_xyz';
      final ourSha = base64Url
          .encode(sha256.convert(utf8.encode(verifier)).bytes)
          .replaceAll('=', '');
      expect(s256Challenge(verifier), equals(ourSha));
    });
  });
}
