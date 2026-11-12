import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/internal/jwt_verify.dart';

void main() {
  test('clock skew of +0 ms is the no-op baseline', () {
    const v = JwtVerifier(expectedIssuer: 'i', expectedAudience: 'a');
    final r = v.verify(
      token: 'malformed',
      jwks: const <String, VerificationKey>{},
      clockSkewMs: 0,
    );
    // We expect malformed (not clockSkewExcessive) — proves 0ms passes the cap.
    expect(
      (r as JwtVerifyError).reason,
      equals(JwtVerifyErrorReason.malformed),
    );
  });

  test('±5min boundary accepted; outside rejected', () {
    const v = JwtVerifier(expectedIssuer: 'i', expectedAudience: 'a');
    // Boundary: exactly ±5min is acceptable (we use abs > _max).
    final inside = v.verify(
      token: 'a.b.c',
      jwks: const <String, VerificationKey>{},
      clockSkewMs: 5 * 60 * 1000,
    );
    final outside = v.verify(
      token: 'a.b.c',
      jwks: const <String, VerificationKey>{},
      clockSkewMs: 5 * 60 * 1000 + 1,
    );
    expect(
      (inside as JwtVerifyError).reason,
      isNot(equals(JwtVerifyErrorReason.clockSkewExcessive)),
    );
    expect(
      (outside as JwtVerifyError).reason,
      equals(JwtVerifyErrorReason.clockSkewExcessive),
    );
  });

  test('negative skew also bound by absolute value', () {
    const v = JwtVerifier(expectedIssuer: 'i', expectedAudience: 'a');
    final r = v.verify(
      token: 'a.b.c',
      jwks: const <String, VerificationKey>{},
      clockSkewMs: -6 * 60 * 1000,
    );
    expect(
      (r as JwtVerifyError).reason,
      equals(JwtVerifyErrorReason.clockSkewExcessive),
    );
  });
}
