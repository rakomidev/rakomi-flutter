import 'dart:convert' show base64Url, jsonDecode, utf8;

import 'package:crypto/crypto.dart' show sha256;
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:pointycastle/asymmetric/api.dart' as pc;

/// Offline-capable JWT verification.
///
/// **Hardcoded RS256 contract**:
///
/// - The `alg` field from the JWT header is rejected unless it is exactly
///   `'RS256'`. Headers naming `none`, `HS256`, `HS384`, `HS512` are rejected
///   in [verifyRs256] BEFORE any signature check (alg-confusion mitigation).
/// - The algorithm is pinned in code and is NEVER read from the token header
///   (RFC 9068 alignment).
///
/// **Claim validation** (per RFC 7519):
///
/// - `aud` MUST accept BOTH scalar string AND array form (§4.1.3).
/// - `iss` MUST equal the configured issuer.
/// - `exp` MUST be in the future (after applying clock-skew offset).
/// - `iat` MUST be in the past (with 30s grace for skew tolerance).
/// - `nbf` validated only if present (§4.1.5).
///
/// **Clock-skew handling**: caller passes a signed [clockSkewMs] offset
/// (server time minus device time, capped ±5 min). Skew offset outside
/// ±300_000 ms forces fail-closed (reject — online verification required).

const int _maxClockSkewMs = 5 * 60 * 1000;

sealed class JwtVerifyResult {
  const JwtVerifyResult();
}

class JwtVerifyOk extends JwtVerifyResult {
  const JwtVerifyOk(this.claims);
  final Map<String, Object?> claims;
}

class JwtVerifyError extends JwtVerifyResult {
  const JwtVerifyError(this.reason, {this.detail});
  final JwtVerifyErrorReason reason;
  final String? detail;
}

enum JwtVerifyErrorReason {
  algRejected,
  malformed,
  kidMiss,
  signatureInvalid,
  issuerMismatch,
  audienceMismatch,
  expired,
  notYetIssued,
  notYetValid,
  clockSkewExcessive,
}

class JwtVerifier {
  const JwtVerifier({
    required this.expectedIssuer,
    required this.expectedAudience,
  });

  final String expectedIssuer;
  final String expectedAudience;

  JwtVerifyResult verifyRs256({
    required String token,
    required Map<String, pc.RSAPublicKey> jwks,
    int clockSkewMs = 0,
    DateTime? now,
  }) {
    if (clockSkewMs.abs() > _maxClockSkewMs) {
      return const JwtVerifyError(JwtVerifyErrorReason.clockSkewExcessive);
    }

    final parts = token.split('.');
    if (parts.length != 3) {
      return const JwtVerifyError(JwtVerifyErrorReason.malformed);
    }

    final Map<String, Object?> header;
    final Map<String, Object?> payload;
    try {
      header = _decodeJsonSegment(parts[0]);
      payload = _decodeJsonSegment(parts[1]);
    } catch (_) {
      return const JwtVerifyError(JwtVerifyErrorReason.malformed);
    }

    if (header['alg'] != 'RS256') {
      // SECURITY: alg-confusion mitigation. ALWAYS reject anything but RS256.
      return const JwtVerifyError(JwtVerifyErrorReason.algRejected);
    }

    final kid = header['kid'] as String?;
    final pcKey = kid == null ? null : jwks[kid];
    if (pcKey == null) {
      return const JwtVerifyError(JwtVerifyErrorReason.kidMiss);
    }

    // Real signature verify with the JWKS-resolved key.
    // We disable djw's built-in expiry/nbf/audience/issuer checks and do them
    // ourselves below — gives us control over clock-skew offset semantics.
    final djwKey = djw.RSAPublicKey.raw(pcKey);
    try {
      djw.JWT.verify(
        token,
        djwKey,
        checkExpiresIn: false,
        checkNotBefore: false,
      );
    } on djw.JWTException {
      return const JwtVerifyError(JwtVerifyErrorReason.signatureInvalid);
    } catch (_) {
      return const JwtVerifyError(JwtVerifyErrorReason.signatureInvalid);
    }

    final adjustedNow = (now ?? DateTime.now().toUtc()).add(
      Duration(milliseconds: clockSkewMs),
    );

    final iss = payload['iss'];
    if (iss != expectedIssuer) {
      return const JwtVerifyError(JwtVerifyErrorReason.issuerMismatch);
    }

    final aud = payload['aud'];
    if (!_audienceMatches(aud, expectedAudience)) {
      return const JwtVerifyError(JwtVerifyErrorReason.audienceMismatch);
    }

    final exp = payload['exp'];
    if (exp is! int) {
      return const JwtVerifyError(JwtVerifyErrorReason.expired);
    }
    final expAt = DateTime.fromMillisecondsSinceEpoch(exp * 1000, isUtc: true);
    if (!adjustedNow.isBefore(expAt)) {
      return const JwtVerifyError(JwtVerifyErrorReason.expired);
    }

    final iat = payload['iat'];
    if (iat is! int) {
      return const JwtVerifyError(JwtVerifyErrorReason.notYetIssued);
    }
    final iatAt = DateTime.fromMillisecondsSinceEpoch(iat * 1000, isUtc: true);
    if (iatAt.isAfter(adjustedNow.add(const Duration(seconds: 30)))) {
      return const JwtVerifyError(JwtVerifyErrorReason.notYetIssued);
    }

    final nbf = payload['nbf'];
    if (nbf is int) {
      final nbfAt = DateTime.fromMillisecondsSinceEpoch(
        nbf * 1000,
        isUtc: true,
      );
      if (adjustedNow.isBefore(nbfAt)) {
        return const JwtVerifyError(JwtVerifyErrorReason.notYetValid);
      }
    }

    return JwtVerifyOk(payload);
  }

  /// SHA-256 of the JWT signing input — for higher-layer audit logs (CRA
  /// Art. 14, NIS2 supply-chain). NOT used for verification.
  static List<int> signingInputDigest(String token) {
    final parts = token.split('.');
    if (parts.length != 3) return const <int>[];
    return sha256.convert(utf8.encode('${parts[0]}.${parts[1]}')).bytes;
  }

  static Map<String, Object?> _decodeJsonSegment(String segment) {
    final pad = (4 - segment.length % 4) % 4;
    final json = utf8.decode(base64Url.decode(segment + ('=' * pad)));
    return jsonDecode(json) as Map<String, Object?>;
  }

  static bool _audienceMatches(Object? aud, String expected) {
    if (aud == null) return false;
    if (aud is String) return aud == expected;
    if (aud is List) return aud.any((e) => e == expected);
    return false;
  }
}

/// Convert a JWK `{kty,n,e}` into a PointyCastle RSAPublicKey.
/// RFC 7517 + RFC 7518 §6.3.
pc.RSAPublicKey rsaPublicKeyFromJwk(Map<String, Object?> jwk) {
  if (jwk['kty'] != 'RSA') {
    throw FormatException('JWK kty must be RSA, got ${jwk['kty']}');
  }
  final n = jwk['n'] as String?;
  final e = jwk['e'] as String?;
  if (n == null || e == null) {
    throw const FormatException('JWK missing n/e');
  }
  return pc.RSAPublicKey(_b64UrlBigInt(n), _b64UrlBigInt(e));
}

BigInt _b64UrlBigInt(String s) {
  final pad = (4 - s.length % 4) % 4;
  final bytes = base64Url.decode(s + ('=' * pad));
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}
