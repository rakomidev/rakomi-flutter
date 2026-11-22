import 'dart:convert' show base64Url, jsonDecode, utf8;

import 'package:crypto/crypto.dart' show sha256;
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;

/// Offline-capable JWT verification.
///
/// **Algorithm contract**:
///
/// - Only [kAllowedSigningAlgorithms] (RS256, PS256, ES256) are accepted.
///   Headers naming `none`, `HS256`, `HS384`, `HS512` or anything else are
///   rejected in [JwtVerifier.verify] BEFORE any key lookup (alg-confusion
///   mitigation).
/// - The algorithm is bound to the key: each [VerificationKey] carries the
///   `alg` published with it, and a token whose header names a different
///   algorithm than its key is rejected before the signature is checked.
/// - Keys come from the expected issuer's own `jwks_uri`, so a key of another
///   issuer is never in the set a token is checked against.
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

/// Default expected `iss`/`aud` when a caller derives neither from its own
/// configuration.
///
/// A tenant that has bound its own custom domain as its issuer host is issued
/// tokens whose `iss` is that host (optionally path-suffixed for a non-default
/// environment), not a shared platform constant — a platform-hosted tenant's
/// `iss` is, by construction, the same frozen constant it always was, never a
/// special-cased branch (see [deriveDefaultIssuer]). `aud`, in contrast, stays
/// the FROZEN platform identity regardless of host — Rakomi user-flow
/// (control-plane) access tokens always name the platform itself as the
/// resource server, confirmed server-side, so `aud` never varies with the
/// deployment host. Mirrors `@rakomi/react-native`'s
/// `RAKOMI_PLATFORM_ISSUER_DEFAULT`/`RAKOMI_PLATFORM_AUDIENCE_DEFAULT`
/// (`packages/react-native/src/internal/token-runtime.ts`).
const String kRakomiPlatformIssuerDefault = 'https://api.rakomi.com';
const String kRakomiPlatformAudienceDefault = 'https://api.rakomi.com';

/// Normalizes a single trailing slash away so `https://host/env` and
/// `https://host/env/` compare equal — the ONE leniency this comparison
/// allows, never a prefix/suffix match. Mirrors the RFC 8414 §3.3
/// issuer-trust comparison `@rakomi/sdk-core`'s discovery client applies to a
/// fetched discovery document's `issuer` field.
String stripTrailingSlash(String value) =>
    value.endsWith('/') ? value.substring(0, value.length - 1) : value;

/// True iff [host] is a PLATFORM host — the server's own JWT issuer identity
/// is FROZEN to [kRakomiPlatformIssuerDefault] in every environment (dev,
/// staging, prod alike), so any base URL resolving to one of these hosts
/// MUST expect the frozen constant, never a value derived from the host
/// itself.
///
/// - `rakomi.com` or any subdomain of it (`api.rakomi.com`,
///   `accounts.rakomi.com`, an environment-qualified `api.` subdomain, …) —
///   matched on a DNS LABEL boundary
///   (`host == 'rakomi.com' || host.endsWith('.rakomi.com')`), NEVER by
///   substring: `evilrakomi.com` and `rakomi.com.evil.net` must both be
///   REJECTED as platform hosts (see the should-FAIL tests).
/// - `localhost` / `127.0.0.1` / `::1` — the local dev API also mints under
///   the same frozen issuer identity.
///
/// [host] is compared lowercase — defensive, since `Uri.host` already
/// lowercases, but this function must not assume that stays true forever.
bool _isPlatformHost(String host) {
  final h = host.toLowerCase();
  if (h == 'localhost' || h == '127.0.0.1' || h == '::1') return true;
  return h == 'rakomi.com' || h.endsWith('.rakomi.com');
}

/// Derive the default expected `iss` for offline verification from
/// `apiBaseUrl` — the value `RakomiProvider(apiBaseUrl: ...)` was configured
/// with.
///
/// **A PLATFORM host** ([_isPlatformHost]) always expects
/// [kRakomiPlatformIssuerDefault] — the server's `JWT_ISSUER` is frozen there
/// regardless of which platform host the app happens to be pointed at, so
/// deriving the expectation from the host itself would reject every real
/// token a staging/dev deployment mints.
///
/// **Any other host** (a tenant's bound custom domain) expects [baseUrl]
/// itself, normalized by [stripTrailingSlash] — that domain IS the issuer
/// identity end-to-end (RFC 8414 §3.3): a token whose `iss` does not equal
/// this SDK instance's own `baseUrl` belongs to a different tenant or
/// environment and MUST be rejected, never silently accepted because it
/// happens to verify against a shared JWKS.
///
/// Falls back to [kRakomiPlatformIssuerDefault] when [baseUrl] is absent,
/// empty, or not a valid absolute URL — construction never throws on a
/// malformed config. `RakomiProvider._bootstrap` already defaults `baseUrl`
/// to the platform constant before calling this, so the byte-identical
/// frozen constant is what a platform-hosted tenant gets either way.
/// Mirrors `@rakomi/react-native`'s `deriveDefaultIssuer`
/// (`packages/react-native/src/internal/token-runtime.ts`).
String deriveDefaultIssuer(String? baseUrl) {
  if (baseUrl == null || baseUrl.isEmpty) {
    return kRakomiPlatformIssuerDefault;
  }
  try {
    final uri = Uri.parse(baseUrl);
    if (!uri.hasScheme || !uri.hasAuthority) {
      return kRakomiPlatformIssuerDefault;
    }
    if (_isPlatformHost(uri.host)) {
      return kRakomiPlatformIssuerDefault;
    }
    // `Uri.origin` throws `StateError` for a non-http(s) scheme or an empty
    // host — both already excluded by `hasAuthority`/`hasScheme` above for
    // every input this SDK accepts, but the catch stays broad (not
    // `on FormatException`) so an unanticipated `Uri` edge case degrades to
    // the frozen constant rather than a thrown exception reaching the
    // widget constructor.
    return stripTrailingSlash('${uri.origin}${uri.path}');
  } catch (_) {
    return kRakomiPlatformIssuerDefault;
  }
}

/// The JWS algorithms a Rakomi-issued token may be signed with.
const Set<String> kAllowedSigningAlgorithms = <String>{
  'RS256',
  'PS256',
  'ES256',
};

/// A verification key together with the algorithm its key record is bound to.
class VerificationKey {
  const VerificationKey({required this.alg, required this.key});

  /// One of [kAllowedSigningAlgorithms].
  final String alg;

  /// The public key used to check the signature.
  final djw.JWTKey key;
}

/// Build a [VerificationKey] from a JWK, or return `null` when the key may not
/// verify a Rakomi token signature: it needs a `kid`, an allowed `alg` on the
/// key itself, `use` absent or `sig`, and a matching key type (RSA for
/// RS256/PS256, EC on P-256 for ES256).
VerificationKey? verificationKeyFromJwk(Map<String, Object?> jwk) {
  final kid = jwk['kid'];
  if (kid is! String || kid.isEmpty) return null;
  final use = jwk['use'];
  if (use != null && use != 'sig') return null;
  final alg = jwk['alg'];
  if (alg is! String || !kAllowedSigningAlgorithms.contains(alg)) return null;
  if (alg == 'ES256') {
    if (jwk['kty'] != 'EC' || jwk['crv'] != 'P-256') return null;
  } else if (jwk['kty'] != 'RSA') {
    return null;
  }
  try {
    return VerificationKey(
      alg: alg,
      key: djw.JWTKey.fromJWK(Map<String, dynamic>.from(jwk)),
    );
  } catch (_) {
    return null;
  }
}

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

  JwtVerifyResult verify({
    required String token,
    required Map<String, VerificationKey> jwks,
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

    final alg = header['alg'];
    if (alg is! String || !kAllowedSigningAlgorithms.contains(alg)) {
      // SECURITY: alg-confusion mitigation — none/HS* and unknown algorithms never reach key lookup.
      return const JwtVerifyError(JwtVerifyErrorReason.algRejected);
    }

    final kid = header['kid'];
    final verificationKey = kid is String ? jwks[kid] : null;
    if (verificationKey == null) {
      return const JwtVerifyError(JwtVerifyErrorReason.kidMiss);
    }
    // The algorithm is bound to the key record, never taken from the header alone.
    if (verificationKey.alg != alg) {
      return const JwtVerifyError(JwtVerifyErrorReason.algRejected);
    }

    // Real signature verify with the JWKS-resolved key.
    // We disable djw's built-in expiry/nbf/audience/issuer checks and do them
    // ourselves below — gives us control over clock-skew offset semantics.
    try {
      djw.JWT.verify(
        token,
        verificationKey.key,
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
