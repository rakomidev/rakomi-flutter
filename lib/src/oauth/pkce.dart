import 'dart:convert' show base64Url, utf8;
import 'dart:math' show Random;
import 'dart:typed_data' show Uint8List;

import 'package:crypto/crypto.dart' show sha256;

/// RFC 7636 PKCE primitives.
///
/// - [generateVerifier] — 32 random bytes from a CSPRNG, base64url-encoded
///   without `=` padding (per RFC 7515 §2 / RFC 7636 §4.1). The encoded
///   length is 43 chars ASCII (RFC 7636 requires 43–128).
/// - [s256Challenge] — `BASE64URL(SHA-256(verifier_ascii))`, no padding.
/// - [randomState] — 32 random bytes, base64url-encoded without padding,
///   for the OAuth `state` parameter.
/// - [constantTimeEquals] — byte-array constant-time comparator. NEVER use
///   `==` for state/code/nonce comparison (timing-attack defense).

class _Csprng {
  static final Random _rng = Random.secure();

  static Uint8List bytes(int n) {
    final buf = Uint8List(n);
    for (var i = 0; i < n; i++) {
      buf[i] = _rng.nextInt(256);
    }
    return buf;
  }
}

/// Strip `=` padding per RFC 7515 §2 / RFC 7636 §4.1.
String _b64UrlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Generate a 32-byte CSPRNG-backed PKCE `code_verifier` per RFC 7636 §4.1.
/// Returns the base64url-encoded ASCII string (no `=` padding).
String generateVerifier() => _b64UrlNoPad(_Csprng.bytes(32));

/// Compute the S256 PKCE `code_challenge` for [verifier]. Returns
/// `BASE64URL-NO-PAD(SHA-256(verifier_ascii))`.
String s256Challenge(String verifier) {
  // RFC 7636 §4.2: hash the ASCII octets of the verifier string (NOT the
  // base64url-decoded bytes — common mistake).
  final digest = sha256.convert(utf8.encode(verifier));
  return _b64UrlNoPad(digest.bytes);
}

/// Generate a 32-byte CSPRNG-backed OAuth `state` value, base64url no padding.
String randomState() => _b64UrlNoPad(_Csprng.bytes(32));

/// Generate a random one-time-id (16 bytes hex) for paired storage keys.
String randomOneTimeId() {
  final bytes = _Csprng.bytes(16);
  final buf = StringBuffer();
  for (final b in bytes) {
    buf.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buf.toString();
}

/// Constant-time comparison. Returns `true` iff [a] and [b] have the same
/// length AND the same bytes. Iteration time is independent of where the
/// first mismatch is.
///
/// Mirrors `crypto.timingSafeEqual` from the React Native SDK. Used for state/code/
/// nonce validation (timing-attack defense).
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) {
    // We still scan b to keep length-leakage minimal — but length is
    // public information for the OAuth state value (always 43 chars), so
    // this short-circuit is acceptable.
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Convenience wrapper: constant-time string comparison. Encodes both
/// strings as ASCII octets before comparing (PKCE/state values are ASCII
/// only — base64url alphabet).
bool constantTimeStringEquals(String a, String b) =>
    constantTimeEquals(utf8.encode(a), utf8.encode(b));
