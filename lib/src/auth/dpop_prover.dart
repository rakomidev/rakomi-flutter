// rakomi_flutter — RFC 9449 DPoP proof prover.
//
// The canonical cross-port prover contract, mirroring the equivalent
// `DpopProver` contract in the Rakomi React Native and Node SDKs and the
// `@rakomi/node` `createDpopProver` conformance oracle byte-for-byte in
// STRUCTURE.
//
// SECURITY — key custody:
//   The PRODUCTION prover ([NativeKeystoreDpopProver]) NEVER holds or signs with
//   the private key in Dart. It routes signing to the native keystore
//   (AndroidKeyStore/StrongBox on Android, Keychain/Secure Enclave on iOS) over a
//   `MethodChannel`. The native side:
//     1. generates a session ES256 (P-256) keypair in the secure element
//        (`setIsStrongBoxBacked(true)` when available, non-extractable);
//     2. returns ONLY the PUBLIC JWK coordinates (`x`, `y`);
//     3. signs caller-supplied signing-input BYTES and returns the raw P1363/JOSE
//        64-byte `R‖S` signature (NEVER the DER-wrapped form).
//   The private key bytes NEVER cross the channel. A pure-Dart in-heap signing key
//   is explicitly FORBIDDEN — see [NativeKeystoreDpopProver]'s contract
//   note + the device-only residual described there.
//
// The prover OWNS every security-relevant proof field: `typ` (`dpop+jwt`), the
// pinned `alg` (`ES256` — the Secure-Enclave-eligible cross-port baseline, NEVER
// derived from a key or any input), the public-only `jwk`, `jti` (CSPRNG UUID v4,
// fresh per call), and `iat` (seconds NumericDate). The caller supplies ONLY the
// canonical request binding (`htm`/`htu`) + an optional server `nonce`; it can
// never influence the algorithm or inject claims. The proof carries NO PII
// (exactly `{htm, htu, jti, iat}` + optional `nonce`).
//
// HOST-TESTABILITY: the production native channel is device-only; on the host VM
// `flutter test` has no platform channels. The host suite injects a
// pointycastle-backed TEST signer ([EcdsaP256NativeSigner.generate], clearly a
// test fake) that implements the SAME [NativeDpopSigner] seam so the prover's
// canonical assembly + structure are verifiable on a CI host without a device.

import 'dart:convert' show base64Url, jsonEncode, utf8;
import 'dart:math' show Random;
import 'dart:typed_data' show Uint8List;

import 'package:crypto/crypto.dart' show sha256;
import 'package:meta/meta.dart';

/// RFC 9449 DPoP proof generator — the canonical cross-port prover contract.
///
/// Mirrors the RN/Swift/Node ports. The prover OWNS `jti`/`iat`/`typ`/`jwk`/`alg`;
/// the caller supplies ONLY `htm`/`htu`/optional `nonce` via [DpopProofInput].
///
/// Implementations MUST reject (throw) — never return an empty/falsy string — if
/// the native signer is unavailable, so the SDK surfaces `dpop_prover_unavailable`
/// instead of a silent Bearer call.
abstract interface class DpopProver {
  /// Build a compact-serialized DPoP-proof JWT for the bound request. Resolves to
  /// the `DPoP` header value. Signs with the session's single keypair (one keypair
  /// per session — never re-generated per call).
  Future<String> createProof(DpopProofInput input);

  /// RFC 7638 SHA-256 thumbprint of the prover's public JWK (base64url-no-pad).
  /// Lets the SDK pair `token_type == "DPoP"` with a `jkt` continuity check.
  /// Resolves the SAME value for the life of the session's keypair.
  Future<String> jktHint();
}

/// The caller-supplied inputs to [DpopProver.createProof]. The caller provides
/// ONLY the request binding; the prover owns every other claim.
@immutable
class DpopProofInput {
  const DpopProofInput({required this.htm, required this.htu, this.nonce});

  /// HTTP method of the bound request — `"POST"` for the refresh call.
  final String htm;

  /// The ALREADY-canonical `htu` (RFC 9449 §4.3). The decision layer
  /// canonicalizes; the prover signs it verbatim and MUST NOT re-derive it.
  final String htu;

  /// Optional RFC 9449 §8 server nonce, echoed into the proof on a retry.
  final String? nonce;
}

/// The native-keystore signing seam. The PRODUCTION impl bridges to a
/// `MethodChannel`; the host TEST impl is a pointycastle fake. Either way the
/// private key never leaves the signer — [DpopProver] only ever sees the public
/// JWK members + a raw `R‖S` signature.
abstract interface class NativeDpopSigner {
  /// The PUBLIC EC point of the session keypair, base64url-no-pad, as the JWK
  /// `x`/`y` members. MUST NOT include the private scalar `d`.
  Future<({String x, String y})> publicCoordinates();

  /// Sign [signingInput] (the ASCII `b64url(header).b64url(payload)` bytes) with
  /// the session private key in the secure element. MUST return the raw P1363 /
  /// JOSE 64-byte `R‖S` signature (NOT DER), so the prover base64url-no-pads it
  /// directly into the JWS.
  Future<Uint8List> signEs256(Uint8List signingInput);
}

/// Base64url WITHOUT padding (RFC 7515 §2 / RFC 7638). Never use the padded form
/// in a JWS/JWK.
String base64UrlNoPad(List<int> bytes) {
  final s = base64Url.encode(bytes);
  final pad = s.indexOf('=');
  return pad == -1 ? s : s.substring(0, pad);
}

/// The production DPoP prover. Routes ALL signing to [signer] (a native-keystore
/// `MethodChannel` bridge); never holds the private key in Dart heap.
///
/// Wire `signer` to a `MethodChannel('rakomi_flutter/dpop')` bridge whose native
/// side (Kotlin/Swift) implements:
///   - `generateSessionKey` → creates a non-extractable ES256 key in
///     AndroidKeyStore/StrongBox or Keychain/Secure Enclave, returns `{x, y}`;
///   - `sign({signingInput}) ` → returns the raw 64-byte `R‖S` signature;
///   - `destroySessionKey` → deletes the key on logout.
///
/// DEVICE-ONLY RESIDUAL: the Kotlin/Swift `MethodChannel` handler + the
/// secure-element key ceremony are device-only and not compilable/runnable under
/// host `flutter test`. They are validated on-device, out
/// of band. The Dart-side canonical assembly below is what the host suite covers
/// via a pointycastle test fake of [NativeDpopSigner].
class NativeKeystoreDpopProver implements DpopProver {
  NativeKeystoreDpopProver({required NativeDpopSigner signer, Random? random})
    : _signer = signer,
      _random = random ?? Random.secure();

  final NativeDpopSigner _signer;

  /// CSPRNG for `jti`. MUST be a [Random.secure] (default) — NEVER `Random()`.
  final Random _random;

  // The public JWK is fetched once from the signer and memoized — it is stable
  // for the life of the session keypair. The private scalar is never present.
  Map<String, String>? _publicJwk;
  String? _jkt;

  Future<Map<String, String>> _ensurePublicJwk() async {
    final cached = _publicJwk;
    if (cached != null) return cached;
    final ({String x, String y}) coords = await _signer.publicCoordinates();
    // Public-only EC JWK — exactly `{kty, crv, x, y}`, NEVER a private `d`.
    final jwk = <String, String>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': coords.x,
      'y': coords.y,
    };
    _publicJwk = jwk;
    return jwk;
  }

  /// CSPRNG UUID v4 (RFC 4122 §4.4) from [Random.secure]. 122 bits of entropy;
  /// well above the >22-char floor the ports share.
  String _newJtiV4() {
    final b = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      b[i] = _random.nextInt(256);
    }
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
    String hex(int x) => x.toRadixString(16).padLeft(2, '0');
    final h = b.map(hex).join();
    return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}'
        '-${h.substring(16, 20)}-${h.substring(20)}';
  }

  @override
  Future<String> createProof(DpopProofInput input) async {
    final jwk = await _ensurePublicJwk();

    // Protected header — STRUCTURED encoder (jsonEncode over an ordered map),
    // NEVER string concatenation of claim values. `typ`/`alg` are prover-owned
    // and pinned; `alg` is NEVER derived from a key or any caller input.
    final header = <String, Object?>{
      'typ': 'dpop+jwt',
      'alg': 'ES256',
      'jwk': jwk, // public-only
    };

    // Payload — exactly `{htm, htu, iat, jti}` (+ `nonce` when present). No PII.
    final payload = <String, Object?>{
      'htm': input.htm,
      'htu': input.htu,
      'iat':
          DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000, // seconds int
      'jti': _newJtiV4(),
      if (input.nonce != null) 'nonce': input.nonce,
    };

    final headerB64 = base64UrlNoPad(utf8.encode(jsonEncode(header)));
    final payloadB64 = base64UrlNoPad(utf8.encode(jsonEncode(payload)));
    final signingInput = '$headerB64.$payloadB64';

    // The native keystore signs the bytes and returns the raw R‖S (JOSE) form.
    final rawSig = await _signer.signEs256(
      Uint8List.fromList(utf8.encode(signingInput)),
    );
    if (rawSig.length != 64) {
      // A correct ES256 JOSE signature is exactly 64 bytes (R‖S, 32 each). A
      // DER-wrapped or empty signature is a native-bridge contract violation —
      // reject so the SDK surfaces `dpop_prover_unavailable`, never a bad proof.
      throw StateError(
        'native ES256 signer returned a non-JOSE signature '
        '(${rawSig.length} bytes; expected 64 raw R‖S)',
      );
    }
    final sigB64 = base64UrlNoPad(rawSig);

    return '$signingInput.$sigB64';
  }

  @override
  Future<String> jktHint() async {
    final cached = _jkt;
    if (cached != null) return cached;
    final jwk = await _ensurePublicJwk();
    // RFC 7638 thumbprint: SHA-256 over the canonical JSON of the REQUIRED EC
    // members in LEXICOGRAPHIC order (`crv`,`kty`,`x`,`y`), no whitespace.
    final canonical = jsonEncode(<String, String>{
      'crv': jwk['crv']!,
      'kty': jwk['kty']!,
      'x': jwk['x']!,
      'y': jwk['y']!,
    });
    final digest = sha256.convert(utf8.encode(canonical)).bytes;
    final jkt = base64UrlNoPad(digest);
    _jkt = jkt;
    return jkt;
  }
}
