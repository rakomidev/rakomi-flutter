// DPoP refresh-proof conformance suite of `rakomi_flutter`.
//
// Proves the genuinely-new control (a DPoP proof attached on the refresh of a
// DPoP-bound session) is NON-VACUOUS for the Flutter port. The proof *shape*
// mirrors `@rakomi/node`'s `createDpopProver` (the shared conformance oracle) and
// the RN port byte-for-byte in STRUCTURE; the self-describing test names double as
// GRC compliance evidence (`bearer_session_attaches_no_proof`,
// `same_jkt_across_refreshes`, `distinct_jti_two_refreshes`,
// `dpop_proof_carries_no_pii`).
//
// Includes the no-silent-Bearer and nonce-retry pins. The network is
// fully faked — we assert the OUTBOUND `DPoP` header and decode the proof JWT; no
// live server.
//
// NOTE (platform constraint): in PRODUCTION the Flutter prover bridges
// signing to the native keystore (AndroidKeyStore/StrongBox, Keychain/Secure
// Enclave) over a `MethodChannel` and NEVER signs in Dart. `flutter test` runs on
// the host VM where platform channels are unavailable, so this suite injects a
// pointycastle-backed TEST signer ([_PointyCastleEs256Signer], a clearly-named
// test fake) that implements the SAME [NativeDpopSigner] seam. This validates the
// prover's canonical assembly + proof structure on a CI host without a device; the
// native-keystore signing itself is validated on-device, out of band (device-only
// residual).
//
// Standards: RFC 9449 §4.2/§4.3 (htm/htu/iat/jti), §8 (nonce), RFC 7638 (jkt
// thumbprint), RFC 7519 (NumericDate seconds), RFC 6749 §5.2 (error envelope),
// RFC 7515 (JWS compact + base64url-no-pad).

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';
// The canonicalizer is an internal mirror (not part of the public surface); the
// conformance-vector test reaches it via a `package:` (src/) import, same as the
// RN port's test reaches its local canonical-url mirror.
import 'package:rakomi_flutter/src/internal/canonical_url.dart';

const String kBaseUrl = 'https://api.test.io';
const String kTokenEndpoint = 'https://api.test.io/v1/auth/refresh';

// ─── pointycastle-backed TEST ES256 signer (the host stand-in for the native
//     keystore — returns raw P1363/JOSE R‖S, exactly like the device bridge). ────

class _PointyCastleEs256Signer implements NativeDpopSigner {
  _PointyCastleEs256Signer._(this._priv, this._pub);

  factory _PointyCastleEs256Signer.generate() {
    final domain = ECDomainParameters('prime256v1');
    final rnd = FortunaRandom();
    final seed = Uint8List(32);
    final r = Random.secure();
    for (var i = 0; i < 32; i++) {
      seed[i] = r.nextInt(256);
    }
    rnd.seed(KeyParameter(seed));
    final gen = ECKeyGenerator()
      ..init(ParametersWithRandom(ECKeyGeneratorParameters(domain), rnd));
    final pair = gen.generateKeyPair();
    return _PointyCastleEs256Signer._(pair.privateKey, pair.publicKey);
  }

  final ECPrivateKey _priv;
  final ECPublicKey _pub;

  static Uint8List _i2osp(BigInt n, int len) {
    final out = Uint8List(len);
    var x = n;
    for (var i = len - 1; i >= 0; i--) {
      out[i] = (x & BigInt.from(0xff)).toInt();
      x = x >> 8;
    }
    return out;
  }

  static String _b64(List<int> bytes) {
    final s = base64Url.encode(bytes);
    final pad = s.indexOf('=');
    return pad == -1 ? s : s.substring(0, pad);
  }

  @override
  Future<({String x, String y})> publicCoordinates() async {
    final q = _pub.Q!;
    return (
      x: _b64(_i2osp(q.x!.toBigInteger()!, 32)),
      y: _b64(_i2osp(q.y!.toBigInteger()!, 32)),
    );
  }

  @override
  Future<Uint8List> signEs256(Uint8List signingInput) async {
    // RFC 6979 deterministic ECDSA over SHA-256 → raw R‖S (64 bytes), the JOSE
    // form. (The real device keystore returns the same P1363 shape.)
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(true, PrivateKeyParameter<ECPrivateKey>(_priv));
    final sig = signer.generateSignature(signingInput) as ECSignature;
    return Uint8List(64)
      ..setRange(0, 32, _i2osp(sig.r, 32))
      ..setRange(32, 64, _i2osp(sig.s, 32));
  }

  /// Cryptographically verify a proof's signature against THIS keypair (used by
  /// the "real ES256, not just structural" assertion).
  bool verifyCompactJws(String compact) {
    final parts = compact.split('.');
    if (parts.length != 3) return false;
    final signingInput = Uint8List.fromList(
      utf8.encode('${parts[0]}.${parts[1]}'),
    );
    final raw = base64Url.decode(_pad(parts[2]));
    if (raw.length != 64) return false;
    final r = _osip(raw.sublist(0, 32));
    final s = _osip(raw.sublist(32, 64));
    final verifier = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(false, PublicKeyParameter<ECPublicKey>(_pub));
    return verifier.verifySignature(signingInput, ECSignature(r, s));
  }

  static String _pad(String s) {
    final m = s.length % 4;
    return m == 0 ? s : s + ('=' * (4 - m));
  }

  static BigInt _osip(List<int> bytes) {
    var r = BigInt.zero;
    for (final b in bytes) {
      r = (r << 8) | BigInt.from(b);
    }
    return r;
  }
}

// ─── A signer whose key exists (so the session binds) but whose secure-element
//     signing op fails at proof time (e.g. enclave evicted / user-presence lost). ─
//
// This is the realistic `dpop_prover_unavailable` failure mode: the session
// became bound at issuance (the key + public coords exist), then a later refresh
// signing throws. Coordinates succeed; only `signEs256` fails.

class _FailingSigner implements NativeDpopSigner {
  _FailingSigner._(this._base);
  factory _FailingSigner.generate() =>
      _FailingSigner._(_PointyCastleEs256Signer.generate());

  final _PointyCastleEs256Signer _base;

  @override
  Future<({String x, String y})> publicCoordinates() =>
      _base.publicCoordinates();

  @override
  Future<Uint8List> signEs256(Uint8List signingInput) async =>
      throw StateError('secure enclave unavailable');
}

// ─── A signer that returns a non-JOSE (DER-ish, wrong length) signature. ───────
//
// Public coordinates are real (so the prover assembles a header); only the
// signature length is wrong — the prover MUST reject it (never emit a bad proof).

class _BadLengthSigner implements NativeDpopSigner {
  _BadLengthSigner._(this._base);
  factory _BadLengthSigner.generate() =>
      _BadLengthSigner._(_PointyCastleEs256Signer.generate());

  final _PointyCastleEs256Signer _base;

  @override
  Future<({String x, String y})> publicCoordinates() =>
      _base.publicCoordinates();

  @override
  Future<Uint8List> signEs256(Uint8List signingInput) async => Uint8List(70); // DER-ish, not raw 64-byte R‖S
}

// ─── Faked HTTP poster recording outbound DPoP headers + queued responses. ─────

class _FakeResponse {
  const _FakeResponse({
    required this.statusCode,
    this.tokenType,
    this.oauthError,
    this.dpopNonce,
  });

  final int statusCode;
  final String? tokenType;
  final String? oauthError;
  final String? dpopNonce;
}

_FakeResponse _dpopTokens() =>
    const _FakeResponse(statusCode: 200, tokenType: 'DPoP');
_FakeResponse _bearerTokens() =>
    const _FakeResponse(statusCode: 200, tokenType: 'Bearer');
_FakeResponse _nonceChallenge(String nonce) => _FakeResponse(
  statusCode: 401,
  oauthError: 'use_dpop_nonce',
  dpopNonce: nonce,
);
_FakeResponse _proofRejected() =>
    const _FakeResponse(statusCode: 401, oauthError: 'invalid_dpop_proof');
_FakeResponse _revoked() =>
    const _FakeResponse(statusCode: 400, oauthError: 'invalid_grant');

class _RecordedCall {
  _RecordedCall(this.refreshToken, this.dpopProof);
  final String refreshToken;
  final String? dpopProof;
}

class _FakePoster {
  _FakePoster(this._queue);
  final List<_FakeResponse> _queue;
  final List<_RecordedCall> calls = [];

  DpopRefreshPoster get post =>
      ({required String refreshToken, String? dpopProof}) async {
        calls.add(_RecordedCall(refreshToken, dpopProof));
        if (_queue.isEmpty) {
          throw StateError('fake poster: no queued response');
        }
        final r = _queue.removeAt(0);
        return TokenPostResult(
          statusCode: r.statusCode,
          tokenType: r.tokenType,
          accessToken: r.statusCode == 200 ? 'at' : null,
          refreshToken: r.statusCode == 200 ? 'rt' : null,
          oauthError: r.oauthError,
          dpopNonce: r.dpopNonce,
        );
      };
}

// ─── Proof decode helpers ──────────────────────────────────────────────────────

Map<String, Object?> _decodeSeg(String seg) {
  final pad = (4 - seg.length % 4) % 4;
  return jsonDecode(utf8.decode(base64Url.decode(seg + ('=' * pad))))
      as Map<String, Object?>;
}

({Map<String, Object?> header, Map<String, Object?> payload}) _decodeProof(
  String? proof,
) {
  expect(proof, isNotNull, reason: 'expected a DPoP proof');
  final parts = proof!.split('.');
  expect(parts.length, 3, reason: 'compact JWS must have 3 segments');
  return (header: _decodeSeg(parts[0]), payload: _decodeSeg(parts[1]));
}

DpopSession _boundSessionFrom(DpopProver prover) {
  final s = DpopSession(prover: prover, baseUrl: kBaseUrl);
  // Issuance observed `DPoP` — bound at issuance, not lazily.
  s.observeTokenType('DPoP', attachedProof: true);
  return s;
}

void main() {
  group('bound session attaches a conformant DPoP proof on refresh', () {
    test('bound_refresh_attaches_structurally_valid_proof', () async {
      final signer = _PointyCastleEs256Signer.generate();
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: signer),
      );
      expect(session.isBound, isTrue);
      final poster = _FakePoster([_dpopTokens()]);

      final outcome = await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt_abc',
        session: session,
      );
      expect(outcome.isOk, isTrue);
      expect(outcome.attachedProof, isTrue);

      final proof = poster.calls[0].dpopProof;
      final decoded = _decodeProof(proof);
      expect(decoded.header['typ'], 'dpop+jwt');
      expect(decoded.header['alg'], 'ES256');
      expect(decoded.header['jwk'], isNotNull);
      expect(decoded.payload['htm'], 'POST');
      expect(decoded.payload['htu'], '$kBaseUrl/v1/auth/refresh');
      expect(decoded.payload['jti'], isA<String>());
      expect(
        (decoded.payload['jti'] as String).length,
        greaterThanOrEqualTo(22),
      );
      final nowSec = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
      expect(decoded.payload['iat'], isA<int>());
      expect((decoded.payload['iat'] as int) - nowSec, inInclusiveRange(-5, 5));
      // NO `ath` on the refresh endpoint (RFC 9449 §4.3(12)).
      expect(decoded.payload.containsKey('ath'), isFalse);

      // The signature is a REAL ES256 over the signing input (not just structural).
      expect(signer.verifyCompactJws(proof!), isTrue);
    });

    test('dpop_proof_jwk_is_public_only_no_private_members', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
      );
      final poster = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      final jwk =
          _decodeProof(poster.calls[0].dpopProof).header['jwk']
              as Map<String, Object?>;
      for (final priv in ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
        expect(
          jwk.containsKey(priv),
          isFalse,
          reason: 'proof jwk must not carry private member "$priv"',
        );
      }
      expect(jwk['kty'], 'EC');
      expect(jwk['crv'], 'P-256');
      expect(jwk.keys.toList()..sort(), ['crv', 'kty', 'x', 'y']);
    });
  });

  group('Bearer/no-prover negative pins (the bound branch is real)', () {
    test('bearer_session_attaches_no_proof (no dpop session at all)', () async {
      final poster = _FakePoster([_bearerTokens()]);
      final outcome = await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: null,
      );
      expect(outcome.isOk, isTrue);
      expect(outcome.attachedProof, isFalse);
      expect(poster.calls[0].dpopProof, isNull);
    });

    test('unbound_session_attaches_no_proof (cold start)', () async {
      // A session that has NOT observed a DPoP issuance is not bound.
      final session = DpopSession(
        prover: NativeKeystoreDpopProver(
          signer: _PointyCastleEs256Signer.generate(),
        ),
        baseUrl: kBaseUrl,
      );
      expect(session.isBound, isFalse);
      final poster = _FakePoster([_bearerTokens()]);
      await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      expect(poster.calls[0].dpopProof, isNull);
    });

    test(
      'server_downgrade_to_bearer_marks_session_not_bound_and_refresh_attaches_no_proof',
      () async {
        var downgradeCalls = 0;
        final session = DpopSession(
          prover: NativeKeystoreDpopProver(
            signer: _PointyCastleEs256Signer.generate(),
          ),
          baseUrl: kBaseUrl,
          onDowngrade: (_) => downgradeCalls += 1,
        );
        // Issuance presented a proof but the server returned Bearer (downgrade).
        await session.observeTokenType('Bearer', attachedProof: true);
        expect(session.isBound, isFalse);
        expect(session.isDowngraded, isTrue);
        expect(downgradeCalls, 1);

        final poster = _FakePoster([_bearerTokens()]);
        await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        expect(poster.calls[0].dpopProof, isNull);
      },
    );

    test(
      'bound_session_with_throwing_signer_yields_typed_error_never_silent_bearer',
      () async {
        final session = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _FailingSigner.generate()),
        );
        final poster = _FakePoster([]); // NO response should ever be consumed
        final outcome = await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        expect(outcome.isOk, isFalse);
        expect(
          outcome.error!.errorClass,
          DpopRefreshErrorClass.dpopProverUnavailable,
        );
        expect(outcome.error!.code, 'auth/dpop_prover_unavailable');
        // CRITICAL: NO proof-less (Bearer) network call.
        expect(poster.calls, isEmpty);
      },
    );

    test('bound_session_with_non_jose_signature_yields_typed_error', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _BadLengthSigner.generate()),
      );
      final poster = _FakePoster([]);
      final outcome = await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      expect(outcome.isOk, isFalse);
      expect(
        outcome.error!.errorClass,
        DpopRefreshErrorClass.dpopProverUnavailable,
      );
      expect(poster.calls, isEmpty);
    });
  });

  group('fresh jti per network attempt', () {
    test('distinct_jti_two_refreshes', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
      );
      final a = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: a.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      final b = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: b.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      final jti1 = _decodeProof(a.calls[0].dpopProof).payload['jti'];
      final jti2 = _decodeProof(b.calls[0].dpopProof).payload['jti'];
      expect(jti1, isNot(equals(jti2)));
    });

    test(
      'transport_second_attempt_mints_distinct_jti (rebuilt per HTTP attempt)',
      () async {
        final session = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        final poster = _FakePoster([
          _nonceChallenge('srv-nonce-1'),
          _dpopTokens(),
        ]);
        final outcome = await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        expect(outcome.isOk, isTrue);
        final jti0 = _decodeProof(poster.calls[0].dpopProof).payload['jti'];
        final jti1 = _decodeProof(poster.calls[1].dpopProof).payload['jti'];
        expect(jti0, isNot(equals(jti1)));
      },
    );
  });

  group('same key across refreshes (CURRENT single-key policy)', () {
    test('same_jkt_across_refreshes_and_committed_boundJkt', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
      );
      final a = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: a.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      final b = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: b.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );

      final jwk1 =
          _decodeProof(a.calls[0].dpopProof).header['jwk']
              as Map<String, Object?>;
      final jwk2 =
          _decodeProof(b.calls[0].dpopProof).header['jwk']
              as Map<String, Object?>;
      expect(jwk2, equals(jwk1)); // same public key across refreshes
      // Committed boundJkt equals the RFC 7638 thumbprint of that key.
      expect(session.boundJkt, _rfc7638(jwk1));
    });

    test(
      'fresh_session_uses_a_distinct_keypair (per-session, not global)',
      () async {
        final a = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        final b = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        // Force boundJkt to commit.
        await a.jktHint();
        await b.jktHint();
        expect(a.boundJkt, isNotNull);
        expect(b.boundJkt, isNotNull);
        expect(a.boundJkt, isNot(equals(b.boundJkt)));
      },
    );

    test(
      'jkt_at_issuance_equals_jkt_at_refresh (stable + same instance)',
      () async {
        final prover = NativeKeystoreDpopProver(
          signer: _PointyCastleEs256Signer.generate(),
        );
        final session = _boundSessionFrom(prover);
        final atIssuance = await session.jktHint();
        final poster = _FakePoster([_dpopTokens()]);
        await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        final jwk =
            _decodeProof(poster.calls[0].dpopProof).header['jwk']
                as Map<String, Object?>;
        expect(_rfc7638(jwk), atIssuance);
        // Stable across repeated calls.
        expect(await session.jktHint(), atIssuance);
      },
    );
  });

  group('exactly one nonce retry', () {
    test(
      'use_dpop_nonce_triggers_exactly_one_retry_with_nonce_echoed',
      () async {
        final session = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        final poster = _FakePoster([
          _nonceChallenge('NONCE-XYZ'),
          _dpopTokens(),
        ]);
        final outcome = await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        expect(outcome.isOk, isTrue);
        expect(poster.calls.length, 2); // challenged + retry
        expect(
          _decodeProof(poster.calls[0].dpopProof).payload.containsKey('nonce'),
          isFalse,
        );
        expect(
          _decodeProof(poster.calls[1].dpopProof).payload['nonce'],
          'NONCE-XYZ',
        );
      },
    );

    test(
      'use_dpop_nonce_returned_twice_stops_after_one_retry_terminal_error',
      () async {
        final session = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        final poster = _FakePoster([
          _nonceChallenge('N1'),
          _nonceChallenge('N2'),
        ]);
        final outcome = await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        expect(outcome.isOk, isFalse);
        expect(
          outcome.error!.errorClass,
          DpopRefreshErrorClass.invalidDpopProof,
        );
        expect(poster.calls.length, 2); // 2 attempts, NO third
      },
    );

    test(
      'same_refresh_token_re_presented_on_nonce_retry (no rotation between attempts)',
      () async {
        final session = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        final poster = _FakePoster([_nonceChallenge('N1'), _dpopTokens()]);
        await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt_abc',
          session: session,
        );
        expect(poster.calls[0].refreshToken, 'rt_abc');
        expect(poster.calls[1].refreshToken, 'rt_abc');
      },
    );
  });

  group('proof carries no PII (GDPR Art. 5(1)(c))', () {
    test('dpop_proof_carries_no_pii_exact_claim_set', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
      );
      final poster = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      final decoded = _decodeProof(poster.calls[0].dpopProof);
      expect(decoded.payload.keys.toList()..sort(), [
        'htm',
        'htu',
        'iat',
        'jti',
      ]);
      expect(decoded.header.keys.toList()..sort(), ['alg', 'jwk', 'typ']);
    });
  });

  group('shared canonical-htu golden vector (server-anchored, all 4 packages)', () {
    late List<Map<String, Object?>> cases;
    setUpAll(() {
      // The cross-SDK vectors (a copy of the shared fixture).
      final f = File('test/fixtures/dpop-canonicalization-parity-vectors.json');
      expect(f.existsSync(), isTrue, reason: 'shared golden fixture missing');
      final json = jsonDecode(f.readAsStringSync()) as Map<String, Object?>;
      cases = (json['cases'] as List).cast<Map<String, Object?>>();
    });

    test('flutter_canonicalizeUrl_matches_every_reachable_shared_vector', () {
      // IDN/NFC vectors are a DOCUMENTED RESIDUAL: the Dart core `Uri` parser does
      // NOT punycode-encode a Unicode host, and adding a punycode runtime dep is
      // out of scope + forbidden by the no-new-runtime-dep rule. The
      // issuer/API host is a FROZEN ASCII host, so an IDN `htu` is structurally
      // unreachable in production; the `@rakomi/node` oracle covers the IDN/NFC
      // vectors. We assert all ASCII vectors and explicitly SKIP the 2 IDN ones.
      var asserted = 0;
      var skipped = 0;
      for (final c in cases) {
        final input = c['input'] as String;
        final expected = c['expectedCanonical'] as String;
        final rule = c['rule'] as String;
        final isIdn =
            rule.contains('Punycode') ||
            rule.contains('NFC') ||
            expected.contains('xn--');
        if (isIdn) {
          skipped += 1;
          continue; // documented residual — frozen ASCII issuer host
        }
        expect(canonicalizeUrl(input), expected, reason: 'case: $rule');
        asserted += 1;
      }
      expect(asserted, 13, reason: 'all 13 reachable ASCII vectors asserted');
      expect(skipped, 2, reason: 'exactly the 2 IDN/NFC vectors are skipped');
    });

    test(
      'golden_htu_through_resolveProof_query_fragment_mixedcase_host_443',
      () async {
        final golden = cases.firstWhere(
          (c) =>
              c['input'] ==
              'HTTPS://API.RAKOMI.COM:443/oauth/token/?next=evil#x',
        );
        expect(
          golden['expectedCanonical'],
          'https://api.rakomi.com/oauth/token',
        );
        // Through the session's resolveProof (the path the refresh actually uses).
        final session = DpopSession(
          prover: NativeKeystoreDpopProver(
            signer: _PointyCastleEs256Signer.generate(),
          ),
          baseUrl: 'HTTPS://API.RAKOMI.COM:443',
        );
        final proof = await session.resolveProof(
          'POST',
          '/oauth/token/?next=evil#x',
        );
        expect(_decodeProof(proof).payload['htu'], golden['expectedCanonical']);
      },
    );

    test('refresh_proof_htu_matches_oracle_for_a_bound_session', () async {
      final session = DpopSession(
        prover: NativeKeystoreDpopProver(
          signer: _PointyCastleEs256Signer.generate(),
        ),
        baseUrl: 'HTTPS://API.RAKOMI.COM:443',
      );
      await session.observeTokenType('DPoP', attachedProof: true);
      final poster = _FakePoster([_dpopTokens()]);
      await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: 'HTTPS://API.RAKOMI.COM:443/oauth/token',
        refreshToken: 'rt',
        session: session,
      );
      expect(
        _decodeProof(poster.calls[0].dpopProof).payload['htu'],
        'https://api.rakomi.com/oauth/token',
      );
    });
  });

  group('distinct three-class failure taxonomy', () {
    test(
      'server_invalid_dpop_proof_maps_to_invalid_dpop_proof_class',
      () async {
        final session = _boundSessionFrom(
          NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
        );
        final poster = _FakePoster([_proofRejected()]);
        final outcome = await refreshWithDpop(
          post: poster.post,
          tokenEndpoint: kTokenEndpoint,
          refreshToken: 'rt',
          session: session,
        );
        expect(outcome.isOk, isFalse);
        expect(
          outcome.error!.errorClass,
          DpopRefreshErrorClass.invalidDpopProof,
        );
      },
    );

    test('revoked_refresh_token_maps_to_invalid_refresh_token_class', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _PointyCastleEs256Signer.generate()),
      );
      final poster = _FakePoster([_revoked()]);
      final outcome = await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: session,
      );
      expect(outcome.isOk, isFalse);
      expect(
        outcome.error!.errorClass,
        DpopRefreshErrorClass.invalidRefreshToken,
      );
    });

    test('bearer_refresh_returns_attachedProof_false', () async {
      final poster = _FakePoster([_bearerTokens()]);
      final outcome = await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'rt',
        session: null,
      );
      expect(outcome.isOk, isTrue);
      expect(outcome.attachedProof, isFalse);
    });

    test('three_classes_have_distinct_wire_codes', () {
      final codes = DpopRefreshErrorClass.values.map((c) => c.wire).toSet();
      expect(codes, {
        'auth/dpop_prover_unavailable',
        'auth/invalid_dpop_proof',
        'auth/invalid_refresh_token',
        'auth/network',
      });
    });
  });

  group('no-secret-in-logs — error surfaces never carry token/proof bytes', () {
    test('dpop_refresh_error_toString_has_no_jwt_shape', () async {
      final session = _boundSessionFrom(
        NativeKeystoreDpopProver(signer: _FailingSigner.generate()),
      );
      final poster = _FakePoster([]);
      final outcome = await refreshWithDpop(
        post: poster.post,
        tokenEndpoint: kTokenEndpoint,
        refreshToken: 'super-secret-refresh-token',
        session: session,
      );
      final s = outcome.error.toString();
      expect(s.contains('super-secret-refresh-token'), isFalse);
      expect(RegExp(r'eyJ[A-Za-z0-9_\-]+\.eyJ').hasMatch(s), isFalse);
    });
  });
}

/// RFC 7638 thumbprint of an EC public JWK (lexicographic members, no whitespace,
/// base64url-no-pad). Mirrors the prover's `jktHint` for cross-checking.
String _rfc7638(Map<String, Object?> jwk) {
  final canonical = jsonEncode(<String, Object?>{
    'crv': jwk['crv'],
    'kty': jwk['kty'],
    'x': jwk['x'],
    'y': jwk['y'],
  });
  final digest = sha256.convert(utf8.encode(canonical)).bytes;
  final s = base64Url.encode(digest);
  final pad = s.indexOf('=');
  return pad == -1 ? s : s.substring(0, pad);
}
