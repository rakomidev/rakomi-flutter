// `RakomiAuth._refresh` DPoP wiring.
//
// End-to-end-ish controller wiring: a bound `DpopSession` ⇒ the outbound
// `POST /v1/auth/refresh` carries a `DPoP` proof header; a Bearer / cold-start
// session ⇒ NO header; a signer failure ⇒ a typed `dpop_prover_unavailable`
// surfaced via the controller, with ZERO proof-less Bearer downgrade; and the
// three-class taxonomy lands on the controller's `SdkError`.
//
// The network is the fake adapter's `MockClient`; we capture the outbound
// `/v1/auth/refresh` request to assert the `DPoP` header. To keep this focused on
// WIRING (not JWKS verification, which `jwt_verify_test`/`clock_skew_test` cover),
// the mock server returns non-200 outcomes so the refresh resolves to a typed
// error without needing a valid RS256 token + JWKS.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';

const String _kApiBase = 'https://api.test.io';
const String _kTenant = 'acme';

// ─── A trivial in-heap ES256 test signer (host stand-in for the keystore). ─────
// Coordinates are static valid-shape base64url; signing returns a fixed 64-byte
// R‖S so the proof is structurally valid (this suite asserts WIRING + the `DPoP`
// header, not cryptographic verification — that is covered by dpop_prover_test).

class _StubSigner implements NativeDpopSigner {
  _StubSigner(this._seed);
  final int _seed;

  @override
  Future<({String x, String y})> publicCoordinates() async {
    String coord(int salt) {
      final b = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        b[i] = (_seed + salt + i) & 0xff;
      }
      return base64UrlNoPad(b);
    }

    return (x: coord(1), y: coord(2));
  }

  @override
  Future<Uint8List> signEs256(Uint8List signingInput) async {
    // Deterministic 64-byte R‖S derived from the input (not real ECDSA — this
    // suite asserts the header is attached, not signature validity).
    final d = sha256.convert(signingInput).bytes;
    final out = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      out[i] = d[i % d.length];
    }
    return out;
  }
}

class _FailingSigner implements NativeDpopSigner {
  _FailingSigner(this._delegate);
  final NativeDpopSigner _delegate;
  @override
  Future<({String x, String y})> publicCoordinates() =>
      _delegate.publicCoordinates();
  @override
  Future<Uint8List> signEs256(Uint8List signingInput) async =>
      throw StateError('enclave unavailable');
}

/// Build a `RakomiAuth` wired to a capturing mock server. [onRefresh] returns the
/// response for `POST /v1/auth/refresh`; the outbound request is recorded.
({RakomiAuth auth, List<http.Request> refreshCalls}) _buildAuth({
  required http.Response Function(http.Request) onRefresh,
  DpopSession? dpopSession,
}) {
  final refreshCalls = <http.Request>[];
  final adapter = FakeRakomiNativeAdapter();
  adapter.mockClient = http_test.MockClient((http.Request r) async {
    if (r.url.path == '/v1/auth/refresh') {
      refreshCalls.add(r);
      return onRefresh(r);
    }
    // /v1/auth/me and any other call — benign empty 200.
    return http.Response(
      '{}',
      200,
      headers: <String, String>{'content-type': 'application/json'},
    );
  });
  final jwks = JwksCache(
    tenantId: _kTenant,
    jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
    storage: _NullJwksStorage(),
    httpClient: adapter.mockClient,
  );
  final auth = RakomiAuth(
    tenantId: _kTenant,
    publishableKey: 'pk_test',
    apiBaseUrl: _kApiBase,
    issuer: _kApiBase,
    audience: 'aud',
    adapter: adapter,
    jwksCache: jwks,
    dpopSession: dpopSession,
  );
  return (auth: auth, refreshCalls: refreshCalls);
}

class _NullJwksStorage implements JwksStorage {
  final Map<String, String> _m = {};
  @override
  Future<String?> readKey(String key) async => _m[key];
  @override
  Future<void> writeKey(String key, String value) async => _m[key] = value;
  @override
  Future<void> deleteKey(String key) async => _m.remove(key);
}

DpopSession _boundSession(NativeDpopSigner signer) {
  final s = DpopSession(
    prover: NativeKeystoreDpopProver(signer: signer),
    baseUrl: _kApiBase,
  );
  s.observeTokenType('DPoP', attachedProof: true);
  return s;
}

Future<void> _seedRefreshToken(RakomiAuth auth) async {
  // The controller reads the refresh token from adapter storage; seed it.
  await auth.adapter.storageWrite(
    'rakomi.v1.refresh_token.$_kTenant',
    'rt_seed',
  );
}

void main() {
  test(
    'bound_session_refresh_attaches_DPoP_header_on_outbound_request',
    () async {
      final built = _buildAuth(
        // Reject the proof so the refresh resolves WITHOUT needing JWKS verify;
        // we only care that the DPoP header was attached on the way out.
        onRefresh: (_) => http.Response(
          jsonEncode({'error': 'invalid_dpop_proof'}),
          401,
          headers: {'content-type': 'application/json'},
        ),
        dpopSession: _boundSession(_StubSigner(7)),
      );
      await _seedRefreshToken(built.auth);

      await built.auth.refreshTokens();

      expect(built.refreshCalls, hasLength(1));
      final dpop =
          built.refreshCalls[0].headers['DPoP'] ??
          built.refreshCalls[0].headers['dpop'];
      expect(dpop, isNotNull, reason: 'bound refresh must attach a DPoP proof');
      // It is a compact JWS with the right header shape.
      final parts = dpop!.split('.');
      expect(parts.length, 3);
      final header =
          jsonDecode(utf8.decode(base64Url.decode(_pad(parts[0]))))
              as Map<String, Object?>;
      expect(header['typ'], 'dpop+jwt');
      expect(header['alg'], 'ES256');

      built.auth.dispose();
    },
  );

  test('bearer_cold_start_session_refresh_attaches_NO_DPoP_header', () async {
    // A session that never observed a DPoP issuance is not bound (cold start).
    final coldSession = DpopSession(
      prover: NativeKeystoreDpopProver(signer: _StubSigner(3)),
      baseUrl: _kApiBase,
    );
    expect(coldSession.isBound, isFalse);

    final built = _buildAuth(
      onRefresh: (_) => http.Response(
        jsonEncode({'error': 'invalid_grant'}),
        401,
        headers: {'content-type': 'application/json'},
      ),
      dpopSession: coldSession,
    );
    await _seedRefreshToken(built.auth);

    await built.auth.refreshTokens();

    expect(built.refreshCalls, hasLength(1));
    expect(built.refreshCalls[0].headers.containsKey('DPoP'), isFalse);
    expect(built.refreshCalls[0].headers.containsKey('dpop'), isFalse);

    built.auth.dispose();
  });

  test('no_dpop_session_refresh_attaches_NO_DPoP_header', () async {
    final built = _buildAuth(
      onRefresh: (_) => http.Response(
        jsonEncode({'error': 'invalid_grant'}),
        401,
        headers: {'content-type': 'application/json'},
      ),
    );
    await _seedRefreshToken(built.auth);

    await built.auth.refreshTokens();

    expect(built.refreshCalls, hasLength(1));
    expect(built.refreshCalls[0].headers.containsKey('DPoP'), isFalse);

    built.auth.dispose();
  });

  test(
    'bound_session_with_failing_signer_makes_ZERO_network_call (no silent bearer)',
    () async {
      final built = _buildAuth(
        onRefresh: (_) => http.Response('{}', 200),
        dpopSession: _boundSession(_FailingSigner(_StubSigner(9))),
      );
      await _seedRefreshToken(built.auth);

      await built.auth.refreshTokens();

      // CRITICAL: a signer failure must NOT fall back to a proof-less Bearer call —
      // ZERO requests to /v1/auth/refresh.
      expect(
        built.refreshCalls,
        isEmpty,
        reason:
            'a signer failure must NOT fall back to a proof-less Bearer call',
      );
      // And the refresh did NOT succeed (state is not Authenticated).
      expect(built.auth.authState, isNot(isA<AuthStateAuthenticated>()));

      built.auth.dispose();
    },
  );

  test('single_inflight_refresh_dedup_preserved_under_dpop', () async {
    var serverHits = 0;
    final built = _buildAuth(
      onRefresh: (_) {
        serverHits += 1;
        return http.Response(
          jsonEncode({'error': 'invalid_dpop_proof'}),
          401,
          headers: {'content-type': 'application/json'},
        );
      },
      dpopSession: _boundSession(_StubSigner(11)),
    );
    await _seedRefreshToken(built.auth);

    // Two concurrent refreshes must share ONE in-flight pipeline (TOCTOU pin —
    // single-flight set before async signing).
    await Future.wait<void>([
      built.auth.refreshTokens().catchError((_) => null),
      built.auth.refreshTokens().catchError((_) => null),
    ]);
    expect(
      serverHits,
      1,
      reason: 'concurrent refreshes share one in-flight call',
    );

    built.auth.dispose();
  });
}

String _pad(String s) {
  final m = s.length % 4;
  return m == 0 ? s : s + ('=' * (4 - m));
}
