// Review finding #1254 (Medium): `getToken()` must not hand back an
// already-in-memory access token when it is inside `_refreshLeadtime` of
// `exp` AND the refresh that was needed to renew it was blocked by a denied
// biometric prompt. Before the fix, `_refresh()` failing on the biometric-
// lock branch left `_accessToken` untouched, so the caller received the
// stale, soon-to-expire token back silently while `authState` had already
// moved to `AuthStateError(biometricError)`.
//
// This needs a GENUINELY VALID (RS256-signed, JWKS-verifiable) access token
// in memory to exercise the branch at all — `getToken()` only calls
// `_refresh()` when the in-memory token IS expiring soon, and `_refresh()`
// only ever assigns `_accessToken` after `_verifyToken()` passes. The other
// controller-wiring suites in this package (`refresh_dpop_wiring_test.dart`)
// deliberately avoid real JWTs because they don't need a token to already be
// held in memory; this test does, so it reuses the same fixture-based
// signing approach as `jwt_verify_test.dart`.

import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';
import 'helpers/test_rsa_key.dart';

const String _kApiBase = 'https://api.rakomi.test';
const String _kTenant = 'acme';
const String _kIssuer = 'https://api.rakomi.test';
const String _kAudience = 'pk_test_demo';
const String _kStoredRefresh = 'rt_stored_credential';

class _MemoryJwksStorage implements JwksStorage {
  final Map<String, String> _m = {};
  @override
  Future<String?> readKey(String key) async => _m[key];
  @override
  Future<void> writeKey(String key, String value) async => _m[key] = value;
  @override
  Future<void> deleteKey(String key) async => _m.remove(key);
}

late djw.RSAPrivateKey _privateKey;
late String _jwksBody;

String _signAccessToken({required Duration expiresIn}) {
  final now = DateTime.now().toUtc();
  final jwt = djw.JWT(
    <String, Object?>{
      'iss': _kIssuer,
      'aud': _kAudience,
      'sub': 'usr_001',
      'email': 'user@example.com',
      'iat': now.millisecondsSinceEpoch ~/ 1000,
      'exp': now.add(expiresIn).millisecondsSinceEpoch ~/ 1000,
    },
    header: <String, Object?>{'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'},
  );
  return jwt.sign(_privateKey, algorithm: djw.JWTAlgorithm.RS256);
}

void main() {
  setUpAll(() {
    _privateKey = testRsaPrivateKey();
    _jwksBody = testJwksBody();
  });

  test('getToken() returns null (never the stale token) when a soon-expiring '
      'session hits a denied biometric prompt on refresh', () async {
    BiometricResult biometric = const BiometricSuccess();
    final adapter = FakeRakomiNativeAdapter(biometricResult: biometric);
    final freshAccessToken = _signAccessToken(
      expiresIn: const Duration(seconds: 10),
    );
    adapter.mockClient = http_test.MockClient((http.Request r) async {
      if (r.url.path == '/.well-known/jwks.json') {
        return http.Response(
          _jwksBody,
          200,
          headers: {'content-type': 'application/json'},
        );
      }
      if (r.url.path == '/v1/auth/refresh') {
        return http.Response(
          jsonEncode({'access_token': freshAccessToken}),
          200,
          headers: {'content-type': 'application/json'},
        );
      }
      return http.Response(
        '{}',
        200,
        headers: {'content-type': 'application/json'},
      );
    });
    await adapter.storageWrite(
      'rakomi.v1.refresh_token.$_kTenant',
      _kStoredRefresh,
    );
    final auth = RakomiAuth(
      tenantId: _kTenant,
      publishableKey: 'pk_test',
      apiBaseUrl: _kApiBase,
      issuer: _kIssuer,
      audience: _kAudience,
      adapter: adapter,
      jwksCache: JwksCache(
        tenantId: _kTenant,
        jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
        storage: _MemoryJwksStorage(),
        httpClient: adapter.mockClient,
      ),
      // Zero window: every credential use (incl. the second getToken()
      // call below) re-prompts, matching the real "each refresh checks
      // freshness" behaviour when the prior unlock is not being reused.
      freshAuthWindow: Duration.zero,
      requireBiometricUnlock: true,
    );

    // 1) Prime a real, verifiable, but SOON-EXPIRING (10s, well inside the
    //    default 60s refresh leadtime) access token in memory.
    final firstToken = await auth.getToken();
    expect(firstToken, freshAccessToken);
    expect(adapter.biometricRequestCount, 1);

    // 2) The unlock is denied on the next credential use (e.g. the user
    //    cancels the resume prompt). `_accessToken` is still the
    //    still-technically-valid-but-expiring-in-10s token from step 1.
    biometric = const BiometricCancelled();
    adapter.biometricResult = biometric;

    final secondToken = await auth.getToken();

    expect(
      secondToken,
      isNull,
      reason:
          'a denied biometric prompt must never hand back the stale, '
          'soon-to-expire in-memory token',
    );
    expect(adapter.biometricRequestCount, 2);
    expect(auth.authState, isA<AuthStateError>());
    expect(
      (auth.authState as AuthStateError).error.code,
      SdkErrorCode.biometricError,
    );

    auth.dispose();
  });
}
