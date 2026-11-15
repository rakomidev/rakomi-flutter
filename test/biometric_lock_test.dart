// Biometric lock in front of the stored credential.
//
// With `requireBiometricUnlock` on, `hydrate()`, `getToken()` and the refresh
// path must not read or use the stored refresh token until a biometric prompt
// has succeeded within `freshAuthWindow`. A denied prompt yields no token and a
// typed `biometricError`. With the lock off, nothing prompts.
//
// The refresh endpoint answers 500 (a transient failure that keeps the stored
// credential), so the tests observe whether the stored refresh token was ever
// sent, without needing a signed token.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';

import 'helpers/fake_adapter.dart';

const String _kApiBase = 'https://api.test.io';
const String _kTenant = 'acme';
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

class _Built {
  _Built(this.auth, this.adapter, this.sentRefreshTokens);
  final RakomiAuth auth;
  final FakeRakomiNativeAdapter adapter;
  final List<String> sentRefreshTokens;
}

Future<_Built> _build({
  required bool lock,
  required BiometricResult biometric,
  Duration window = const Duration(seconds: 30),
}) async {
  final sent = <String>[];
  final adapter = FakeRakomiNativeAdapter(biometricResult: biometric);
  adapter.mockClient = http_test.MockClient((http.Request r) async {
    if (r.url.path == '/v1/auth/refresh') {
      final body = jsonDecode(r.body) as Map<String, Object?>;
      sent.add(body['refresh_token']! as String);
      // A transient failure that keeps the session and is not retried at once
      // (a 500 is retried once and then ends the session), so every send seen
      // here is one credential use.
      return http.Response('{}', 503);
    }
    return http.Response(
      '{}',
      200,
      headers: <String, String>{'content-type': 'application/json'},
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
    issuer: _kApiBase,
    audience: 'aud',
    adapter: adapter,
    jwksCache: JwksCache(
      tenantId: _kTenant,
      jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
      storage: _MemoryJwksStorage(),
      httpClient: adapter.mockClient,
    ),
    freshAuthWindow: window,
    requireBiometricUnlock: lock,
  );
  return _Built(auth, adapter, sent);
}

void expectBiometricError(AuthState state, SdkErrorReason reason) {
  expect(state, isA<AuthStateError>());
  final err = (state as AuthStateError).error;
  expect(err.code, SdkErrorCode.biometricError);
  expect(err.reason, reason);
}

void main() {
  group('biometric lock on, prompt denied', () {
    test(
      'getToken returns no token and never sends the stored credential',
      () async {
        final b = await _build(
          lock: true,
          biometric: const BiometricCancelled(),
        );

        final token = await b.auth.getToken();

        expect(token, isNull);
        expect(
          b.sentRefreshTokens,
          isEmpty,
          reason:
              'the stored refresh token was used without a successful '
              'biometric prompt',
        );
        expect(b.adapter.biometricRequestCount, 1);
        expectBiometricError(
          b.auth.authState,
          SdkErrorReason.biometricCancelled,
        );
      },
    );

    test(
      'hydrate settles on a biometric error and keeps the credential',
      () async {
        final b = await _build(lock: true, biometric: const BiometricLockout());

        await b.auth.hydrate();

        expect(b.sentRefreshTokens, isEmpty);
        expect(b.adapter.biometricRequestCount, 1);
        expectBiometricError(b.auth.authState, SdkErrorReason.biometricLockout);
        expect(
          await b.adapter.storageRead('rakomi.v1.refresh_token.$_kTenant'),
          _kStoredRefresh,
        );
      },
    );

    test('refreshTokens never sends the stored credential', () async {
      final b = await _build(
        lock: true,
        biometric: const BiometricNotEnrolled(),
      );

      final session = await b.auth.refreshTokens();

      expect(session, isNull);
      expect(b.sentRefreshTokens, isEmpty);
      expectBiometricError(
        b.auth.authState,
        SdkErrorReason.biometricNotEnrolled,
      );
    });
  });

  group('biometric lock on, prompt succeeds', () {
    test('hydrate uses the credential; a refresh inside the window does not '
        'prompt again', () async {
      final b = await _build(lock: true, biometric: const BiometricSuccess());

      await b.auth.hydrate();
      expect(b.sentRefreshTokens, [_kStoredRefresh]);
      expect(b.adapter.biometricRequestCount, 1);

      await b.auth.refreshTokens();
      expect(b.sentRefreshTokens, [_kStoredRefresh, _kStoredRefresh]);
      expect(b.adapter.biometricRequestCount, 1);
    });

    test('a zero window prompts on every credential use', () async {
      final b = await _build(
        lock: true,
        biometric: const BiometricSuccess(),
        window: Duration.zero,
      );

      await b.auth.hydrate();
      await b.auth.refreshTokens();

      expect(b.adapter.biometricRequestCount, 2);
      expect(b.sentRefreshTokens, hasLength(2));
    });

    test('unlockWithBiometric after a denial retries hydration without a '
        'second prompt', () async {
      final b = await _build(
        lock: true,
        biometric: const BiometricCancelled(),
        window: Duration.zero,
      );

      await b.auth.hydrate();
      expect(b.sentRefreshTokens, isEmpty);

      b.adapter.biometricResult = const BiometricSuccess();
      await b.auth.unlockWithBiometric(reason: 'Unlock');

      expect(b.sentRefreshTokens, [_kStoredRefresh]);
      expect(b.adapter.biometricRequestCount, 2);
    });
  });

  group('resume-driven refresh does not loop (review #1254 HIGH)', () {
    test('a denied biometric prompt on resume is not immediately retried by a '
        'second resume within the denial cooldown', () async {
      final b = await _build(lock: true, biometric: const BiometricCancelled());

      await b.auth.refreshIfNeededOnResume();
      expect(b.adapter.biometricRequestCount, 1);
      expectBiometricError(b.auth.authState, SdkErrorReason.biometricCancelled);

      // Simulates the iOS local_auth `inactive`->`resumed` feedback loop:
      // the dismissed system sheet itself re-fires `resumed` immediately.
      await b.auth.refreshIfNeededOnResume();
      expect(
        b.adapter.biometricRequestCount,
        1,
        reason: 'a resume within the denial cooldown must not re-prompt',
      );
    });

    test('contrast case: refreshTokens() (the pre-fix resume wiring) DOES '
        're-prompt on every call, showing why refreshIfNeededOnResume is the '
        'actual fix', () async {
      final b = await _build(lock: true, biometric: const BiometricCancelled());

      await b.auth.refreshTokens();
      expect(b.adapter.biometricRequestCount, 1);

      // The OLD `provider.dart` wiring called this directly on every
      // `resumed` event; it always forces a fresh prompt, which is exactly
      // the undismissable loop the finding describes.
      await b.auth.refreshTokens();
      expect(
        b.adapter.biometricRequestCount,
        2,
        reason:
            'refreshTokens() always re-prompts, by design (see its own '
            'doc comment) — it must never be wired to a lifecycle event',
      );
    });

    test('once the denial cooldown elapses, the next resume prompts again '
        '(a UX cooldown, not a permanent lockout)', () async {
      final b = await _build(lock: true, biometric: const BiometricCancelled());

      await b.auth.refreshIfNeededOnResume();
      expect(b.adapter.biometricRequestCount, 1);

      // No fake-clock seam exists for the internal denial-cooldown timer;
      // this waits it out for real (cooldown is a fixed 2s).
      await Future<void>.delayed(const Duration(seconds: 2, milliseconds: 150));

      await b.auth.refreshIfNeededOnResume();
      expect(
        b.adapter.biometricRequestCount,
        2,
        reason: 'a resume after the cooldown must prompt again',
      );
    });
  });

  group('biometric lock off', () {
    test('never prompts and uses the stored credential', () async {
      final b = await _build(
        lock: false,
        biometric: const BiometricCancelled(),
      );

      await b.auth.hydrate();
      await b.auth.refreshTokens();

      expect(b.adapter.biometricRequestCount, 0);
      expect(b.sentRefreshTokens, [_kStoredRefresh, _kStoredRefresh]);
    });

    test('is the default', () async {
      final adapter = FakeRakomiNativeAdapter();
      final auth = RakomiAuth(
        tenantId: _kTenant,
        publishableKey: 'pk_test',
        apiBaseUrl: _kApiBase,
        issuer: _kApiBase,
        audience: 'aud',
        adapter: adapter,
        jwksCache: JwksCache(
          tenantId: _kTenant,
          jwksUrl: Uri.parse('$_kApiBase/.well-known/jwks.json'),
          storage: _MemoryJwksStorage(),
          httpClient: adapter.mockClient,
        ),
      );
      expect(auth.requireBiometricUnlock, isFalse);
    });
  });
}
