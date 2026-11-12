import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/internal/storage_keys.dart';

import 'helpers/fake_adapter.dart';

void main() {
  group('Storage key namespacing', () {
    test('refresh token keyed by tenantId, v1 namespace', () {
      expect(refreshTokenKey('acme'), equals('rakomi.v1.refresh_token.acme'));
    });

    test('JWKS cache keyed by tenantId', () {
      expect(jwksCacheKey('acme'), equals('rakomi.v1.jwks.acme'));
      expect(jwksEtagKey('acme'), equals('rakomi.v1.jwks_etag.acme'));
      expect(
        jwksFetchedAtKey('acme'),
        equals('rakomi.v1.jwks_fetched_at.acme'),
      );
    });

    test('JWKS cache keyed by tenantId AND host, when a host is given', () {
      expect(
        jwksCacheKey('acme', host: 'tenant-a.example.com'),
        equals('rakomi.v1.jwks.acme.h.tenant-a.example.com'),
      );
      expect(
        jwksEtagKey('acme', host: 'tenant-a.example.com'),
        equals('rakomi.v1.jwks_etag.acme.h.tenant-a.example.com'),
      );
      expect(
        jwksFetchedAtKey('acme', host: 'tenant-a.example.com'),
        equals('rakomi.v1.jwks_fetched_at.acme.h.tenant-a.example.com'),
      );
      // A different host is a genuinely different slot — the whole point of
      // scoping the cache per-host (packages/react-native's parity fix).
      expect(
        jwksCacheKey('acme', host: 'tenant-a.example.com'),
        isNot(equals(jwksCacheKey('acme', host: 'tenant-b.example.com'))),
      );
    });

    test('OAuth state + verifier paired by oneTimeId', () {
      const id = 'abc123';
      expect(
        oauthStateKey('acme', id),
        equals('rakomi.v1.oauth_state.acme.$id'),
      );
      expect(
        pkceVerifierKey('acme', id),
        equals('rakomi.v1.pkce_verifier.acme.$id'),
      );
    });

    test('Tenant scoping prevents collision across tenants', () {
      expect(refreshTokenKey('acme'), isNot(equals(refreshTokenKey('beta'))));
    });
  });

  group('FakeRakomiNativeAdapter — storage primitives', () {
    test('write+read roundtrip', () async {
      final a = FakeRakomiNativeAdapter();
      await a.storageWrite('k', 'v');
      expect(await a.storageRead('k'), 'v');
      await a.storageDelete('k');
      expect(await a.storageRead('k'), isNull);
    });

    test('storageReadByPrefix returns matching keys only', () async {
      final a = FakeRakomiNativeAdapter();
      await a.storageWrite('rakomi.v1.refresh_token.acme', 'a');
      await a.storageWrite('rakomi.v1.refresh_token.beta', 'b');
      await a.storageWrite('other.key', 'c');
      final hit = await a.storageReadByPrefix('rakomi.v1.refresh_token.');
      expect(hit.length, 2);
      expect(hit['rakomi.v1.refresh_token.acme'], 'a');
      expect(hit['rakomi.v1.refresh_token.beta'], 'b');
      expect(hit.containsKey('other.key'), isFalse);
    });

    test('marker store distinct from secure store', () async {
      final a = FakeRakomiNativeAdapter();
      await a.storageWrite('shared.key', 'secure');
      await a.markerWrite('shared.key', 'marker');
      expect(await a.storageRead('shared.key'), 'secure');
      expect(await a.markerRead('shared.key'), 'marker');
    });

    test(
      'fresh_install_purge — Keychain residue without marker triggers purge logic',
      () async {
        // Simulate post-uninstall reinstall: Keychain has lifecycle ID, marker
        // (shared_preferences) does NOT — pre-bootstrap sweep deletes
        // rakomi.v1.* Keychain entries before hydration.
        final a = FakeRakomiNativeAdapter();
        await a.storageWrite(lifecycleIdKey('acme'), 'pre-uninstall-id');
        await a.storageWrite(refreshTokenKey('acme'), 'leaked-refresh');
        // Marker store is empty (post-uninstall — shared_preferences cleared).

        final keychainId = await a.storageRead(lifecycleIdKey('acme'));
        final markerId = await a.markerRead(lifecycleMarkerKey('acme'));
        expect(keychainId, isNotNull);
        expect(markerId, isNull);

        // Sweep logic — replicates _freshInstallSweep in provider.dart.
        if (keychainId != null && markerId == null) {
          final entries = await a.storageReadByPrefix('rakomi.v1.');
          for (final key in entries.keys) {
            if (key.contains('.acme')) await a.storageDelete(key);
          }
        }
        expect(
          await a.storageRead(refreshTokenKey('acme')),
          isNull,
          reason: 'leaked refresh token must be purged',
        );
      },
    );
  });
}
