import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/oauth/oauth_state.dart';

import 'helpers/fake_adapter.dart';

void main() {
  group('PersistedOAuthState', () {
    test('begin() persists state + verifier paired by oneTimeId', () async {
      final adapter = FakeRakomiNativeAdapter();
      final p = PersistedOAuthState(tenantId: 'acme', adapter: adapter);
      final bundle = await p.begin();
      expect(bundle.state.length, equals(43));
      expect(bundle.verifier.length, equals(43));
      expect(bundle.oneTimeId.length, equals(32));
      expect(bundle.challenge.length, equals(43));
    });

    test(
      'validateAndConsume — happy path returns ok+verifier and deletes entries',
      () async {
        final adapter = FakeRakomiNativeAdapter();
        final p = PersistedOAuthState(tenantId: 'acme', adapter: adapter);
        final b = await p.begin();
        final r = await p.validateAndConsume(
          oneTimeId: b.oneTimeId,
          callbackState: b.state,
        );
        expect(r.ok, isTrue);
        expect(r.verifier, equals(b.verifier));
        // Verify single-use deletion.
        final after = await p.validateAndConsume(
          oneTimeId: b.oneTimeId,
          callbackState: b.state,
        );
        expect(after.ok, isFalse);
      },
    );

    test(
      'validateAndConsume — state mismatch returns ok=false and deletes entries',
      () async {
        final adapter = FakeRakomiNativeAdapter();
        final p = PersistedOAuthState(tenantId: 'acme', adapter: adapter);
        final b = await p.begin();
        final r = await p.validateAndConsume(
          oneTimeId: b.oneTimeId,
          callbackState: 'attacker-state',
        );
        expect(r.ok, isFalse);
        expect(r.verifier, isNull);
        // Replay with the correct state — entries already deleted, fails.
        final replay = await p.validateAndConsume(
          oneTimeId: b.oneTimeId,
          callbackState: b.state,
        );
        expect(replay.ok, isFalse);
      },
    );

    test('sweep clears stale entries', () async {
      final adapter = FakeRakomiNativeAdapter();
      final p = PersistedOAuthState(tenantId: 'acme', adapter: adapter);
      await p.begin();
      await p.begin();
      final swept = await p.sweep();
      expect(swept, equals(2));
      // After sweep, no oauth_state.* keys remain for this tenant.
      final remaining = await adapter.storageReadByPrefix(
        'rakomi.v1.oauth_state.acme.',
      );
      expect(remaining, isEmpty);
    });
  });
}
