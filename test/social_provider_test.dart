import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

void main() {
  group('SocialProvider wire identifiers', () {
    test('all 10 main providers have wire mappings', () {
      const expected = <SocialProvider, String>{
        SocialProvider.google: 'google',
        SocialProvider.github: 'github',
        SocialProvider.microsoft: 'microsoft',
        SocialProvider.apple: 'apple',
        SocialProvider.discord: 'discord',
        SocialProvider.facebook: 'facebook',
        SocialProvider.slack: 'slack',
        SocialProvider.twitter: 'twitter',
        SocialProvider.gitlab: 'gitlab',
        SocialProvider.linkedin: 'linkedin',
      };
      expected.forEach((p, w) => expect(p.wire, w));
    });

    test('eudiWallet placeholder maps to "eudi_wallet"', () {
      expect(SocialProvider.eudiWallet.wire, equals('eudi_wallet'));
    });
  });

  group('User decoding', () {
    test('User.fromJson handles both `sub`/`id` + `tenant_id`/`tenantId`', () {
      final u1 = User.fromJson(<String, Object?>{
        'sub': 'u1',
        'email': 'a@b.com',
        'email_verified': true,
        'tenant_id': 't1',
      });
      expect(u1.id, equals('u1'));
      expect(u1.tenantId, equals('t1'));

      final u2 = User.fromJson(<String, Object?>{
        'id': 'u2',
        'email': 'b@b.com',
        'tenantId': 't2',
      });
      expect(u2.id, equals('u2'));
      expect(u2.tenantId, equals('t2'));
    });

    test('User equality keyed on (id, tenantId)', () {
      const a = User(id: 'u1', email: 'a@b.com', tenantId: 't1');
      const b = User(id: 'u1', email: 'different@b.com', tenantId: 't1');
      expect(
        a,
        equals(b),
        reason: 'email + claims diff should not break identity equality',
      );
    });
  });

  group('Session expiry helpers', () {
    test('isExpired — true after exp', () {
      final s = Session(
        id: 's',
        userId: 'u',
        tenantId: 't',
        issuedAt: DateTime.utc(2026, 1, 1),
        expiresAt: DateTime.utc(2026, 1, 1, 0, 15),
      );
      expect(s.isExpired(now: DateTime.utc(2026, 1, 1, 0, 16)), isTrue);
      expect(s.isExpired(now: DateTime.utc(2026, 1, 1, 0, 14)), isFalse);
    });

    test('isExpiringSoon — true when within leadtime of exp', () {
      final s = Session(
        id: 's',
        userId: 'u',
        tenantId: 't',
        issuedAt: DateTime.utc(2026, 1, 1),
        expiresAt: DateTime.utc(2026, 1, 1, 0, 15),
      );
      // 30 seconds before exp, with 60s leadtime → expiring soon.
      expect(
        s.isExpiringSoon(now: DateTime.utc(2026, 1, 1, 0, 14, 30)),
        isTrue,
      );
      // 90 seconds before exp, with 60s leadtime → not yet expiring.
      expect(
        s.isExpiringSoon(now: DateTime.utc(2026, 1, 1, 0, 13, 30)),
        isFalse,
      );
    });
  });
}
