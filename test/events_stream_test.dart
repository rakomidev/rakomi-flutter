import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

void main() {
  group('AuthEvent', () {
    test('AuthEventType has all 32 expected values', () {
      // 24 web + 5 RN + 3 Flutter-specific = 32
      expect(AuthEventType.values.length, equals(32));
    });

    test('AuthEventSeverity has 3 levels', () {
      expect(
        AuthEventSeverity.values,
        equals(<AuthEventSeverity>[
          AuthEventSeverity.info,
          AuthEventSeverity.warning,
          AuthEventSeverity.security,
        ]),
      );
    });

    test('toJson includes type, severity, ISO timestamp', () {
      final e = AuthEvent(
        type: AuthEventType.signedIn,
        severity: AuthEventSeverity.info,
      );
      final json = e.toJson();
      expect(json['type'], equals('signedIn'));
      expect(json['severity'], equals('info'));
      expect(json['timestamp'], isA<String>());
      // ISO 8601 with `Z` suffix or `+HH:MM` offset.
      expect((json['timestamp'] as String).contains('T'), isTrue);
    });

    test('toJson optional fields gated on presence', () {
      final e1 = AuthEvent(
        type: AuthEventType.signedIn,
        severity: AuthEventSeverity.info,
      );
      expect(e1.toJson().containsKey('errorMessage'), isFalse);
      expect(e1.toJson().containsKey('metadata'), isFalse);

      final e2 = AuthEvent(
        type: AuthEventType.refreshFailed,
        severity: AuthEventSeverity.warning,
        errorMessage: 'http_503',
        metadata: <String, Object?>{'attempt': 3},
      );
      expect(e2.toJson()['errorMessage'], equals('http_503'));
      expect(e2.toJson()['metadata'], isA<Map<String, Object?>>());
    });

    test('timestamp default is UTC', () {
      final e = AuthEvent(
        type: AuthEventType.signedIn,
        severity: AuthEventSeverity.info,
      );
      expect(e.timestamp.isUtc, isTrue);
    });

    test('toString is non-empty diagnostic form', () {
      final s = AuthEvent(
        type: AuthEventType.deepLinkReceived,
        severity: AuthEventSeverity.security,
      ).toString();
      expect(s, contains('deepLinkReceived'));
      expect(s, contains('security'));
    });
  });
}
