import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

void main() {
  group('SdkError', () {
    test('toString redacts JWT-shape errorMessage', () {
      const e = SdkError(
        code: SdkErrorCode.refreshFailed,
        reason: SdkErrorReason.refreshExpired,
        errorMessage: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature',
      );
      final s = e.toString();
      expect(
        s.contains('eyJ'),
        isFalse,
        reason: 'JWT shape must be redacted from toString output',
      );
      expect(s, contains('[redacted]'));
    });

    test('toString redacts Bearer-prefixed errorMessage', () {
      const e = SdkError(
        code: SdkErrorCode.networkError,
        reason: SdkErrorReason.network,
        errorMessage: 'Bearer eyJhbGciOiJ',
      );
      expect(e.toString().contains('Bearer'), isFalse);
      expect(e.toString(), contains('[redacted]'));
    });

    test('toString preserves non-token errorMessage', () {
      const e = SdkError(
        code: SdkErrorCode.networkError,
        reason: SdkErrorReason.network,
        errorMessage: 'connection_timeout',
      );
      expect(e.toString(), contains('connection_timeout'));
    });

    test('toJson includes wire-level enum strings', () {
      const e = SdkError(
        code: SdkErrorCode.oauthCallbackError,
        reason: SdkErrorReason.oauthStateMismatch,
        providerError: 'access_denied',
      );
      final json = e.toJson();
      expect(json['code'], equals('OAUTH_CALLBACK_ERROR'));
      expect(json['reason'], equals('oauth_state_mismatch'));
      expect(json['providerError'], equals('access_denied'));
    });

    test('SdkErrorCodeWire — every code has a stable string', () {
      for (final c in SdkErrorCode.values) {
        expect(c.wire, isNotEmpty);
        expect(
          c.wire,
          equals(c.wire.toUpperCase()),
          reason: 'codes are SCREAMING_SNAKE_CASE',
        );
      }
    });

    test('SdkErrorReasonWire — every reason has a stable string', () {
      for (final r in SdkErrorReason.values) {
        expect(r.wire, isNotEmpty);
      }
    });
  });
}
