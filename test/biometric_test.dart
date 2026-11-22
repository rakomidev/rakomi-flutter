import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

import 'helpers/fake_adapter.dart';

void main() {
  group('Biometric gate', () {
    test('BiometricSuccess sealed variant', () {
      const r = BiometricSuccess();
      expect(r, isA<BiometricResult>());
    });

    test('BiometricCancelled returned via fake adapter', () async {
      final a = FakeRakomiNativeAdapter(
        biometricResult: const BiometricCancelled(),
      );
      final r = await a.requestBiometric(reason: 'unlock');
      expect(r, isA<BiometricCancelled>());
    });

    test(
      'BiometricLockout permanent flag distinguishes lockout types',
      () async {
        final transient = FakeRakomiNativeAdapter(
          biometricResult: const BiometricLockout(),
        );
        final permanent = FakeRakomiNativeAdapter(
          biometricResult: const BiometricLockout(permanent: true),
        );
        expect(
          (await transient.requestBiometric(reason: 'r')) is BiometricLockout,
          isTrue,
        );
        expect(
          ((await permanent.requestBiometric(reason: 'r')) as BiometricLockout)
              .permanent,
          isTrue,
        );
      },
    );

    test('BiometricNotEnrolled — typed for SdkErrorReason mapping', () async {
      final a = FakeRakomiNativeAdapter(
        biometricResult: const BiometricNotEnrolled(),
      );
      final r = await a.requestBiometric(reason: 'r');
      expect(r, isA<BiometricNotEnrolled>());
    });

    test('BiometricUnavailable carries diagnostic reason', () async {
      final a = FakeRakomiNativeAdapter(
        biometricResult: const BiometricUnavailable(
          reason: 'no_device_passcode',
        ),
      );
      final r = await a.requestBiometric(reason: 'r');
      expect(r, isA<BiometricUnavailable>());
      expect((r as BiometricUnavailable).reason, 'no_device_passcode');
    });
  });
}
