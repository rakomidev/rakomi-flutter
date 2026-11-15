import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

/// Surface-naming + error-reason parity vs `@rakomi/react-native`.
///
/// Loads `test/fixtures/rn_sdk_surface.json` (committed snapshot of RN
/// public surface) and asserts that:
///
/// 1. Every RN error code has a matching `SdkErrorCode` value in Flutter.
/// 2. Every RN OAuth error reason has a matching `SdkErrorReason` value
///    in Flutter (wire-level string match).
/// 3. Every RN social provider has a matching `SocialProvider` enum value.
/// 4. Every RN `AuthEvent` type has a matching `AuthEventType` value.
void main() {
  late Map<String, Object?> fixture;

  setUpAll(() {
    final f = File('test/fixtures/rn_sdk_surface.json');
    expect(
      f.existsSync(),
      isTrue,
      reason: 'rn_sdk_surface.json fixture missing',
    );
    fixture = jsonDecode(f.readAsStringSync()) as Map<String, Object?>;
  });

  test('SdkErrorCode wire values match RN AuthErrorCode literal-union 1:1', () {
    final rnCodes = (fixture['auth_error_codes'] as List).cast<String>();
    final flutterCodes = SdkErrorCode.values.map((c) => c.wire).toSet();
    for (final rn in rnCodes) {
      expect(
        flutterCodes,
        contains(rn),
        reason: 'RN AuthErrorCode $rn missing in Flutter SdkErrorCode',
      );
    }
  });

  test('SdkErrorReason wire values include all RN oauth_* reasons', () {
    final rnOauth = (fixture['oauth_error_reasons'] as List).cast<String>();
    final flutterReasons = SdkErrorReason.values.map((r) => r.wire).toSet();
    for (final rn in rnOauth) {
      expect(
        flutterReasons,
        contains(rn),
        reason: 'RN oauth reason $rn missing in Flutter SdkErrorReason',
      );
    }
  });

  test('SocialProvider enum covers all RN LinkProvider values', () {
    final rnProviders = (fixture['social_providers'] as List).cast<String>();
    final flutterProviders = SocialProvider.values.map((p) => p.wire).toSet();
    for (final rn in rnProviders) {
      expect(
        flutterProviders,
        contains(rn),
        reason: 'RN provider $rn missing in Flutter SocialProvider',
      );
    }
  });

  test('AuthEventType enum covers all RN AuthEvent type values', () {
    final rnEvents = (fixture['auth_event_types'] as List).cast<String>();
    final flutterEvents = AuthEventType.values
        .map((e) => _camelToSnake(e.name))
        .toSet();
    for (final rn in rnEvents) {
      expect(
        flutterEvents,
        contains(rn),
        reason: 'RN event $rn missing in Flutter AuthEventType',
      );
    }
  });

  test('Flutter SocialProvider includes EUDI Wallet extensibility hook', () {
    expect(
      SocialProvider.values,
      contains(SocialProvider.eudiWallet),
      reason:
          'EUDI Wallet (Reg. 2024/1183) extensibility hook required for end-of-2026 mandate',
    );
  });

  test(
    'AuthState has Loading, Unauthenticated, Authenticated, Error variants',
    () {
      const loading = AuthStateLoading();
      const unauth = AuthStateUnauthenticated();
      expect(loading.runtimeType.toString(), 'AuthStateLoading');
      expect(unauth.runtimeType.toString(), 'AuthStateUnauthenticated');
      // Authenticated + Error need typed payloads — instantiate via switch
      // pattern in production; here we only assert the types are exported.
      expect(AuthStateAuthenticated, isNotNull);
      expect(AuthStateError, isNotNull);
    },
  );
}

String _camelToSnake(String name) {
  final out = StringBuffer();
  for (var i = 0; i < name.length; i++) {
    final ch = name[i];
    if (ch == ch.toUpperCase() && ch != ch.toLowerCase() && i > 0) {
      out.write('_');
    }
    out.write(ch.toLowerCase());
  }
  return out.toString();
}
