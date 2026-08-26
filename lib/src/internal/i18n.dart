/// Lightweight i18n helper. Loads JSON dictionaries from
/// `assets/i18n/<locale>.json`.
///
/// Translation keys mirror `@rakomi/react`'s `useTranslation` keys 1:1
/// (parity asserted in CI).
///
/// This is NOT a full i18n framework — only enough for SDK strings.
/// Consumers SHOULD use `intl` or `easy_localization` for app-level strings.
library;

import 'dart:convert';
import 'package:flutter/services.dart' show rootBundle;

class RakomiI18n {
  RakomiI18n._(this._dict);

  final Map<String, String> _dict;

  static Future<RakomiI18n> load(String locale) async {
    try {
      final json = await rootBundle.loadString(
        'packages/rakomi_flutter/assets/i18n/$locale.json',
      );
      final dict = (jsonDecode(json) as Map<String, Object?>).map(
        (k, v) => MapEntry(k, v as String),
      );
      return RakomiI18n._(dict);
    } catch (_) {
      // Fallback to English if the locale is unsupported.
      if (locale != 'en') return load('en');
      return RakomiI18n._(_fallbackEn());
    }
  }

  /// Synchronous in-memory factory used by tests + the fallback path. Tests
  /// pass `RakomiI18n.fromMap({...})` to avoid asset bundle setup.
  factory RakomiI18n.fromMap(Map<String, String> dict) => RakomiI18n._(dict);

  String t(String key, {Map<String, Object?>? params}) {
    var s = _dict[key] ?? key;
    if (params != null) {
      params.forEach((k, v) {
        s = s.replaceAll('{$k}', '$v');
      });
    }
    return s;
  }

  static Map<String, String> _fallbackEn() => const <String, String>{
    'sign_in.title': 'Sign in',
    'sign_in.email_label': 'Email',
    'sign_in.password_label': 'Password',
    'sign_in.submit': 'Sign in',
    'sign_in.continue_with': 'Continue with {provider}',
    'sign_in.magic_link_sent': 'We sent you a magic link.',
    'sign_in.otp_sent': 'We sent you a one-time code.',
    'sign_in.otp_label': 'Code',
    'mfa.totp.title': 'Verify',
    'mfa.totp.label': 'Authentication code',
    'mfa.totp.hint': 'Enter the 6-digit code from your authenticator app.',
    'mfa.unavailable.title': 'Multi-factor not available',
    'mfa.unavailable.message': 'Sign in via your registered passwordless flow.',
    'user_avatar.signed_in_as': 'Signed in as {email}',
    'user_avatar.session_expires': 'Session expires {time}',
    'user_avatar.sign_out': 'Sign out',
    'biometric.prompt': 'Unlock',
    'errors.network': 'Network error. Please try again.',
    'errors.invalid_credentials': 'Invalid email or password.',
    'errors.rate_limited': 'Too many attempts. Try again later.',
    'errors.unknown': 'Something went wrong.',
  };
}
