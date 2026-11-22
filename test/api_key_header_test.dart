import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:rakomi_flutter/src/internal/http_client.dart';

/// The tenant's publishable key has to arrive in the header the API reads.
///
/// It used not to be sent at all: `RakomiHttpClient` had no notion of it, and
/// `X-API-Key` appeared nowhere in the package, so every first-party auth call
/// was answered 401 `auth/missing_api_key` before its body was considered. The
/// same defect was found and fixed on the Swift side, where the key was sent
/// under a header name nothing on the server reads.
void main() {
  Future<Map<String, String>> capturedHeaders({String? publishableKey}) async {
    late Map<String, String> seen;
    final mock = MockClient((request) async {
      seen = request.headers;
      return http.Response(jsonEncode(<String, Object?>{}), 200);
    });
    final client = RakomiHttpClient(
      mock,
      userAgent: 'rakomi_flutter/test',
      publishableKey: publishableKey,
    );
    await client.postJson(
      Uri.parse('https://api.example.test/v1/auth/login'),
      <String, Object?>{},
    );
    return seen;
  }

  test('the publishable key travels as X-API-Key', () async {
    final headers = await capturedHeaders(
      publishableKey: 'pk_test_header_probe',
    );
    // Substrate first: an empty header map would satisfy the absence assertion
    // below for the wrong reason.
    expect(headers['content-type'], contains('application/json'));
    expect(headers['x-api-key'], equals('pk_test_header_probe'));
  });

  test('no key configured means no header, not an empty one', () async {
    final headers = await capturedHeaders();
    expect(headers.containsKey('x-api-key'), isFalse);
    expect(headers['accept'], equals('application/json'));
  });

  test('an empty key is not sent', () async {
    final headers = await capturedHeaders(publishableKey: '');
    expect(headers.containsKey('x-api-key'), isFalse);
  });

  /// The second-factor step posted `challenge_id` to `/v1/auth/mfa/totp/verify`.
  /// Measured against the running API: that path is 404, and that field name is
  /// rejected 400 `validation/invalid_request` by the endpoint that does exist.
  test('the MFA verification targets the path and field the API accepts', () {
    final source = File('lib/src/oauth/mfa.dart').readAsStringSync();
    expect(source, contains('/v1/auth/mfa/verify-login'));
    expect(source, contains("'mfa_challenge_token'"));
    expect(source.contains('/v1/auth/mfa/totp/verify'), isFalse);
    expect(source.contains("'challenge_id':"), isFalse);
  });

  /// The login response signals a second factor with `next_step`, not
  /// `next_action`, and names the challenge `mfa_challenge_token`.
  test('the login response is read with the keys the API sends', () {
    final source = File('lib/src/auth/auth_controller.dart').readAsStringSync();
    expect(source, contains("body['next_step'] == 'mfa_verify'"));
    expect(source, contains("body['mfa_challenge_token']"));
    expect(source.contains("body['next_action']"), isFalse);
  });
}
