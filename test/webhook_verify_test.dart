// Flutter publisher-webhook verifier.
//
// Primary test: the SHARED cross-SDK conformance vector loop (the same fixture @rakomi/node, Swift and
// React-Native load) — an executable Self-Consistency check across the four ports. Plus a negative matrix.

import 'dart:convert' show base64, base64Url, jsonDecode, utf8;
import 'dart:io' show File;

import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/internal/webhook_verify.dart';

const _fixturePath = 'test/fixtures/publisher-webhook-verify.json';

String? _errorClass(WebhookVerifyResult r) =>
    r is WebhookVerifyFailure ? r.error.wire : null;

void main() {
  group('publisher-webhook conformance vectors (shared fixture)', () {
    final raw = File(_fixturePath).readAsStringSync();
    final fixture = jsonDecode(raw) as Map<String, Object?>;
    final vectors = (fixture['vectors']! as List).cast<Map<String, Object?>>();

    test('fixture is non-empty', () {
      expect(vectors.length, greaterThan(15));
    });

    for (final v in vectors) {
      final name = v['name'] as String;
      test('vector: $name', () {
        final headers = (v['headers']! as Map).map(
          (key, value) => MapEntry(key as String, value as String),
        );
        final body = utf8.encode(v['body'] as String);
        final now = DateTime.fromMillisecondsSinceEpoch(
          (v['now_override'] as int) * 1000,
          isUtc: true,
        );
        final expect_ = v['expect']! as Map<String, Object?>;

        final result = verifyPublisherWebhook(
          body: body,
          headers: headers,
          secret: v['secret'] as String,
          tolerance: v['tolerance'] as int,
          now: now,
        );

        expect(
          result is WebhookVerifyOk,
          expect_['ok'],
          reason: 'vector $name ok mismatch',
        );
        final expectedClass = expect_['error_class'] as String?;
        if (result is WebhookVerifyFailure && expectedClass != null) {
          expect(
            _errorClass(result),
            expectedClass,
            reason: 'vector $name error_class',
          );
        }
        if (result is WebhookVerifyOk) {
          expect(result.webhookId.isNotEmpty, true);
          expect(result.payload, jsonDecode(v['body'] as String));
        }
      });
    }
  });

  group('verifyPublisherWebhook focused invariants', () {
    final key = List<int>.filled(32, 7);
    // base64url of 32×0x07 (no padding) → the rksec_ secret.
    final secret = 'rksec_${base64UrlNoPad(key)}';
    const body =
        '{"publisher_id":"p","correlation_id":"c","actor_axis":"tenant_admin"}';
    const ts = 1700000000;

    String sign(String b, int t, String id) {
      final mac = Hmac(sha256, key).convert(utf8.encode('$id.$t.$b')).bytes;
      return 'v1,${base64Std(mac)}';
    }

    test('valid delivery verifies and surfaces the dedup key + eventType', () {
      final headers = {
        'webhook-id': 'wid_1',
        'webhook-timestamp': '$ts',
        'webhook-signature': sign(body, ts, 'wid_1'),
        'x-rakomi-delivery-id': 'did_1',
        'x-rakomi-event': 'app.uninstalled',
      };
      final r = verifyPublisherWebhook(
        body: utf8.encode(body),
        headers: headers,
        secret: secret,
        now: DateTime.fromMillisecondsSinceEpoch(ts * 1000, isUtc: true),
      );
      expect(r, isA<WebhookVerifyOk>());
      r as WebhookVerifyOk;
      expect(r.webhookId, 'wid_1');
      expect(r.deliveryId, 'did_1');
      expect(r.eventType, 'app.uninstalled');
    });

    test('rejects a non-rksec_ secret', () {
      final headers = {
        'webhook-id': 'wid_1',
        'webhook-timestamp': '$ts',
        'webhook-signature': 'v1,AAAA',
      };
      final r = verifyPublisherWebhook(
        body: utf8.encode(body),
        headers: headers,
        secret: 'raw-not-prefixed',
        now: DateTime.fromMillisecondsSinceEpoch(ts * 1000, isUtc: true),
      );
      expect(r, isA<WebhookVerifyFailure>());
      expect(
        (r as WebhookVerifyFailure).error,
        WebhookVerifyErrorClass.invalidSecret,
      );
    });

    test('wrong-length decoded signature does not crash', () {
      final shortSig = 'v1,${base64Std(List<int>.filled(16, 1))}';
      final headers = {
        'webhook-id': 'wid_1',
        'webhook-timestamp': '$ts',
        'webhook-signature': shortSig,
      };
      final r = verifyPublisherWebhook(
        body: utf8.encode(body),
        headers: headers,
        secret: secret,
        now: DateTime.fromMillisecondsSinceEpoch(ts * 1000, isUtc: true),
      );
      expect(
        (r as WebhookVerifyFailure).error,
        WebhookVerifyErrorClass.invalidSignature,
      );
    });
  });
}

/// base64url of [bytes] without `=` padding (the rksec_ secret alphabet).
String base64UrlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// standard base64 of [bytes] (the SIGNATURE alphabet, +//, padded).
String base64Std(List<int> bytes) => base64.encode(bytes);
