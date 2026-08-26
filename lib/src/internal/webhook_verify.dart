// Publisher-webhook receiver verification (Standard Webhooks).
//
// ─── Irreducible Receiver Contract (the 5-point first-principles invariant — port this verbatim) ───
//  1. Verify over the EXACT received bytes joined `{webhook-id}.{webhook-timestamp}.{body}` — never a
//     re-serialized body.
//  2. Constant-time signature compare on the fixed 32 raw HMAC bytes (XOR-accumulate; NEVER `listEquals`,
//     NEVER a base64-string `==`).
//  3. HMAC-SHA256 is HARDCODED — never read an algorithm from input. `v1,` = HMAC-SHA256; non-`v1,`
//     entries are SKIPPED, but ZERO `v1,` candidates FAIL CLOSED.
//  4. Timestamp bounded BOTH ways, checked BEFORE the HMAC. Integer seconds; non-integer → missing/invalid.
//  5. Secret `rksec_<base64url>` MUST decode to exactly 32 bytes. SECRET is base64url (-/_); SIGNATURE is
//     standard base64 (+//) — a port using one decoder for both silently mis-verifies.
//
// Mirrors `internal/jwt_verify.dart`. Returns a sealed `WebhookVerifyResult` (never throws). No
// attacker-controlled input may crash. Errors never embed the secret, decoded key, or computed HMAC.

import 'dart:convert' show base64, base64Url, jsonDecode, utf8;

import 'package:crypto/crypto.dart' show Hmac, sha256;

const String _rksecPrefix = 'rksec_';
const int _expectedKeyLength = 32;

/// Default publisher replay window (seconds) and the hard max clamp.
const int kDefaultWebhookTolerance = 300;
const int kMaxWebhookTolerance = 600;

/// Portable webhook-verify error class. [wire] IS the cross-SDK conformance `error_class`.
enum WebhookVerifyErrorClass {
  invalidSignature('invalid_signature'),
  invalidSecret('invalid_secret'),
  missingHeader('missing_header'),
  timestampTooOld('timestamp_too_old'),
  timestampTooNew('timestamp_too_new'),
  invalidBody('invalid_body');

  const WebhookVerifyErrorClass(this.wire);
  final String wire;
}

/// Sealed verify result — `WebhookVerifyOk` | `WebhookVerifyFailure`.
sealed class WebhookVerifyResult {
  const WebhookVerifyResult();
}

/// A verified publisher-webhook delivery. [webhookId] is the stable at-least-once dedup key;
/// [deliveryId] is per-delivery diagnostics; [eventType] is from the `X-Rakomi-Event` header (the body
/// carries no `type`); [payload] is the flat, verified metadata object.
class WebhookVerifyOk extends WebhookVerifyResult {
  const WebhookVerifyOk({
    required this.webhookId,
    required this.deliveryId,
    required this.eventType,
    required this.timestamp,
    required this.payload,
  });

  final String webhookId;
  final String deliveryId;
  final String eventType;
  final int timestamp;
  final Map<String, Object?> payload;
}

class WebhookVerifyFailure extends WebhookVerifyResult {
  const WebhookVerifyFailure(this.error);
  final WebhookVerifyErrorClass error;
}

String? _header(Map<String, String> headers, String name) {
  final lower = name.toLowerCase();
  for (final entry in headers.entries) {
    if (entry.key.toLowerCase() == lower) return entry.value.trim();
  }
  return null;
}

List<int>? _deriveKey(String secret) {
  final encoded = secret.startsWith(_rksecPrefix)
      ? secret.substring(_rksecPrefix.length)
      : secret;
  try {
    final pad = (4 - encoded.length % 4) % 4;
    final key = base64Url.decode(encoded + ('=' * pad));
    if (key.length != _expectedKeyLength) return null;
    return key;
  } catch (_) {
    return null;
  }
}

/// Constant-time equality over two byte lists — always touches all bytes, no early return, no
/// data-dependent branch. Length is NOT secret (both are fixed 32-byte HMAC outputs).
bool _constantTimeEquals(List<int> a, List<int> b) {
  var diff = a.length ^ b.length;
  final len = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Raw generic verify (tenant + advanced use). [now] is injectable for deterministic tests.
WebhookVerifyResult verifyWebhook({
  required List<int> body,
  required Map<String, String> headers,
  required String secret,
  int tolerance = kDefaultWebhookTolerance,
  DateTime? now,
}) {
  final signature = _header(headers, 'webhook-signature');
  final timestampStr = _header(headers, 'webhook-timestamp');
  final webhookId = _header(headers, 'webhook-id');
  if (signature == null ||
      signature.isEmpty ||
      timestampStr == null ||
      webhookId == null ||
      webhookId.isEmpty) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.missingHeader);
  }

  final timestamp = int.tryParse(timestampStr);
  if (timestamp == null) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.missingHeader);
  }

  final nowSecs =
      (now ?? DateTime.now()).toUtc().millisecondsSinceEpoch ~/ 1000;
  final diff = nowSecs - timestamp;
  if (diff > tolerance) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.timestampTooOld);
  }
  if (diff < -tolerance) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.timestampTooNew);
  }

  final key = _deriveKey(secret);
  if (key == null) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.invalidSecret);
  }

  final String bodyString;
  try {
    bodyString = utf8.decode(body);
  } catch (_) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.invalidBody);
  }

  // Sign over the RAW received body string + the RAW timestamp string.
  final signedContent = '$webhookId.$timestampStr.$bodyString';
  final expected = Hmac(sha256, key).convert(utf8.encode(signedContent)).bytes;

  var matched = false;
  for (final raw in signature.split(' ')) {
    final entry = raw.trim();
    if (!entry.startsWith('v1,')) continue; // skip v2,/etc. (forward-compat)
    final candidateB64 = entry.substring(3);
    List<int> candidate;
    try {
      candidate = base64.decode(
        candidateB64,
      ); // SIGNATURE = standard base64 (+//)
    } catch (_) {
      continue; // malformed base64 → non-match, never a crash
    }
    // length-guard the decoded candidate to 32 bytes before the constant-time compare.
    if (candidate.length != _expectedKeyLength) continue;
    if (_constantTimeEquals(expected, candidate)) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.invalidSignature);
  }

  final Object? parsed;
  try {
    parsed = jsonDecode(bodyString);
  } catch (_) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.invalidBody);
  }
  if (parsed is! Map<String, Object?>) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.invalidBody);
  }

  final deliveryId = _header(headers, 'x-rakomi-delivery-id') ?? webhookId;
  final eventType = _header(headers, 'x-rakomi-event') ?? '';
  return WebhookVerifyOk(
    webhookId: webhookId,
    deliveryId: deliveryId,
    eventType: eventType,
    timestamp: timestamp,
    payload: parsed,
  );
}

/// Recommended publisher entry point. Pre-binds the 300 s window (clamped ≤600) and REJECTS a
/// non-`rksec_` secret outright. Mirrors `@rakomi/node`'s `verifyPublisherWebhook`.
WebhookVerifyResult verifyPublisherWebhook({
  required List<int> body,
  required Map<String, String> headers,
  required String secret,
  int tolerance = kDefaultWebhookTolerance,
  DateTime? now,
}) {
  if (!secret.startsWith(_rksecPrefix)) {
    return const WebhookVerifyFailure(WebhookVerifyErrorClass.invalidSecret);
  }
  final clamped = tolerance < 0
      ? 0
      : (tolerance > kMaxWebhookTolerance ? kMaxWebhookTolerance : tolerance);
  return verifyWebhook(
    body: body,
    headers: headers,
    secret: secret,
    tolerance: clamped,
    now: now,
  );
}
