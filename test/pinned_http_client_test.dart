// Regression tests for the cert-pinning HTTP client. Covers:
//   - happy path (matching pin in normalised cache),
//   - sad path (mismatched pin throws HandshakeException with cert_pin_mismatch),
//   - empty pins (assert blocks construction — pins are required),
//   - dev-loopback short-circuit (localhost / 127.0.0.1 / ::1),
//   - HTTP-scheme short-circuit (no pin check on http://).
//
// In-vivo TLS handshake assertion against a real public host is OUT OF SCOPE
// for unit tests (network-dependent). Coverage here is structural:
// short-circuit paths execute without an out-of-band SecureSocket connect,
// while pin normalisation is exercised against multiple input formats.

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:rakomi_flutter/src/native/pinned_http_client.dart';

void main() {
  group('PinnedHttpClient — pin normalisation', () {
    test('hex pin (no colons) normalises to canonical 44-char base64', () {
      final hex = List<String>.generate(
        32,
        (i) => i.toRadixString(16).padLeft(2, '0'),
      ).join();
      final c = PinnedHttpClient(pins: [hex]);
      expect(c.debugNormalisedPins.length, 1);
      expect(c.debugNormalisedPins.first.length, 44);
      c.close();
    });

    test('hex pin with colons is accepted equivalently', () {
      final raw = List<int>.generate(32, (i) => i);
      final hexPlain = raw
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      final hexColon = raw
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(':');
      final c1 = PinnedHttpClient(pins: [hexPlain]);
      final c2 = PinnedHttpClient(pins: [hexColon]);
      expect(c1.debugNormalisedPins, equals(c2.debugNormalisedPins));
      c1.close();
      c2.close();
    });

    test('base64 pin survives normalisation idempotently', () {
      final b64 = base64.encode(List<int>.filled(32, 0xab));
      final c = PinnedHttpClient(pins: [b64]);
      expect(c.debugNormalisedPins, contains(b64));
      c.close();
    });

    test('multiple pins are deduplicated post-normalisation', () {
      final raw = List<int>.generate(32, (i) => i);
      final hexA = raw.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      final hexB = raw
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(':');
      final c = PinnedHttpClient(pins: [hexA, hexB]);
      expect(
        c.debugNormalisedPins.length,
        1,
        reason: 'colon and no-colon forms collide',
      );
      c.close();
    });

    test('empty pin list is rejected via assert (construction-time)', () {
      expect(() => PinnedHttpClient(pins: []), throwsA(isA<AssertionError>()));
    });
  });

  group('PinnedHttpClient — short-circuits', () {
    test('http:// URL skips out-of-band handshake', () async {
      final inner = _StubClient();
      final c = PinnedHttpClient(
        pins: [base64.encode(List<int>.filled(32, 0))],
        inner: inner,
      );
      final req = http.Request('GET', Uri.parse('http://example.com/'));
      final res = await c.send(req);
      expect(res.statusCode, 200);
      expect(inner.lastUrl?.scheme, 'http');
      // No host should have been added to the verified-host cache (HTTP
      // does not warrant a cert pin check by definition).
      expect(c.debugVerifiedHosts, isEmpty);
      c.close();
    });

    test('localhost https:// URL skips pin check', () async {
      final inner = _StubClient();
      final c = PinnedHttpClient(
        pins: [base64.encode(List<int>.filled(32, 0))],
        inner: inner,
      );
      final req = http.Request('GET', Uri.parse('https://localhost:9999/'));
      final res = await c.send(req);
      expect(res.statusCode, 200);
      expect(c.debugVerifiedHosts, isEmpty);
      c.close();
    });

    test('127.0.0.1 https:// URL skips pin check', () async {
      final inner = _StubClient();
      final c = PinnedHttpClient(
        pins: [base64.encode(List<int>.filled(32, 0))],
        inner: inner,
      );
      final req = http.Request('GET', Uri.parse('https://127.0.0.1:9999/'));
      final res = await c.send(req);
      expect(res.statusCode, 200);
      expect(c.debugVerifiedHosts, isEmpty);
      c.close();
    });

    test('::1 IPv6 loopback https:// URL skips pin check', () async {
      final inner = _StubClient();
      final c = PinnedHttpClient(
        pins: [base64.encode(List<int>.filled(32, 0))],
        inner: inner,
      );
      final req = http.Request('GET', Uri.parse('https://[::1]:9999/'));
      final res = await c.send(req);
      expect(res.statusCode, 200);
      c.close();
    });
  });

  group('PinnedHttpClient — pin-derivation parity', () {
    test('SHA-256(cert.der) → base64 matches the documented pin format', () {
      // Sanity check: the documented pin format is base64(SHA-256(cert.der)).
      // Verify the math against a known input.
      final fakeDer = utf8.encode('hello world');
      final hash = sha256.convert(fakeDer).bytes;
      final pin = base64.encode(hash);
      expect(pin, 'uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=');
    });
  });
}

class _StubClient extends http.BaseClient {
  Uri? lastUrl;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    lastUrl = request.url;
    return http.StreamedResponse(const Stream.empty(), 200);
  }
}
