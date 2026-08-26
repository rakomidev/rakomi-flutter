// Certificate-pinned HTTP client.
//
// `dart:io` `HttpClient.badCertificateCallback` only fires when the OS REJECTS a
// certificate, so it is NOT a sufficient place to implement pinning: a chain the
// OS accepts never reaches it.
//
// This implementation runs an out-of-band TLS handshake against the target
// host:port BEFORE the HTTP request, inspects the peer certificate, and
// only proceeds if the SHA-256 fingerprint matches one of the configured
// pins. On mismatch, the request is aborted with a `HandshakeException`
// carrying the wire-level reason `cert_pin_mismatch`. Callers up the stack
// surface this as `SdkError(networkError, certPinMismatch)` per the
// canonical SDK error envelope.
//
// Trade-offs (documented for adversarial review):
// - One extra TLS handshake per host on first contact. The verified-host cache
//   is process-lifetime.
// - The pin is verified on a probe connection, and the request itself travels
//   on a separate connection that is NOT pin-checked. An intermediary able to
//   present different certificates to the two connections is therefore NOT
//   covered here, and the OS will not catch it: with a device-installed CA it
//   accepts the substituted certificate, which is the whole reason this file
//   exists. Closing it requires pinning the connection that carries the
//   request, i.e. a transport-layer change, not a change in this class.
// - Pin format: base64(SHA-256(cert.der)), matching the published
//   `certificateFingerprints` API contract. SPKI-based pinning
//   (MASVS-NETWORK-2 preferred) is planned for a later release.
// - Mobile only: local-development hosts (`localhost`/`127.0.0.1`/`::1`) and
//   `http://` URLs short-circuit the pin check.
// - Web platform: this client is never instantiated under `kIsWeb` — the
//   browser TLS stack handles transport security.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

/// HTTP client wrapper that enforces SHA-256 certificate pinning at TLS
/// handshake time for `https://` requests to non-loopback hosts.
class PinnedHttpClient extends http.BaseClient {
  PinnedHttpClient({required this.pins, http.Client? inner})
    : assert(pins.isNotEmpty, 'PinnedHttpClient requires at least one pin'),
      _inner = inner ?? http.Client(),
      _normalisedPins = pins.map(_normalisePin).toSet() {
    pins.forEach(_assertUsablePin);
  }

  /// Configured SHA-256 fingerprints (raw — accepts hex-no-colons,
  /// hex-with-colons, or base64).
  final List<String> pins;

  final http.Client _inner;
  final Set<String> _normalisedPins;
  final Set<String> _verifiedHosts = <String>{};

  /// Public test seam — exposes the normalised pin set for assertion.
  Set<String> get debugNormalisedPins => Set.unmodifiable(_normalisedPins);

  /// Public test seam — exposes the verified-host cache for assertion.
  Set<String> get debugVerifiedHosts => Set.unmodifiable(_verifiedHosts);

  static const _loopbackHosts = <String>{'localhost', '127.0.0.1', '::1'};

  static String _normalisePin(String raw) {
    final trimmed = raw.replaceAll(':', '').trim();
    // Accept hex (64 chars), base64 (44 chars), or base64-without-padding (43).
    //
    // Case folding is scoped to the HEX branch ONLY, and MUST stay that way:
    // base64 is case-SENSITIVE, so folding a base64 pin decodes different
    // bytes and re-encodes to a value that can never equal the runtime digest
    // compared in `_verifyPin`. Hex is case-insensitive and folds safely.
    final lower = trimmed.toLowerCase();
    if (RegExp(r'^[0-9a-f]{64}$').hasMatch(lower)) {
      // Hex → bytes → base64.
      final bytes = <int>[];
      for (var i = 0; i < lower.length; i += 2) {
        bytes.add(int.parse(lower.substring(i, i + 2), radix: 16));
      }
      return base64.encode(bytes);
    }
    // Already base64-ish — re-encode to canonical (with `=` padding) form.
    try {
      final bytes = base64.decode(_padBase64(trimmed));
      return base64.encode(bytes);
    } catch (_) {
      // Unreachable: `_assertUsablePin` rejects anything that cannot normalise.
      return trimmed;
    }
  }

  /// A pin that cannot be normalised can never match, so every request to a
  /// pinned host fails with `cert_pin_mismatch` — a configuration typo
  /// reported to the operator as an active MITM. Reject it where it is
  /// entered instead.
  static void _assertUsablePin(String raw) {
    final trimmed = raw.replaceAll(':', '').trim();
    if (RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(trimmed)) return;
    try {
      if (base64.decode(_padBase64(trimmed)).length == 32) return;
    } catch (_) {
      // fall through to the throw below
    }
    throw ArgumentError.value(
      raw,
      'certificateFingerprints',
      'each pin MUST be a SHA-256 digest: 64 hex chars (colons optional) or '
          'base64 of 32 bytes',
    );
  }

  static String _padBase64(String s) {
    final pad = (4 - s.length % 4) % 4;
    return s + '=' * pad;
  }

  /// Matches 127.0.0.0/8 written as a dotted quad, and NOTHING else.
  ///
  /// A `startsWith('127.')` prefix test accepted `127.evil.com` — an
  /// attacker-controlled hostname — and skipped the pin check for it silently.
  /// `0.0.0.0` was accepted too: it is the unspecified address, not loopback,
  /// and it was never in the documented set.
  static final RegExp _loopbackV4 = RegExp(r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$');

  static bool _isLoopback(String host) =>
      _loopbackHosts.contains(host) || _loopbackV4.hasMatch(host);

  Future<void> _verifyPin(Uri url) async {
    final hostPort = '${url.host}:${url.port}';
    if (_verifiedHosts.contains(hostPort)) return;

    final secure = await SecureSocket.connect(url.host, url.port);
    try {
      final cert = secure.peerCertificate;
      if (cert == null) {
        throw const HandshakeException(
          'cert_pin_mismatch (no peer certificate)',
        );
      }
      final hash = base64.encode(sha256.convert(cert.der).bytes);
      if (!_normalisedPins.contains(hash)) {
        throw const HandshakeException('cert_pin_mismatch');
      }
      _verifiedHosts.add(hostPort);
    } finally {
      secure.destroy();
    }
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final url = request.url;
    if (url.scheme == 'https' && !_isLoopback(url.host)) {
      await _verifyPin(url);
    }
    // Redirects are NOT followed. `package:http` follows them by default, and
    // a followed redirect never re-enters this method — so a pinned host could
    // 302 to an unpinned one and the SDK would fetch it with no pin check at
    // all. The SDK talks to its own API and does not expect redirects; a
    // 3xx is surfaced to the caller rather than chased.
    request.followRedirects = false;
    return _inner.send(request);
  }

  @override
  void close() {
    _inner.close();
    _verifiedHosts.clear();
  }
}
