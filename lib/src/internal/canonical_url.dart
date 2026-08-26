// RFC 9449 §4.3 DPoP `htu` URL canonicalization.
//
// Every Rakomi SDK canonicalizes `htu` identically, and identically to the
// server, for all production-reachable cases; a shared golden-`htu` vector is
// the cross-runtime conformance oracle.
//
// The canonicalization lives in the Dart package itself so that a published
// consumer's proof `htu` matches the server with no extra runtime dependency.
//
// DRIFT CONSIDERATION: a divergence between the SDK's canonicalization and the
// server's makes valid proofs fail verification, so this implementation MUST NOT
// be changed in isolation. The cross-runtime conformance vector is the
// regression tripwire.
//
// Canonicalization rules (RFC chain — RFC 9449 §4.3 → RFC 9110 §3.2 / §7.1 →
// RFC 3986 §6.2.2 → RFC 3987 §3.1 / RFC 5891 IDNA2008 for IDN):
//   - lowercase scheme (RFC 3986 §6.2.2.1) — Dart `Uri` does this.
//   - lowercase host (RFC 3986 §6.2.2.1) — Dart `Uri` does this.
//   - strip default port (`:443` https, `:80` http) (RFC 3986 §6.2.3) — Dart
//     `Uri.authority` drops a default port (`hasPort == false`).
//   - strip fragment AND query (RFC 9449 §4.3 — defends `?next=evil.com`) — we
//     read scheme/authority/path only.
//   - strip trailing slash on non-root path (RFC 3986 §6.2.2.3).
//   - lowercase percent-encoded hex (`%2F` → `%2f`) (RFC 3986 §6.2.2.2).
//   - resolve `.`/`..` segments (RFC 3986 §6.2.2.3) — Dart `Uri` does this.
//   - collapse repeated slashes (`//`).
//   - IDN → Punycode (RFC 3987 §3.1 / RFC 5891) is NOT performed: the Dart core
//     `Uri` parser does not punycode-encode a Unicode host, and adding an
//     IDNA2008 runtime dependency would break the SDK's no-new-runtime-dep
//     budget. INTEGRATOR REQUIREMENT: configure an ASCII (already punycoded)
//     API host — the Rakomi platform host is ASCII.

/// Error thrown by [canonicalizeUrl] for an unparseable or unsupported input.
class CanonicalizeUrlError implements Exception {
  const CanonicalizeUrlError(this.code, this.message);

  /// `'invalid_url'` — the input could not be parsed as an absolute URL.
  /// `'unsupported_version'` — an unknown canonicalization version was requested.
  final String code;
  final String message;

  @override
  String toString() => 'CanonicalizeUrlError($code): $message';
}

/// The only supported canonicalization version (RFC 9449, 2023 vintage). Mirrors
/// the `CanonicalUrlVersion` literal of the Rakomi JavaScript SDKs.
const String kCanonicalUrlVersionRfc9449 = 'rfc9449-2023';

String _lowercasePercentHex(String s) {
  return s.replaceAllMapped(
    RegExp('%([0-9A-Fa-f]{2})'),
    (m) => '%${m.group(1)!.toLowerCase()}',
  );
}

String _collapsePath(String path) {
  final collapsed = path.replaceAll(RegExp('/{2,}'), '/');
  if (collapsed.length > 1 && collapsed.endsWith('/')) {
    return collapsed.substring(0, collapsed.length - 1);
  }
  return collapsed;
}

/// Canonicalize [input] into an RFC 9449 §4.3 DPoP `htu`
/// (scheme + authority + path; query/fragment + default port stripped).
///
/// Behaviourally identical to the `@rakomi/node` / React Native SDK's
/// `canonicalizeUrl` for
/// every production-reachable input (the ASCII golden vectors). IDN/NFC hosts
/// are not canonicalized here (see the file header).
///
/// Throws [CanonicalizeUrlError] on an unparseable input or an unsupported
/// [version].
String canonicalizeUrl(
  String input, {
  String version = kCanonicalUrlVersionRfc9449,
}) {
  if (version != kCanonicalUrlVersionRfc9449) {
    throw CanonicalizeUrlError(
      'unsupported_version',
      'unsupported canonicalize-url version: $version',
    );
  }

  final Uri url;
  try {
    url = Uri.parse(input);
  } on FormatException catch (e) {
    throw CanonicalizeUrlError('invalid_url', 'invalid url: ${e.message}');
  }
  if (!url.hasScheme || !url.hasAuthority) {
    throw const CanonicalizeUrlError(
      'invalid_url',
      'invalid url: not an absolute URL with scheme + authority',
    );
  }

  // Dart's `Uri` already: lowercases scheme + host, resolves dot segments, and
  // — via `authority` — drops a default port (`:443`/`:80` → `hasPort == false`)
  // while re-bracketing an IPv6 literal and preserving a non-default port.
  final scheme = url.scheme; // already lowercase
  final authority = url.authority; // host[:non-default-port], IPv6 bracketed

  // `url.path` keeps query/fragment out already (we never read them). Lowercase
  // its percent-hex and collapse repeated + trailing slashes.
  final normalizedPath = _collapsePath(_lowercasePercentHex(url.path));

  return '$scheme://$authority$normalizedPath';
}
