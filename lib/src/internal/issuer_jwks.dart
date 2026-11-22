import 'dart:async' show Future;
import 'dart:convert' show jsonDecode;

import 'package:http/http.dart' as http;

import 'jwt_verify.dart' show stripTrailingSlash;

/// Issuer → `jwks_uri` resolution.
///
/// Each issuer publishes its own signing keys at the `jwks_uri` its discovery
/// document names, so keys are resolved from the issuer the client expects —
/// never from a fixed JWKS path. A key of a different issuer is then never in
/// the set a token is checked against.

/// Thrown when a discovery document exists but belongs to another issuer.
/// Never retried with the next discovery form.
class IssuerMismatchException implements Exception {
  const IssuerMismatchException(this.message);

  final String message;

  @override
  String toString() => 'IssuerMismatchException: $message';
}

/// The discovery document URLs to try for [issuer], in order: OAuth 2.0
/// Authorization Server Metadata (RFC 8414 §3.1, well-known segment inserted
/// before the issuer path), then OpenID Connect Discovery 1.0 §4 (well-known
/// segment appended to the issuer). [discoveryOrigin] fetches the same paths
/// from another origin; the document's `issuer` must still equal [issuer].
List<Uri> issuerDiscoveryUrls(String issuer, {Uri? discoveryOrigin}) {
  final parsed = Uri.parse(stripTrailingSlash(issuer));
  final origin = (discoveryOrigin ?? parsed).origin;
  final path = parsed.path == '/' ? '' : stripTrailingSlash(parsed.path);
  return <Uri>[
    Uri.parse('$origin/.well-known/oauth-authorization-server$path'),
    Uri.parse('$origin$path/.well-known/openid-configuration'),
  ];
}

bool _isHttpsOrLocalhost(Uri uri) {
  if (uri.scheme == 'https') return true;
  return uri.scheme == 'http' &&
      (uri.host == 'localhost' || uri.host == '127.0.0.1');
}

/// Read `jwks_uri` from a discovery document fetched for [issuer]. The
/// document's `issuer` must equal [issuer] exactly (one trailing slash is the
/// only leniency); `jwks_uri` must be https (plain http only on localhost).
Uri extractJwksUri(Object? document, String issuer) {
  final doc = document is Map ? document : const <String, Object?>{};
  final docIssuer = doc['issuer'];
  if (docIssuer is! String ||
      stripTrailingSlash(docIssuer) != stripTrailingSlash(issuer)) {
    throw IssuerMismatchException(
      'discovery document issuer $docIssuer does not equal the expected issuer $issuer',
    );
  }
  final jwksUri = doc['jwks_uri'];
  if (jwksUri is! String || jwksUri.isEmpty) {
    throw FormatException('discovery document for $issuer has no jwks_uri');
  }
  final parsed = Uri.parse(jwksUri);
  if (!_isHttpsOrLocalhost(parsed)) {
    throw FormatException('jwks_uri for $issuer must use https');
  }
  return parsed;
}

/// Resolve the `jwks_uri` of [issuer] by trying each discovery form in turn.
/// A missing document (HTTP 404) moves on to the next form; a document naming
/// another issuer stops immediately.
Future<Uri> resolveIssuerJwksUri(
  String issuer,
  http.Client client, {
  Uri? discoveryOrigin,
}) async {
  Object? lastError;
  for (final url in issuerDiscoveryUrls(
    issuer,
    discoveryOrigin: discoveryOrigin,
  )) {
    final http.Response response;
    try {
      response = await client.get(
        url,
        headers: const {'Accept': 'application/json'},
      );
    } catch (e) {
      lastError = e;
      continue;
    }
    if (response.statusCode == 404) continue;
    if (response.statusCode != 200) {
      lastError = http.ClientException(
        'discovery fetch failed: ${response.statusCode}',
        url,
      );
      continue;
    }
    return extractJwksUri(jsonDecode(response.body), issuer);
  }
  if (lastError != null) throw lastError;
  throw FormatException('no discovery document found for issuer $issuer');
}

/// Where to fetch [issuer]'s discovery document from. A platform-family issuer
/// is served by whichever deployment the client is configured for ([baseUrl]),
/// because every platform deployment mints the same platform-family issuer;
/// any other issuer (a custom domain) is its own origin (`null`).
Uri? discoveryOriginFor(String issuer, String? baseUrl) {
  if (baseUrl == null) return null;
  final Uri issuerUri;
  final Uri base;
  try {
    issuerUri = Uri.parse(issuer);
    base = Uri.parse(baseUrl);
  } catch (_) {
    return null;
  }
  if (!issuerUri.hasAuthority || !base.hasScheme || !base.hasAuthority) {
    return null;
  }
  final host = issuerUri.host.toLowerCase();
  final platform =
      host == 'localhost' ||
      host == '127.0.0.1' ||
      host == '::1' ||
      host == 'rakomi.com' ||
      host.endsWith('.rakomi.com');
  return platform ? base : null;
}
