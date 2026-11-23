import 'dart:convert';

import 'package:http/http.dart' as http;

/// Thrown when discovery is refused or fails.
class RakomiDiscoveryException implements Exception {
  RakomiDiscoveryException(this.message);

  /// What was refused.
  final String message;

  @override
  String toString() => 'RakomiDiscoveryException: $message';
}

/// The provider metadata of an issuer and the key set its `jwks_uri` serves.
class RakomiDiscovery {
  RakomiDiscovery({
    required this.issuer,
    required this.metadata,
    required this.jwks,
  });

  /// The issuer, exactly as the metadata names it.
  final String issuer;

  /// The OpenID provider metadata.
  final Map<String, Object?> metadata;

  /// The JSON Web Key Set (`{"keys": [...]}`).
  final Map<String, Object?> jwks;
}

/// Fetches the OpenID provider metadata of [issuer] and the JSON Web Key Set
/// its `jwks_uri` names.
///
/// HTTPS only, no redirects. The metadata `issuer` must equal [issuer]
/// exactly (OpenID Connect Discovery 1.0 §4.3). Pass [client] to reuse or
/// replace the HTTP client; it is not closed. Each request is bounded by
/// [timeout].
Future<RakomiDiscovery> discover(
  Uri issuer, {
  http.Client? client,
  Duration timeout = const Duration(seconds: 10),
}) async {
  _requireHttps(issuer, 'issuer');
  final issuerText = issuer.toString();
  final base = issuerText.endsWith('/')
      ? issuerText.substring(0, issuerText.length - 1)
      : issuerText;
  final c = client ?? http.Client();
  try {
    final metadata = await _getJsonObject(
      c,
      Uri.parse('$base/.well-known/openid-configuration'),
      timeout,
    );
    if (metadata['issuer'] != issuerText) {
      throw RakomiDiscoveryException('the metadata names another issuer');
    }
    final jwksUri = metadata['jwks_uri'];
    if (jwksUri is! String)
      throw RakomiDiscoveryException('the metadata has no jwks_uri');
    final jwksLocation = Uri.tryParse(jwksUri);
    if (jwksLocation == null)
      throw RakomiDiscoveryException('jwks_uri is not a URI');
    _requireHttps(jwksLocation, 'jwks_uri');
    final jwks = await _getJsonObject(c, jwksLocation, timeout);
    if (jwks['keys'] is! List)
      throw RakomiDiscoveryException('the key set has no keys list');
    return RakomiDiscovery(issuer: issuerText, metadata: metadata, jwks: jwks);
  } finally {
    if (client == null) c.close();
  }
}

void _requireHttps(Uri u, String what) {
  if (u.scheme != 'https' ||
      u.host.isEmpty ||
      u.hasQuery ||
      u.hasFragment ||
      u.userInfo.isNotEmpty) {
    throw RakomiDiscoveryException(
      '$what must be an https URL without credentials, query or fragment',
    );
  }
}

Future<Map<String, Object?>> _getJsonObject(
  http.Client c,
  Uri url,
  Duration timeout,
) async {
  final req = http.Request('GET', url)
    ..followRedirects = false
    ..headers['Accept'] = 'application/json';
  final http.Response res;
  try {
    res = await http.Response.fromStream(
      await c.send(req).timeout(timeout),
    ).timeout(timeout);
  } catch (_) {
    throw RakomiDiscoveryException('the request to ${url.host} failed');
  }
  if (res.statusCode != 200) {
    throw RakomiDiscoveryException(
      '${url.host} answered HTTP ${res.statusCode}',
    );
  }
  final Object? body;
  try {
    body = jsonDecode(utf8.decode(res.bodyBytes));
  } on FormatException {
    throw RakomiDiscoveryException('${url.host} did not answer JSON');
  }
  if (body is! Map<String, Object?>)
    throw RakomiDiscoveryException('${url.host} did not answer a JSON object');
  return body;
}
