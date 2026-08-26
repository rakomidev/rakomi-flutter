import 'dart:async' show Zone;
import 'dart:convert' show jsonDecode, jsonEncode, utf8;

import 'package:http/http.dart' as http;

/// Thin wrapper around `package:http` with:
///
/// - W3C Trace Context propagation (opt-in via `Zone.current[#traceparent]`,
///   no default behavior change).
/// - Automatic `User-Agent: rakomi_flutter/<version>`.
/// - JSON helpers + token redaction in error logs.
class RakomiHttpClient {
  RakomiHttpClient(this.inner, {required this.userAgent});

  final http.Client inner;
  final String userAgent;

  Map<String, String> _baseHeaders(Map<String, String>? extra) {
    final h = <String, String>{
      'User-Agent': userAgent,
      'Accept': 'application/json',
    };
    final traceparent = Zone.current[#traceparent];
    if (traceparent is String && traceparent.isNotEmpty) {
      h['traceparent'] = traceparent;
    }
    if (extra != null) h.addAll(extra);
    return h;
  }

  Future<http.Response> getJson(Uri url, {Map<String, String>? headers}) =>
      inner.get(url, headers: _baseHeaders(headers));

  Future<http.Response> postJson(
    Uri url,
    Map<String, Object?> body, {
    Map<String, String>? headers,
  }) {
    return inner.post(
      url,
      headers: {..._baseHeaders(headers), 'Content-Type': 'application/json'},
      body: jsonEncodeBody(body),
    );
  }

  Future<http.Response> postForm(
    Uri url,
    Map<String, String> body, {
    Map<String, String>? headers,
  }) {
    return inner.post(
      url,
      headers: {
        ..._baseHeaders(headers),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body,
    );
  }

  static String jsonEncodeBody(Map<String, Object?> body) => jsonEncode(body);
}

/// Decode a JSON HTTP response body. Throws [FormatException] on invalid JSON.
Map<String, Object?> decodeJsonBody(http.Response r) {
  return jsonDecode(utf8.decode(r.bodyBytes)) as Map<String, Object?>;
}
