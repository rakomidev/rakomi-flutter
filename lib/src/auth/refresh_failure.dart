import 'package:http_parser/http_parser.dart' show parseHttpDate;

/// How a failed refresh affects the session.
enum RefreshFailureKind {
  /// Try again later: a 5xx, 429 or 408, or a transport failure (status `0`).
  /// The session and the stored refresh token are kept. (A 2xx the SDK cannot
  /// read is not transient: the server consumed the refresh token, so the
  /// session ends locally and the token is never presented again.)
  transient,

  /// The session is over: a 4xx naming `invalid_grant`, `invalid_client`,
  /// `invalid_token`, `unauthorized_client` or `access_denied`, or one of
  /// the API's own session-ending codes (`invalid_refresh_token`,
  /// `session_expired`, `token_reuse_detected`, `race_condition_detected`,
  /// and the 403s `user_blocked` and `pending_parental_consent`), or a bare
  /// 401.
  definitive,

  /// Any other 4xx — for example a 403 without a session-ending code, which a
  /// proxy in front of the API can produce. Not
  /// a reason to end the session, and not worth retrying at once either.
  rejected,
}

const Set<String> _definitiveOAuthErrors = <String>{
  'invalid_grant',
  'invalid_client',
  'invalid_token',
  'unauthorized_client',
  'access_denied',
  // The API's own codes (`auth/…`, namespace dropped) for a refresh it refused
  // because the session is gone. The 401s are definitive by status already;
  // `user_blocked` and `pending_parental_consent` arrive as a 403, and the
  // server has revoked the session before answering.
  'invalid_refresh_token',
  'session_expired',
  'token_reuse_detected',
  'race_condition_detected',
  'user_blocked',
  'pending_parental_consent',
};

/// Upper bound on how long a server-supplied `Retry-After` holds off the next
/// refresh, so a misconfigured server cannot park a session indefinitely.
const Duration maxRefreshRetryAfter = Duration(seconds: 120);

/// `true` for a refresh failure status after which the server may already
/// have rotated the refresh token: any 5xx except 503 and 521–523 (the request
/// never reached a server that could). Such a failure is retried once,
/// immediately; if that retry is neither a success nor a definitive rejection,
/// the outcome is unknown and the session ends locally — the refresh token is
/// never presented later, because after the server's 10-second window a
/// rotated token presented again revokes every session of the user.
bool isRefreshRetryOnceStatus(int status) =>
    status >= 500 &&
    status <= 599 &&
    status != 503 &&
    !(status >= 521 && status <= 523);

/// How long after sending the first refresh its 5xx answer may arrive for the
/// SDK still to retry. The server keeps a lost rotation for 10 seconds; the
/// margin covers the retry's own trip.
const Duration refreshRetryOnceDeadline = Duration(seconds: 8);

/// `true` for a status that says "try again later": any 5xx, 429, 408.
bool isTransientHttpStatus(int status) =>
    status >= 500 || status == 429 || status == 408;

/// Classify a refresh failure from its HTTP [status] (`0` for a transport
/// failure) and the error code in the body, if any, as read by
/// [refreshErrorCode].
RefreshFailureKind classifyRefreshFailure(int status, String? oauthError) {
  if (status == 0 || isTransientHttpStatus(status)) {
    return RefreshFailureKind.transient;
  }
  if (status >= 400 && status < 500) {
    if (oauthError != null && _definitiveOAuthErrors.contains(oauthError)) {
      return RefreshFailureKind.definitive;
    }
    if (status == 401) return RefreshFailureKind.definitive;
  }
  return RefreshFailureKind.rejected;
}

final RegExp _deltaSeconds = RegExp(r'^\d{1,9}$');

/// Parse a `Retry-After` header (RFC 9110 §10.2.3): delta-seconds or an
/// HTTP-date. An absent or unparseable value yields `null` — no delay is ever
/// invented. A date in the past yields [Duration.zero].
Duration? parseRetryAfter(String? header, DateTime now) {
  if (header == null) return null;
  final value = header.trim();
  if (value.isEmpty) return null;
  if (_deltaSeconds.hasMatch(value)) {
    return Duration(seconds: int.parse(value));
  }
  final DateTime at;
  try {
    at = parseHttpDate(value);
  } on FormatException {
    return null;
  }
  final delta = at.difference(now.toUtc());
  return delta.isNegative ? Duration.zero : delta;
}

/// The error code a refresh-endpoint error body names, normalized: the
/// RFC 6749 §5.2 `error` string, else the API's problem+json `code`, else a
/// nested `error.code`. A leading `auth/` namespace is dropped and the result
/// lower-cased; `null` when the body names none.
String? refreshErrorCode(Object? body) {
  if (body is! Map) return null;
  final error = body['error'];
  Object? raw = error is String ? error : body['code'];
  if (raw is! String && error is Map) raw = error['code'];
  if (raw is! String) return null;
  var code = raw.trim().toLowerCase();
  if (code.startsWith('auth/')) code = code.substring('auth/'.length);
  return code.isEmpty ? null : code;
}

/// How long a transient failure's `Retry-After` holds off the next refresh:
/// the server's value, capped at [maxRefreshRetryAfter].
Duration refreshHoldFor(Duration retryAfter) =>
    retryAfter > maxRefreshRetryAfter ? maxRefreshRetryAfter : retryAfter;
