import 'dart:async' show Future;
import 'dart:convert' show jsonDecode;

import 'package:http/http.dart' as http;
import 'issuer_jwks.dart' show resolveIssuerJwksUri;
import 'jwt_verify.dart' show VerificationKey, verificationKeyFromJwk;
import 'storage_keys.dart';

/// JWKS cache.
///
/// - **TTL**: 24h hard ceiling. ETag honoured on revalidation.
/// - **Payload size cap**: 16 KB. Anomalous responses are rejected.
/// - **kid-miss retry**: caller MAY [invalidate] + [getKeys] to force a fresh
///   fetch when a JWT references an unknown `kid`. ONE retry only — second
///   miss surfaces as `SdkError(reason: invalid_credentials,
///   errorMessage: 'jwks_kid_miss')`.
/// - **Public seam**: [invalidate] is a public method to support future
///   SSE/CAEP push-based invalidation later without an API break.

const int _maxPayloadBytes = 16 * 1024;
const Duration _ttl = Duration(hours: 24);

/// Adapter facade — JwksCache uses a small subset of [RakomiNativeAdapter]
/// (storage + http). Inject the storage primitives directly to keep this
/// module testable without the full adapter contract.
abstract class JwksStorage {
  Future<String?> readKey(String key);
  Future<void> writeKey(String key, String value);
  Future<void> deleteKey(String key);
}

class JwksCache {
  /// Reads keys either from an explicit [jwksUrl] (a proxy or mirror), or —
  /// when [jwksUrl] is `null` — from the `jwks_uri` named in [issuer]'s
  /// discovery document, fetched from [discoveryOrigin] when given. Exactly one
  /// of [jwksUrl] and [issuer] must be provided.
  JwksCache({
    required this.tenantId,
    this.jwksUrl,
    this.issuer,
    this.discoveryOrigin,
    required this.storage,
    required this.httpClient,
  }) : assert(
         (jwksUrl == null) != (issuer == null),
         'provide exactly one of jwksUrl or issuer',
       );

  final String tenantId;
  final Uri? jwksUrl;
  final String? issuer;
  final Uri? discoveryOrigin;
  final JwksStorage storage;
  final http.Client httpClient;

  /// The persisted storage slot is scoped to the key source (in addition to
  /// the tenant) — see [jwksCacheKey]'s doc comment: the explicit [jwksUrl]'s
  /// host, or the discovery origin's host plus the expected [issuer], so keys
  /// persisted for another issuer are never reused. `null` only for an empty
  /// host; the bare tenant-only slot is then used as a defensive fallback.
  String? get _host {
    final explicit = jwksUrl;
    if (explicit != null) return explicit.host.isEmpty ? null : explicit.host;
    final iss = issuer!;
    final originHost = (discoveryOrigin ?? Uri.parse(iss)).host;
    if (originHost.isEmpty) return null;
    return '$originHost.i.${Uri.encodeComponent(iss)}';
  }

  /// The JWKS document URL: the explicit override, or the expected issuer's
  /// discovered `jwks_uri`.
  Future<Uri> _currentJwksUrl() async {
    final explicit = jwksUrl;
    if (explicit != null) return explicit;
    return resolveIssuerJwksUri(
      issuer!,
      httpClient,
      discoveryOrigin: discoveryOrigin,
    );
  }

  /// In-memory parsed cache of `kid → VerificationKey`. Repopulated on
  /// `getKeys()` (cold start or post-invalidate).
  Map<String, VerificationKey>? _cached;

  /// Single in-flight fetch dedup. Concurrent kid-miss retries on the same
  /// instance share one network round-trip.
  Future<Map<String, VerificationKey>>? _inflight;

  Future<Map<String, VerificationKey>> getKeys({
    bool forceRefresh = false,
  }) async {
    if (!forceRefresh && _cached != null) return _cached!;
    if (_inflight != null) return _inflight!;
    _inflight = _resolve(forceRefresh: forceRefresh);
    try {
      _cached = await _inflight!;
      return _cached!;
    } finally {
      _inflight = null;
    }
  }

  Future<Map<String, VerificationKey>> _resolve({
    required bool forceRefresh,
  }) async {
    if (!forceRefresh) {
      final hit = await _readCached();
      if (hit != null) return hit;
    }
    return _fetchAndStore();
  }

  Future<Map<String, VerificationKey>?> _readCached() async {
    final cached = await storage.readKey(jwksCacheKey(tenantId, host: _host));
    final fetchedAtRaw = await storage.readKey(
      jwksFetchedAtKey(tenantId, host: _host),
    );
    if (cached == null || fetchedAtRaw == null) return null;
    final fetchedAt = DateTime.fromMillisecondsSinceEpoch(
      int.parse(fetchedAtRaw),
      isUtc: true,
    );
    if (DateTime.now().toUtc().difference(fetchedAt) > _ttl) {
      // Stale — force refresh.
      return null;
    }
    try {
      return _parseJwks(cached);
    } catch (_) {
      return null;
    }
  }

  Future<Map<String, VerificationKey>> _fetchAndStore() async {
    final etag = await storage.readKey(jwksEtagKey(tenantId, host: _host));
    final headers = <String, String>{
      'Accept': 'application/json',
      'If-None-Match': ?etag,
    };
    final url = await _currentJwksUrl();
    final response = await httpClient.get(url, headers: headers);

    if (response.statusCode == 304) {
      // Cached body still valid — refresh fetched-at timestamp.
      await storage.writeKey(
        jwksFetchedAtKey(tenantId, host: _host),
        DateTime.now().toUtc().millisecondsSinceEpoch.toString(),
      );
      final cached = await storage.readKey(jwksCacheKey(tenantId, host: _host));
      if (cached == null) {
        throw const FormatException('JWKS 304 with empty cache');
      }
      return _parseJwks(cached);
    }

    if (response.statusCode != 200) {
      throw http.ClientException(
        'JWKS fetch failed: ${response.statusCode}',
        url,
      );
    }

    final body = response.body;
    if (body.length > _maxPayloadBytes) {
      throw const FormatException('jwks_oversize');
    }
    final keys = _parseJwks(body);

    await storage.writeKey(jwksCacheKey(tenantId, host: _host), body);
    await storage.writeKey(
      jwksFetchedAtKey(tenantId, host: _host),
      DateTime.now().toUtc().millisecondsSinceEpoch.toString(),
    );
    final newEtag = response.headers['etag'];
    if (newEtag != null) {
      await storage.writeKey(jwksEtagKey(tenantId, host: _host), newEtag);
    }

    return keys;
  }

  Map<String, VerificationKey> _parseJwks(String body) {
    final doc = jsonDecode(body);
    if (doc is! Map<String, Object?>) {
      throw const FormatException('JWKS root not an object');
    }
    final keys = doc['keys'];
    if (keys is! List) {
      throw const FormatException('JWKS missing keys[]');
    }
    final out = <String, VerificationKey>{};
    for (final raw in keys) {
      if (raw is! Map<String, Object?>) continue;
      // Only keys allowed to verify a signature (allowed alg on the key,
      // matching key type, use absent or sig); malformed entries are skipped.
      final key = verificationKeyFromJwk(raw);
      if (key == null) continue;
      out[raw['kid']! as String] = key;
    }
    if (out.isEmpty) {
      throw const FormatException('JWKS contains no usable signing keys');
    }
    return out;
  }

  /// Public seam: clear cache + force next-call refetch. Used by:
  /// - kid-miss retry
  /// - future SSE/CAEP push invalidation
  Future<void> invalidate() async {
    _cached = null;
    await storage.deleteKey(jwksCacheKey(tenantId, host: _host));
    await storage.deleteKey(jwksEtagKey(tenantId, host: _host));
    await storage.deleteKey(jwksFetchedAtKey(tenantId, host: _host));
  }
}
