import 'dart:async' show Future;
import 'dart:convert' show jsonDecode;

import 'package:http/http.dart' as http;
import 'package:pointycastle/asymmetric/api.dart' as pc;

import 'jwt_verify.dart' show rsaPublicKeyFromJwk;
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
  JwksCache({
    required this.tenantId,
    required this.jwksUrl,
    required this.storage,
    required this.httpClient,
  });

  final String tenantId;
  final Uri jwksUrl;
  final JwksStorage storage;
  final http.Client httpClient;

  /// In-memory parsed cache of `kid → RSAPublicKey`. Repopulated on
  /// `getKeys()` (cold start or post-invalidate).
  Map<String, pc.RSAPublicKey>? _cached;

  /// Single in-flight fetch dedup. Concurrent kid-miss retries on the same
  /// instance share one network round-trip.
  Future<Map<String, pc.RSAPublicKey>>? _inflight;

  Future<Map<String, pc.RSAPublicKey>> getKeys({
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

  Future<Map<String, pc.RSAPublicKey>> _resolve({
    required bool forceRefresh,
  }) async {
    if (!forceRefresh) {
      final hit = await _readCached();
      if (hit != null) return hit;
    }
    return _fetchAndStore();
  }

  Future<Map<String, pc.RSAPublicKey>?> _readCached() async {
    final cached = await storage.readKey(jwksCacheKey(tenantId));
    final fetchedAtRaw = await storage.readKey(jwksFetchedAtKey(tenantId));
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

  Future<Map<String, pc.RSAPublicKey>> _fetchAndStore() async {
    final etag = await storage.readKey(jwksEtagKey(tenantId));
    final headers = <String, String>{
      'Accept': 'application/json',
      'If-None-Match': ?etag,
    };
    final response = await httpClient.get(jwksUrl, headers: headers);

    if (response.statusCode == 304) {
      // Cached body still valid — refresh fetched-at timestamp.
      await storage.writeKey(
        jwksFetchedAtKey(tenantId),
        DateTime.now().toUtc().millisecondsSinceEpoch.toString(),
      );
      final cached = await storage.readKey(jwksCacheKey(tenantId));
      if (cached == null) {
        throw const FormatException('JWKS 304 with empty cache');
      }
      return _parseJwks(cached);
    }

    if (response.statusCode != 200) {
      throw http.ClientException(
        'JWKS fetch failed: ${response.statusCode}',
        jwksUrl,
      );
    }

    final body = response.body;
    if (body.length > _maxPayloadBytes) {
      throw const FormatException('jwks_oversize');
    }
    final keys = _parseJwks(body);

    await storage.writeKey(jwksCacheKey(tenantId), body);
    await storage.writeKey(
      jwksFetchedAtKey(tenantId),
      DateTime.now().toUtc().millisecondsSinceEpoch.toString(),
    );
    final newEtag = response.headers['etag'];
    if (newEtag != null) {
      await storage.writeKey(jwksEtagKey(tenantId), newEtag);
    }

    return keys;
  }

  Map<String, pc.RSAPublicKey> _parseJwks(String body) {
    final doc = jsonDecode(body);
    if (doc is! Map<String, Object?>) {
      throw const FormatException('JWKS root not an object');
    }
    final keys = doc['keys'];
    if (keys is! List) {
      throw const FormatException('JWKS missing keys[]');
    }
    final out = <String, pc.RSAPublicKey>{};
    for (final raw in keys) {
      if (raw is! Map<String, Object?>) continue;
      if (raw['kty'] != 'RSA') continue;
      final use = raw['use'];
      if (use != null && use != 'sig') continue;
      final kid = raw['kid'];
      if (kid is! String) continue;
      try {
        out[kid] = rsaPublicKeyFromJwk(raw);
      } catch (_) {
        // Skip malformed JWK entries, keep going (defense-in-depth).
        continue;
      }
    }
    if (out.isEmpty) {
      throw const FormatException('JWKS contains no usable RSA sig keys');
    }
    return out;
  }

  /// Public seam: clear cache + force next-call refetch. Used by:
  /// - kid-miss retry
  /// - future SSE/CAEP push invalidation
  Future<void> invalidate() async {
    _cached = null;
    await storage.deleteKey(jwksCacheKey(tenantId));
    await storage.deleteKey(jwksEtagKey(tenantId));
    await storage.deleteKey(jwksFetchedAtKey(tenantId));
  }
}
