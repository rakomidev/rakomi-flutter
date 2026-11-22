import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/src/internal/jwks_cache.dart';
import 'package:rakomi_flutter/src/internal/storage_keys.dart';
import 'helpers/test_rsa_key.dart';

class _MapStorage implements JwksStorage {
  final Map<String, String> _kv = <String, String>{};

  @override
  Future<String?> readKey(String key) async => _kv[key];

  @override
  Future<void> writeKey(String key, String value) async {
    _kv[key] = value;
  }

  @override
  Future<void> deleteKey(String key) async {
    _kv.remove(key);
  }
}

void main() {
  late String jwksBody;

  setUpAll(() {
    jwksBody = testJwksBody();
  });

  group('JwksCache', () {
    test('first call fetches via HTTP and stores body + ETag', () async {
      var fetches = 0;
      final client = http_test.MockClient((http.Request r) async {
        fetches++;
        return http.Response(
          jwksBody,
          200,
          headers: <String, String>{
            'content-type': 'application/json',
            'etag': '"abc"',
          },
        );
      });
      final storage = _MapStorage();
      final cache = JwksCache(
        tenantId: 'acme',
        jwksUrl: Uri.parse('https://api.example/.well-known/jwks.json'),
        storage: storage,
        httpClient: client,
      );
      final keys = await cache.getKeys();
      expect(keys.containsKey('k1'), isTrue);
      expect(fetches, equals(1));
    });

    test('second call (in-memory cache) does NOT fetch', () async {
      var fetches = 0;
      final client = http_test.MockClient((http.Request r) async {
        fetches++;
        return http.Response(jwksBody, 200);
      });
      final cache = JwksCache(
        tenantId: 'acme',
        jwksUrl: Uri.parse('https://api.example/.well-known/jwks.json'),
        storage: _MapStorage(),
        httpClient: client,
      );
      await cache.getKeys();
      await cache.getKeys();
      await cache.getKeys();
      expect(fetches, equals(1));
    });

    test('invalidate() forces refetch', () async {
      var fetches = 0;
      final client = http_test.MockClient((http.Request r) async {
        fetches++;
        return http.Response(jwksBody, 200);
      });
      final cache = JwksCache(
        tenantId: 'acme',
        jwksUrl: Uri.parse('https://api.example/.well-known/jwks.json'),
        storage: _MapStorage(),
        httpClient: client,
      );
      await cache.getKeys();
      await cache.invalidate();
      await cache.getKeys();
      expect(fetches, equals(2));
    });

    test('jwks_oversize — payload >16KB rejected', () async {
      final huge = jsonEncode(<String, Object?>{
        'keys': List<Map<String, Object?>>.generate(
          1000,
          (_) => <String, Object?>{
            'kty': 'RSA',
            'kid': 'k',
            'n': 'A' * 4000,
            'e': 'AQAB',
          },
        ),
      });
      final client = http_test.MockClient(
        (_) async => http.Response(huge, 200),
      );
      final cache = JwksCache(
        tenantId: 'acme',
        jwksUrl: Uri.parse('https://api.example/.well-known/jwks.json'),
        storage: _MapStorage(),
        httpClient: client,
      );
      expect(cache.getKeys(), throwsA(isA<FormatException>()));
    });

    test(
      '304 Not Modified — uses storage-cached body via fresh JwksCache instance',
      () async {
        var calls = 0;
        final client = http_test.MockClient((http.Request r) async {
          calls++;
          if (calls == 1) {
            return http.Response(
              jwksBody,
              200,
              headers: <String, String>{'etag': '"v1"'},
            );
          }
          return http.Response('', 304);
        });
        final storage = _MapStorage();
        final url = Uri.parse('https://api.example/.well-known/jwks.json');

        // First instance — primes storage.
        final cache1 = JwksCache(
          tenantId: 'acme',
          jwksUrl: url,
          storage: storage,
          httpClient: client,
        );
        await cache1.getKeys();

        // Drop the storage's "fetched_at" so the next instance treats body as
        // stale and reissues a conditional GET → server replies 304 →
        // returns cached body. The persisted slot is scoped per-host (see
        // `jwksFetchedAtKey`'s doc comment) — the SAME derivation the cache
        // itself uses, so `url.host` ('api.example') here must match.
        await storage.deleteKey(jwksFetchedAtKey('acme', host: url.host));

        final cache2 = JwksCache(
          tenantId: 'acme',
          jwksUrl: url,
          storage: storage,
          httpClient: client,
        );
        final keys = await cache2.getKeys();
        expect(keys.containsKey('k1'), isTrue);
        expect(calls, equals(2));
      },
    );

    test('non-RSA-sig keys filtered out', () async {
      final mixed = jsonEncode(<String, Object?>{
        'keys': <Map<String, Object?>>[
          jsonDecode(jwksBody)['keys'][0] as Map<String, Object?>,
          <String, Object?>{'kty': 'EC', 'kid': 'ec1', 'crv': 'P-256'},
          <String, Object?>{
            'kty': 'RSA',
            'kid': 'enc1',
            'use': 'enc',
            'n': 'AAAA',
            'e': 'AQAB',
          },
        ],
      });
      final client = http_test.MockClient(
        (_) async => http.Response(mixed, 200),
      );
      final cache = JwksCache(
        tenantId: 'acme',
        jwksUrl: Uri.parse('https://api.example/.well-known/jwks.json'),
        storage: _MapStorage(),
        httpClient: client,
      );
      final keys = await cache.getKeys();
      expect(keys.keys, equals(<String>{'k1'}));
    });

    test('empty/no-RSA JWKS surfaces as FormatException', () async {
      final client = http_test.MockClient(
        (_) async => http.Response('{"keys":[]}', 200),
      );
      final cache = JwksCache(
        tenantId: 'acme',
        jwksUrl: Uri.parse('https://api.example/.well-known/jwks.json'),
        storage: _MapStorage(),
        httpClient: client,
      );
      expect(cache.getKeys(), throwsA(isA<FormatException>()));
    });

    test(
      'per-host cache: two JwksCache instances for the SAME tenantId but '
      'DIFFERENT jwksUrl hosts never read back each other\'s persisted document',
      () async {
        final storage = _MapStorage();
        var fetchesA = 0;
        final clientA = http_test.MockClient((http.Request r) async {
          fetchesA++;
          return http.Response(jwksBody, 200);
        });
        final cacheA = JwksCache(
          tenantId: 'acme',
          jwksUrl: Uri.parse(
            'https://tenant-a.example.com/.well-known/jwks.json',
          ),
          storage: storage,
          httpClient: clientA,
        );
        await cacheA.getKeys();
        expect(fetchesA, equals(1));

        // A SECOND cache, same tenantId, different jwksUrl HOST — must NOT
        // find tenant-a's persisted document under its own slot and skip the
        // network fetch; it must fetch its own document independently.
        var fetchesB = 0;
        final clientB = http_test.MockClient((http.Request r) async {
          fetchesB++;
          return http.Response(jwksBody, 200);
        });
        final cacheB = JwksCache(
          tenantId: 'acme',
          jwksUrl: Uri.parse(
            'https://tenant-b.example.com/.well-known/jwks.json',
          ),
          storage: storage,
          httpClient: clientB,
        );
        await cacheB.getKeys();
        expect(fetchesB, equals(1));
      },
    );

    test(
      'per-host cache: does not treat a pre-migration bare tenant-only slot as fresh',
      () async {
        // Regression guard for the bare (no `.h.<host>`) storage slot a
        // pre-fix persisted cache would have left behind. Pre-seed it with a
        // document that carries a DIFFERENT `kid` than the live fixture, so
        // if per-host scoping ever regressed to reading this bare slot as
        // "fresh", the test below would observe the WRONG key set instead of
        // triggering the real network fetch.
        final storage = _MapStorage();
        await storage.writeKey(
          jwksCacheKey('acme'),
          jsonEncode(<String, Object?>{
            'keys': <Map<String, Object?>>[
              <String, Object?>{
                'kty': 'RSA',
                'kid': 'stale-bare-slot-kid',
                'n': 'AAAA',
                'e': 'AQAB',
              },
            ],
          }),
        );
        await storage.writeKey(
          jwksFetchedAtKey('acme'),
          DateTime.now().toUtc().millisecondsSinceEpoch.toString(),
        );

        var fetches = 0;
        final client = http_test.MockClient((http.Request r) async {
          fetches++;
          return http.Response(jwksBody, 200);
        });
        final cache = JwksCache(
          tenantId: 'acme',
          jwksUrl: Uri.parse(
            'https://tenant-a.example.com/.well-known/jwks.json',
          ),
          storage: storage,
          httpClient: client,
        );
        final keys = await cache.getKeys();
        // The fixture's kid ('k1'), never the stale bare-slot kid — and the
        // network fetch DID fire, proving the bare slot was never consulted.
        expect(keys.keys, equals(<String>{'k1'}));
        expect(fetches, equals(1));
      },
    );
  });
}
