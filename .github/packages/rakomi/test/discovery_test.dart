import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:rakomi/rakomi.dart';
import 'package:test/test.dart';

const issuer = 'https://auth.example.com';

MockClient serve(
  Map<String, http.Response Function()> routes, {
  List<Uri>? seen,
}) => MockClient((req) async {
  seen?.add(req.url);
  final route = routes[req.url.toString()];
  return route == null ? http.Response('not found', 404) : route();
});

http.Response json(Object body, [int status = 200]) => http.Response(
  jsonEncode(body),
  status,
  headers: {'content-type': 'application/json'},
);

Map<String, http.Response Function()> healthy({
  String iss = issuer,
  String jwksUri = '$issuer/.well-known/jwks.json',
}) => {
  '$issuer/.well-known/openid-configuration': () => json({
    'issuer': iss,
    'jwks_uri': jwksUri,
    'token_endpoint': '$issuer/oauth/token',
  }),
  jwksUri: () => json({
    'keys': [
      {'kty': 'EC', 'kid': 'k1'},
    ],
  }),
};

void main() {
  test('returns the metadata and the key set of the issuer', () async {
    final seen = <Uri>[];
    final d = await discover(
      Uri.parse(issuer),
      client: serve(healthy(), seen: seen),
    );
    expect(d.issuer, issuer);
    expect(d.metadata['token_endpoint'], '$issuer/oauth/token');
    expect((d.jwks['keys']! as List).length, 1);
    expect(seen.map((u) => u.toString()), [
      '$issuer/.well-known/openid-configuration',
      '$issuer/.well-known/jwks.json',
    ]);
  });

  test('refuses metadata that names another issuer', () async {
    await expectLater(
      discover(
        Uri.parse(issuer),
        client: serve(healthy(iss: 'https://evil.example')),
      ),
      throwsA(isA<RakomiDiscoveryException>()),
    );
  });

  test(
    'a trailing slash is part of the issuer: metadata without it is refused',
    () async {
      final routes = healthy();
      await expectLater(
        discover(Uri.parse('$issuer/'), client: serve(routes)),
        throwsA(isA<RakomiDiscoveryException>()),
      );
    },
  );

  test('refuses an http issuer before any request', () async {
    final seen = <Uri>[];
    await expectLater(
      () => discover(
        Uri.parse('http://auth.example.com'),
        client: serve(healthy(), seen: seen),
      ),
      throwsA(isA<RakomiDiscoveryException>()),
    );
    expect(seen, isEmpty);
  });

  test('refuses an issuer with a query or fragment', () async {
    for (final bad in ['$issuer?x=1', '$issuer#f']) {
      await expectLater(
        () => discover(Uri.parse(bad), client: serve(healthy())),
        throwsA(isA<RakomiDiscoveryException>()),
      );
    }
  });

  test('refuses an http jwks_uri', () async {
    await expectLater(
      discover(
        Uri.parse(issuer),
        client: serve(healthy(jwksUri: 'http://auth.example.com/jwks.json')),
      ),
      throwsA(isA<RakomiDiscoveryException>()),
    );
  });

  test('refuses a redirect', () async {
    final routes = {
      '$issuer/.well-known/openid-configuration': () => http.Response(
        '',
        302,
        headers: {'location': 'https://evil.example/'},
      ),
    };
    await expectLater(
      discover(Uri.parse(issuer), client: serve(routes)),
      throwsA(isA<RakomiDiscoveryException>()),
    );
  });

  test('refuses a non-JSON body and a key set without keys', () async {
    final notJson = {
      '$issuer/.well-known/openid-configuration': () =>
          http.Response('<html>', 200),
    };
    await expectLater(
      discover(Uri.parse(issuer), client: serve(notJson)),
      throwsA(isA<RakomiDiscoveryException>()),
    );
    final noKeys = healthy();
    noKeys['$issuer/.well-known/jwks.json'] = () => json({'nokeys': true});
    await expectLater(
      discover(Uri.parse(issuer), client: serve(noKeys)),
      throwsA(isA<RakomiDiscoveryException>()),
    );
  });

  test('a transport failure is a RakomiDiscoveryException', () async {
    final failing = MockClient((_) async => throw http.ClientException('boom'));
    await expectLater(
      discover(Uri.parse(issuer), client: failing),
      throwsA(isA<RakomiDiscoveryException>()),
    );
  });
}
