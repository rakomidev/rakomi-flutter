# rakomi

OpenID Connect discovery for a [Rakomi](https://rakomi.com) issuer, in pure
Dart (no Flutter dependency): server-side Dart, CLIs and tests.

For Flutter apps use [`rakomi_flutter`](https://pub.dev/packages/rakomi_flutter),
the full SDK (sign-in, token storage, MFA, JWKS verification).

```dart
import 'package:rakomi/rakomi.dart';

Future<void> main() async {
  final d = await discover(Uri.parse('https://auth.example.com'));
  print(d.metadata['token_endpoint']);
  print(d.jwks['keys']);
}
```

`discover` fetches `<issuer>/.well-known/openid-configuration` and then the
`jwks_uri` it names. It refuses, with a `RakomiDiscoveryException`:

- an issuer or `jwks_uri` that is not `https` (or carries a query or fragment);
- a redirect, a non-200 answer or a body that is not a JSON object;
- metadata whose `issuer` is not exactly the requested issuer (OpenID Connect
  Discovery 1.0 §4.3);
- a key set without a `keys` list.

It does not cache and does not verify tokens.

## License

MIT, see [LICENSE](LICENSE).
