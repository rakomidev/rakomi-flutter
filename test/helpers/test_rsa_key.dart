import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djw;
import 'package:pointycastle/export.dart' as pc;

/// The RSA test key of the token-verification tests: a 2048-bit pair derived
/// from a fixed seed the first time a test asks for it, so no private key is
/// committed and every run signs with the same key. The JWKS publishes its
/// public half under kid `k1`.
final pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> _pair = () {
  final random = pc.FortunaRandom()
    ..seed(
      pc.KeyParameter(Uint8List.fromList(List<int>.generate(32, (i) => i + 1))),
    );
  final generator = pc.RSAKeyGenerator()
    ..init(
      pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
        random,
      ),
    );
  return generator.generateKeyPair();
}();

/// The private half, for signing test tokens.
djw.RSAPrivateKey testRsaPrivateKey() =>
    djw.RSAPrivateKey.raw(_pair.privateKey);

/// The public half as an RS256 signing JWK with kid `k1`.
Map<String, Object?> testRsaJwk() => <String, Object?>{
  'kty': 'RSA',
  'kid': 'k1',
  'use': 'sig',
  'alg': 'RS256',
  'n': _base64UrlUint(_pair.publicKey.modulus!),
  'e': _base64UrlUint(_pair.publicKey.publicExponent!),
};

/// A JWKS document holding [testRsaJwk], as the API serves it.
String testJwksBody() => jsonEncode(<String, Object?>{
  'keys': <Object?>[testRsaJwk()],
});

String _base64UrlUint(BigInt value) {
  final bytes = <int>[];
  var v = value;
  while (v > BigInt.zero) {
    bytes.insert(0, (v & BigInt.from(0xff)).toInt());
    v = v >> 8;
  }
  return base64Url.encode(bytes).replaceAll('=', '');
}
