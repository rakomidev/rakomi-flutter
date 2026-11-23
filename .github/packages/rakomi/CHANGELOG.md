## 0.1.0

- `discover(issuer)`: OpenID Connect discovery of a Rakomi issuer. Fetches
  `/.well-known/openid-configuration` and the `jwks_uri` it names, HTTPS only,
  no redirects, and refuses metadata whose `issuer` differs from the requested
  one.
