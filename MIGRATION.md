# Migrating `rakomi_flutter`

Every minor release on the `0.x` line that changes the public API has a section here.

## 0.2 → next release

### `completeSignIn` takes a required `oauthClientId`

The API refreshes a session issued to an OAuth client only at `/oauth/token`, with that client named,
so the SDK has to know where tokens you hand it came from:

```dart
// 0.2
await auth.completeSignIn(body);

// next: tokens from your own authorization-code exchange at /oauth/token
await auth.completeSignIn(body, oauthClientId: clientId);
// next: tokens from a /v1/auth/* endpoint (password, magic link, OTP, MFA)
await auth.completeSignIn(body, oauthClientId: null);
```

A browser sign-in session stored by 0.2 has no client recorded and is refused at its next refresh; the
user signs in again once.

## 0.1 → 0.2

### `signUp()` takes a required `consent` argument

`/v1/auth/register` requires the person's consent, and the SDK cannot give it on their behalf. Pass
what your sign-up screen collected:

```dart
// 0.1
await auth.signUp(email: email, password: password);

// 0.2
await auth.signUp(email: email, password: password, consent: termsAccepted);
```

`signUp()` no longer reports an authenticated session: registration returns no tokens until the
address is verified, so it settles on `AuthStateUnauthenticated` (unless the response does carry
tokens, in which case sign-in completes as before).

### Signing keys come from the issuer's own `jwks_uri`

Unless you set `jwksUrl`, the SDK reads the issuer's discovery document and verifies tokens only
against the keys it names. If you set `jwksUrl` to a key set published by a different issuer, tokens
from your issuer will no longer verify — remove the override or point it at your issuer's key set.

### Browser and social sign-in need `clientId`

`RakomiProvider` / `RakomiAuth` take an optional `clientId` (your public OAuth client). Without it the
provider buttons are not rendered and `signInWithProvider` returns
`SdkError(code: SdkErrorCode.invalidConfig)` without opening a browser.

### Refresh failures

Only a definitive rejection (`invalid_grant`, `invalid_client`, `invalid_token`,
`unauthorized_client`, `access_denied`, or a bare `401`) signs the user out. If your app treated every
`AuthStateError` after a refresh as "signed out", check `error.code`: a `networkError` with
`httpStatus` and `retryAfter` means the session is still there and the SDK will retry.
