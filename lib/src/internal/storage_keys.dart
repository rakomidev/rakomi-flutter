/// Storage key namespacing.
///
/// All durable keys MUST follow the pattern:
///
///   `rakomi.v1.<purpose>.<tenantId>[.<extra>]`
///
/// The `v1` literal is reserved for future migration: when the schema changes
/// in a way that cannot be handled by `flutter_secure_storage`'s
/// `migrateOnAlgorithmChange` (e.g. value-format change, not just cipher
/// change), bump to `rakomi.v2.*` and write a one-shot migrator that reads
/// `rakomi.v1.*`, writes `rakomi.v2.*`, and deletes the v1 entries.
///
/// **Tenant scoping**: the `<tenantId>` segment isolates multi-tenant test
/// harnesses where multiple `RakomiProvider`s coexist.
/// `<tenantId>` is derived from the publishable key.
///
/// **iOS Keychain post-uninstall residue**: iOS Keychain entries SURVIVE
/// app uninstall. The fresh-install detection sweep
/// uses a paired Keychain + `shared_preferences` lifecycle marker — if the
/// Keychain has the marker but `shared_preferences` does NOT, this is a
/// post-uninstall reinstall and ALL `rakomi.v1.*` Keychain keys are PURGED
/// before any auth state read.
library;

const String kStorageNamespace = 'rakomi.v1';

/// Refresh token key. `rakomi.v1.refresh_token.<tenantId>`.
String refreshTokenKey(String tenantId) =>
    '$kStorageNamespace.refresh_token.$tenantId';

/// The OAuth client a stored session was issued to, when it was issued to one
/// (browser sign-in, authorization code). `rakomi.v1.oauth_client_id.<tenantId>`.
/// Such a session refreshes at `/oauth/token` with that `client_id`; a session
/// without it (password, magic link, OTP, MFA) refreshes at `/v1/auth/refresh`.
/// Written and cleared together with the refresh token.
String oauthClientIdKey(String tenantId) =>
    '$kStorageNamespace.oauth_client_id.$tenantId';

/// JWKS cache key. `rakomi.v1.jwks.<tenantId>[.h.<host>]`. Holds the
/// JSON-encoded JWKS document; ETag tracked separately.
///
/// **Per-host scoping**: [host], when given, is appended as an additional
/// segment (`.h.<host>`) on top of the tenant scope. A tenant's issuer host
/// can change across the app's lifetime (a custom domain bound after this
/// SDK version first shipped, or simply a dev pointed at a different host
/// between builds) — a slot keyed by tenant alone would silently reuse a
/// PREVIOUS host's persisted document as this instance's "fresh" cache on
/// cold start, which offline verification must never do. The host segment is
/// not secret (it is the caller's own `jwksUrl` configuration), so a plain
/// suffix is enough — this only needs to be a stable, DIFFERENT key per
/// host, not a cryptographically-opaque one. Mirrors
/// `@rakomi/react-native`'s `resolveJwksKey`
/// (`packages/react-native/src/internal/token-runtime.ts`).
String jwksCacheKey(String tenantId, {String? host}) => host == null
    ? '$kStorageNamespace.jwks.$tenantId'
    : '$kStorageNamespace.jwks.$tenantId.h.$host';

/// JWKS ETag key. `rakomi.v1.jwks_etag.<tenantId>[.h.<host>]`.
String jwksEtagKey(String tenantId, {String? host}) => host == null
    ? '$kStorageNamespace.jwks_etag.$tenantId'
    : '$kStorageNamespace.jwks_etag.$tenantId.h.$host';

/// JWKS cache timestamp key (UTC millisecondsSinceEpoch).
/// `rakomi.v1.jwks_fetched_at.<tenantId>[.h.<host>]`.
String jwksFetchedAtKey(String tenantId, {String? host}) => host == null
    ? '$kStorageNamespace.jwks_fetched_at.$tenantId'
    : '$kStorageNamespace.jwks_fetched_at.$tenantId.h.$host';

/// OAuth state key. `rakomi.v1.oauth_state.<tenantId>.<oneTimeId>`.
/// Single-use: deleted post-validation regardless of outcome.
String oauthStateKey(String tenantId, String oneTimeId) =>
    '$kStorageNamespace.oauth_state.$tenantId.$oneTimeId';

/// PKCE verifier key (paired with [oauthStateKey] one-time-id).
String pkceVerifierKey(String tenantId, String oneTimeId) =>
    '$kStorageNamespace.pkce_verifier.$tenantId.$oneTimeId';

/// Last-system-browser-auth timestamp (UTC millisecondsSinceEpoch). Used to
/// gate the fresh-auth window: a biometric-gated read within `freshAuthWindow`
/// of the last system-browser auth is served without a new prompt.
String lastSystemBrowserAuthKey(String tenantId) =>
    '$kStorageNamespace.last_browser_auth.$tenantId';

/// Clock-skew offset (signed milliseconds — server time minus device time,
/// capped ±5 min).  Captured on first successful refresh.
String clockSkewKey(String tenantId) =>
    '$kStorageNamespace.clock_skew_ms.$tenantId';

/// Lifecycle ID key (value = `randomOneTimeId()` — 16 CSPRNG bytes rendered
/// as 32 lowercase hex chars — present in BOTH Keychain AND
/// shared_preferences). A missing OR non-matching marker ⇒ post-uninstall
/// reinstall ⇒ purge. `shared_preferences` is NOT secure storage, which is why
/// the two halves are compared by value rather than merely for presence.
String lifecycleIdKey(String tenantId) =>
    '$kStorageNamespace.lifecycle_id.$tenantId';

/// Lifecycle marker key written to `shared_preferences` (NOT Keychain).
/// Pair-checked against [lifecycleIdKey] on cold start.
String lifecycleMarkerKey(String tenantId) =>
    '$kStorageNamespace.lifecycle_id_marker.$tenantId';

/// User snapshot cache (decoded `User` JSON). `rakomi.v1.user.<tenantId>`.
String userKey(String tenantId) => '$kStorageNamespace.user.$tenantId';

/// Session snapshot cache (decoded `Session` JSON).
String sessionKey(String tenantId) => '$kStorageNamespace.session.$tenantId';
