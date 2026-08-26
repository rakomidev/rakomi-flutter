import '../internal/storage_keys.dart';
import '../native/adapter.dart';
import 'pkce.dart';

/// Persisted single-use OAuth `state` + paired PKCE verifier.
///
/// Pattern: client generates `(oneTimeId, state, verifier)`, persists `state`
/// + `verifier` keyed by `oneTimeId` BEFORE opening the system browser, and
/// includes `state` in the authorize URL (the AS echoes it back on callback).
/// On callback, the client validates the echo against the persisted value
/// (constant-time), then deletes the entry regardless of outcome.
///
/// **Single-use enforcement** is server-AND-client (defense-in-depth — RFC
/// 9700 §4.4). The server enforces single-use as well; this is the
/// client-side half.
class PersistedOAuthState {
  PersistedOAuthState({required this.tenantId, required this.adapter});

  final String tenantId;
  final RakomiNativeAdapter adapter;

  /// Generate a fresh `(oneTimeId, state, verifier, challenge)` tuple AND
  /// persist `(state, verifier)` to secure storage. Returns the bundle for
  /// the caller to embed in the authorize URL.
  Future<OAuthStartBundle> begin() async {
    final oneTimeId = randomOneTimeId();
    final state = randomState();
    final verifier = generateVerifier();
    final challenge = s256Challenge(verifier);

    await adapter.storageWrite(oauthStateKey(tenantId, oneTimeId), state);
    await adapter.storageWrite(pkceVerifierKey(tenantId, oneTimeId), verifier);
    return OAuthStartBundle(
      oneTimeId: oneTimeId,
      state: state,
      verifier: verifier,
      challenge: challenge,
    );
  }

  /// Validate a callback `state` against the persisted value for [oneTimeId].
  /// Returns `(true, verifier)` on success, `(false, null)` on mismatch or
  /// missing entry. ALWAYS deletes the persisted entry post-validation
  /// (single-use semantics).
  Future<({bool ok, String? verifier})> validateAndConsume({
    required String oneTimeId,
    required String callbackState,
  }) async {
    final stateKey = oauthStateKey(tenantId, oneTimeId);
    final verifierKey = pkceVerifierKey(tenantId, oneTimeId);

    final persisted = await adapter.storageRead(stateKey);
    final verifier = await adapter.storageRead(verifierKey);

    // Always delete — single-use, regardless of outcome.
    await adapter.storageDelete(stateKey);
    await adapter.storageDelete(verifierKey);

    if (persisted == null || verifier == null) {
      return (ok: false, verifier: null);
    }
    final ok = constantTimeStringEquals(persisted, callbackState);
    return (ok: ok, verifier: ok ? verifier : null);
  }

  /// Cleanup all persisted oauth_state/pkce_verifier entries for this tenant.
  /// Called on cold start. Coarse delete-all semantics — OAuth flows pending
  /// across cold-start are abandoned (the system browser handoff is expected
  /// to complete within a single warm session). State + verifier are stored
  /// side-by-side; both are removed.
  Future<int> sweep() async {
    final prefix = '$kStorageNamespace.oauth_state.$tenantId.';
    final entries = await adapter.storageReadByPrefix(prefix);
    var swept = 0;
    for (final key in entries.keys) {
      final oneTimeId = key.substring(prefix.length);
      await adapter.storageDelete(oauthStateKey(tenantId, oneTimeId));
      await adapter.storageDelete(pkceVerifierKey(tenantId, oneTimeId));
      swept++;
    }
    return swept;
  }
}

class OAuthStartBundle {
  const OAuthStartBundle({
    required this.oneTimeId,
    required this.state,
    required this.verifier,
    required this.challenge,
  });

  final String oneTimeId;
  final String state;
  final String verifier;
  final String challenge;
}
