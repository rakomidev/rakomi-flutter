// rakomi_flutter — DPoP-aware refresh decision logic
//
// Wraps the bare `POST /v1/auth/refresh` call with the SDK-side decision
// logic: bound-vs-Bearer attach, the single bounded RFC 9449 §8 nonce
// retry, and the THREE distinct client-side failure classes. The shared
// `SdkError` taxonomy (parity-asserted vs the React Native SDK) stays
// untouched — the DPoP three-class taxonomy is a Flutter-local,
// rollout-observability surface: the two classes are kept distinct because
// they drive different client-side recovery paths.
//
// SECURITY invariants:
//   - bound + signer fails ⇒ `dpopProverUnavailable`, and NO proof-less network
//     call is made (never a silent Bearer downgrade).
//   - a fresh `jti` is minted per HTTP attempt (the nonce retry rebuilds the
//     proof), never reused across attempts (would trip server reuse-detection).
//   - the nonce retry re-presents the SAME `refresh_token` (no rotation between
//     attempts) and runs AT MOST once; a second challenge is terminal.

import 'dpop_session.dart';

/// RFC 9449 three-class client-side refresh failure taxonomy (+ network).
enum DpopRefreshErrorClass {
  /// This SDK/platform could not produce a proof (native signer failed / returned
  /// empty). NO proof-less network call is made — never a silent Bearer.
  dpopProverUnavailable,

  /// The server rejected the DPoP proof itself (`invalid_dpop_proof`, or a nonce
  /// challenge that survived the single bounded retry). Rollback-actionable.
  invalidDpopProof,

  /// Genuine refresh-token revocation/expiry ⇒ full re-login.
  invalidRefreshToken,

  /// Transport/network failure.
  network,
}

/// Stable `auth/<class>` wire code — parity with the Node and React Native SDKs.
extension DpopRefreshErrorClassWire on DpopRefreshErrorClass {
  String get wire {
    switch (this) {
      case DpopRefreshErrorClass.dpopProverUnavailable:
        return 'auth/dpop_prover_unavailable';
      case DpopRefreshErrorClass.invalidDpopProof:
        return 'auth/invalid_dpop_proof';
      case DpopRefreshErrorClass.invalidRefreshToken:
        return 'auth/invalid_refresh_token';
      case DpopRefreshErrorClass.network:
        return 'auth/network';
    }
  }
}

/// A typed DPoP-refresh failure. NEVER carries token/proof/key material in
/// [message] — error class + a short non-secret note only.
class DpopRefreshError {
  const DpopRefreshError(this.errorClass, this.message);

  final DpopRefreshErrorClass errorClass;
  final String message;

  /// `auth/<class>` string — parity with the Node and React Native SDKs.
  String get code => errorClass.wire;

  @override
  String toString() => 'DpopRefreshError(${errorClass.wire}): $message';
}

/// The normalized outcome of a single refresh-token exchange, as seen by
/// [refreshWithDpop]. Produced by the injected [DpopRefreshPoster].
class TokenPostResult {
  const TokenPostResult({
    required this.statusCode,
    this.tokenType,
    this.accessToken,
    this.refreshToken,
    this.oauthError,
    this.dpopNonce,
    this.networkFailure = false,
  });

  /// HTTP status (0 when [networkFailure] — no response was received).
  final int statusCode;

  /// `token_type` from a 200 body (`"DPoP"` | `"Bearer"`), if present.
  final String? tokenType;

  /// `access_token` from a 200 body.
  final String? accessToken;

  /// `refresh_token` from a 200 body (may be rotated).
  final String? refreshToken;

  /// RFC 6749 §5.2 `error` code from a non-200 body (`use_dpop_nonce`,
  /// `invalid_dpop_proof`, `invalid_grant`,...).
  final String? oauthError;

  /// RFC 9449 §8 server nonce from the `DPoP-Nonce` response header, when the
  /// failure was a `use_dpop_nonce` challenge.
  final String? dpopNonce;

  /// `true` when the request threw before a response (DNS/TLS/socket).
  final bool networkFailure;

  bool get isOk => statusCode == 200 && accessToken != null;
}

/// Poster seam: performs ONE `POST /v1/auth/refresh` with the given `refresh_token`
/// and optional `DPoP` proof header, and normalizes the response into a
/// [TokenPostResult]. Injected so the decision logic is host-testable and stays
/// decoupled from the concrete HTTP client.
typedef DpopRefreshPoster =
    Future<TokenPostResult> Function({
      required String refreshToken,
      String? dpopProof,
    });

/// The result of [refreshWithDpop].
class DpopRefreshOutcome {
  const DpopRefreshOutcome.success({
    required this.tokens,
    required this.attachedProof,
  }) : error = null;

  const DpopRefreshOutcome.failure(this.error)
    : tokens = null,
      attachedProof = false;

  final TokenPostResult? tokens;
  final bool attachedProof;
  final DpopRefreshError? error;

  bool get isOk => error == null;
}

DpopRefreshOutcome _proverUnavailable([
  String message = 'DPoP prover unavailable',
]) => DpopRefreshOutcome.failure(
  DpopRefreshError(DpopRefreshErrorClass.dpopProverUnavailable, message),
);

/// Refresh the access token, attaching a DPoP proof IFF [session] is bound.
/// Performs the single bounded nonce retry and maps every failure into the
/// three-class taxonomy. On success, re-confirms bound-truth from `token_type`.
///
/// [tokenEndpoint] is the full refresh URL used to build the proof `htu`.
Future<DpopRefreshOutcome> refreshWithDpop({
  required DpopRefreshPoster post,
  required String tokenEndpoint,
  required String refreshToken,
  DpopSession? session,
}) async {
  final bound = session?.isBound == true;

  // ── Bearer path — no proof attached. ──
  if (!bound || session == null) {
    final result = await post(refreshToken: refreshToken);
    if (result.networkFailure) {
      return const DpopRefreshOutcome.failure(
        DpopRefreshError(DpopRefreshErrorClass.network, 'network failure'),
      );
    }
    if (result.isOk) {
      await session?.observeTokenType(result.tokenType, attachedProof: false);
      return DpopRefreshOutcome.success(tokens: result, attachedProof: false);
    }
    return _mapFailure(result);
  }

  // ── Bound path — resolve a proof; a signer failure is terminal, NO Bearer fallback. ──
  String proof;
  try {
    proof = await session.resolveProof('POST', tokenEndpoint);
  } catch (e) {
    return _proverUnavailable('DPoP prover threw: $e');
  }
  if (proof.isEmpty) {
    return _proverUnavailable('DPoP prover returned an empty proof');
  }

  var result = await post(refreshToken: refreshToken, dpopProof: proof);

  // ── Single bounded nonce retry: rebuild the proof (fresh jti) with the
  //    server nonce, re-present the SAME refresh_token. At most once. ──
  if (!result.isOk && result.dpopNonce != null) {
    String retryProof;
    try {
      retryProof = await session.resolveProof(
        'POST',
        tokenEndpoint,
        nonce: result.dpopNonce,
      );
    } catch (e) {
      return _proverUnavailable('DPoP prover threw on nonce retry: $e');
    }
    if (retryProof.isEmpty) {
      return _proverUnavailable(
        'DPoP prover returned an empty proof on nonce retry',
      );
    }
    result = await post(refreshToken: refreshToken, dpopProof: retryProof);
  }

  if (result.networkFailure) {
    return const DpopRefreshOutcome.failure(
      DpopRefreshError(DpopRefreshErrorClass.network, 'network failure'),
    );
  }
  if (result.isOk) {
    await session.observeTokenType(result.tokenType, attachedProof: true);
    return DpopRefreshOutcome.success(tokens: result, attachedProof: true);
  }
  return _mapFailure(result);
}

/// Map a non-OK [TokenPostResult] into the three-class taxonomy.
DpopRefreshOutcome _mapFailure(TokenPostResult result) {
  if (result.networkFailure) {
    return const DpopRefreshOutcome.failure(
      DpopRefreshError(DpopRefreshErrorClass.network, 'network failure'),
    );
  }
  // A proof rejection (or a nonce challenge that survived the single retry — a
  // second `use_dpop_nonce` is a proof problem, not a revocation) is the distinct,
  // rollback-actionable `invalidDpopProof` class.
  if (result.oauthError == 'invalid_dpop_proof' ||
      result.oauthError == 'use_dpop_nonce' ||
      result.dpopNonce != null) {
    return const DpopRefreshOutcome.failure(
      DpopRefreshError(
        DpopRefreshErrorClass.invalidDpopProof,
        'server rejected the DPoP proof',
      ),
    );
  }
  // Genuine revocation/expiry (or any other terminal auth failure) ⇒ full re-login.
  return const DpopRefreshOutcome.failure(
    DpopRefreshError(
      DpopRefreshErrorClass.invalidRefreshToken,
      'refresh token rejected',
    ),
  );
}
