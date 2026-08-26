// rakomi_flutter — DPoP session handle.
//
// The Flutter flavour of `@rakomi/node`'s `DpopSession` (the same named
// contract shared across every Rakomi SDK). The ONLY runtime
// difference is that the keypair lives in the NATIVE keystore, so the prover is
// INJECTED (the native `MethodChannel` bridge), never constructed here — Dart
// never holds the private key.
//
// A [DpopSession] bundles THREE things so "have a prover" ≡ "is bound" by
// construction (no separable prover + flag that can drift):
//
//   1. ONE native keypair per session, fronted by the injected [DpopProver]. The
//      SAME prover MUST serve issuance and every refresh — the server binds
//      `dpop_jkt` to the key it saw at issuance, so a fresh keypair on refresh ⇒
//      `jkt` mismatch ⇒ 401 on every bound refresh (the exact mass-lockout
//      this design prevents, re-introduced client-side). One [DpopSession] = one
//      keypair = one bound refresh lineage; never share a refresh token across
//      two [DpopSession] instances.
//
//   2. Bound-truth — re-confirmed from `token_type` on EVERY token
//      response. A proof is attached on refresh IFF the server's latest signal is
//      `token_type == "DPoP"`, never from the SDK's own capability. A capable SDK
//      facing a Bearer session attaches NO proof.
//
//   3. A security-downgrade detector — a session that opted into DPoP but that
//      the server returned as `Bearer` is surfaced via [onDowngrade] /
//      [isDowngraded]; it never silently proceeds as Bearer.
//
// COLD-START: the native key is session-scoped; a fresh
// [DpopSession] after an app restart has NOT observed a `DPoP` issuance, so
// [isBound] is `false` and refresh attaches NO proof. Against a server in `on`
// mode the proof-less refresh of an already-bound server session is rejected with
// the typed `invalid_dpop_proof` → the app re-logins to re-bind a fresh key. The
// SDK NEVER emits a malformed proof and NEVER silently downgrades to Bearer.
// Deterministic key persistence across a restart is a separate, planned
// change; the behaviour above is the current, pinned one.

import 'package:meta/meta.dart';

import '../internal/canonical_url.dart';
import 'dpop_prover.dart';

/// Reason a DPoP-requested session was downgraded to Bearer by the server.
@immutable
class DpopDowngradeInfo {
  const DpopDowngradeInfo({this.reason = 'server_returned_bearer'});

  /// The server returned `token_type: "Bearer"` for a session that presented a
  /// DPoP proof.
  final String reason;
}

/// Opaque, session-scoped DPoP binding handle. Create ONE per logged-in session,
/// pass it to the auth ceremony AND every refresh for that session. Never share
/// an instance across distinct sessions or across a refresh-token boundary.
class DpopSession {
  DpopSession({
    required DpopProver prover,
    required String baseUrl,
    void Function(DpopDowngradeInfo info)? onDowngrade,
  }) : _prover = prover,
       // Normalize away a trailing slash so `$baseUrl$path` never doubles it.
       _baseUrl = baseUrl.endsWith('/')
           ? baseUrl.substring(0, baseUrl.length - 1)
           : baseUrl,
       _onDowngrade = onDowngrade;

  final DpopProver _prover;
  final String _baseUrl;
  final void Function(DpopDowngradeInfo info)? _onDowngrade;

  bool _bound = false;
  bool _downgraded = false;
  bool _downgradeNotified = false;
  String? _boundJkt;

  static final RegExp _absoluteUrl = RegExp(
    r'^[a-z][a-z0-9+.-]*://',
    caseSensitive: false,
  );

  /// `true` once the server has confirmed (`token_type == "DPoP"`) that this
  /// session's key is sender-bound. The SDK attaches a refresh proof IFF this is
  /// `true`. Starts `false`; set by observing issuance/refresh responses.
  bool get isBound => _bound;

  /// `true` if a session that presented a DPoP proof was returned as `Bearer` by
  /// the server (a security downgrade — flag off / server-side downgrade).
  bool get isDowngraded => _downgraded;

  /// The committed RFC 7638 thumbprint (`jkt`) of the session keypair, once bound.
  String? get boundJkt => _boundJkt;

  /// @internal — resolve a finished compact proof STRING for [htm] + [target]
  /// using the session's single native keypair. Canonicalizes the FULL target
  /// into the RFC 9449 §4.3 `htu` (scheme+host+path; query/fragment + default
  /// port stripped), then delegates signing to the injected native prover.
  /// [target] may be an absolute URL or a `$baseUrl`-relative path. The transport
  /// layer only ever receives the returned string, never the prover (the
  /// layering). May throw if the native signer fails; callers map that to
  /// `dpop_prover_unavailable` and MUST NOT fall back to a proof-less call.
  Future<String> resolveProof(
    String htm,
    String target, {
    String? nonce,
  }) async {
    final absolute = _absoluteUrl.hasMatch(target)
        ? target
        : '$_baseUrl$target';
    final htu = canonicalizeUrl(absolute);
    return _prover.createProof(
      DpopProofInput(htm: htm, htu: htu, nonce: nonce),
    );
  }

  /// @internal — RFC 7638 thumbprint of the session keypair.
  Future<String> jktHint() => _prover.jktHint();

  /// @internal — update bound-truth from a token response. Called
  /// after EVERY token response while a session is attached.
  ///
  /// [tokenType] is the `token_type` from the response (`"DPoP"` | `"Bearer"`).
  /// [attachedProof] is whether THIS call presented a DPoP proof (opted in).
  Future<void> observeTokenType(
    String? tokenType, {
    required bool attachedProof,
  }) async {
    if (tokenType == 'DPoP') {
      _bound = true;
      _downgraded = false;
      _boundJkt ??= await _prover.jktHint();
      return;
    }
    // Server signalled Bearer (or omitted token_type) — follow the server's
    // signal, never our own capability: the session is NOT bound.
    _bound = false;
    if (attachedProof) {
      _downgraded = true;
      if (!_downgradeNotified) {
        _downgradeNotified = true;
        _onDowngrade?.call(const DpopDowngradeInfo());
      }
    }
  }
}
