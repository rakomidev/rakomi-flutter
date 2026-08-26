// SDK error taxonomy.
//
// Mirrors `@rakomi/react-native`'s `AuthError` shape:
//
// - SdkErrorCode — top-level error category (one-of). Mirrors the React
//   Native SDK's `AuthErrorCode` literal-union 1:1 (parity-asserted in CI).
// - SdkErrorReason — discriminating sub-reason within a code (most useful
//   for OAuth flow errors and biometric gate failures).
//
// Errors NEVER throw across the public API surface — they are emitted via
// `authStateChanges` as an `AuthState.error(SdkError(...))` envelope.
// Programmer errors (assertion violations on construction) DO throw
// synchronously via `ArgumentError`.

/// Top-level SDK error code. 1:1 parity with `@rakomi/react-native`'s
/// `AuthError.code` literal-union.
enum SdkErrorCode {
  refreshFailed,
  oauthCallbackError,
  tenantSuspended,
  csrfMismatch,
  codeExchangeFailed,
  signInFailed,
  invalidConfig,
  networkError,
  providerError,
  biometricError,
  storageError,
  rateLimited,
  invalidCredentials,
  mfaStepUpRequired,
  mfaStepUpUnavailable,
  unknown,
}

/// Discriminating sub-reason. Combined with [SdkErrorCode] gives the full
/// error taxonomy. Wire-level enum values match `@rakomi/react-native`'s
/// `oauth_*`/`biometric_*` reasons (parity-asserted in CI).
enum SdkErrorReason {
  // OAuth flow reasons (React Native SDK parity)
  oauthUserCancelled,
  oauthLocked,
  oauthStateMismatch,
  oauthRedirectMismatch,
  oauthMissingParams,
  oauthProviderError,
  // Biometric gate reasons (Flutter-specific; the React Native SDK treats
  // biometric as a runtime gate, not an auth-flow error — the Flutter SDK
  // surfaces these as typed reasons for ergonomic error handling).
  biometricCancelled,
  biometricLockout,
  biometricNotEnrolled,
  biometricUnavailable,
  // Session lifecycle reasons
  sessionExpired,
  sessionRevoked,
  // Session refresh failure reasons (mirrors the React Native SDK's
  // `REFRESH_FAILED.reason`)
  refreshExpired,
  refreshRevoked,
  refreshNetwork,
  // Cert-pinning failure.
  // Surfaced when a configured cert pin does not match the peer certificate
  // SHA-256 fingerprint observed at TLS handshake time.
  certPinMismatch,
  // Generic
  network,
  unknown,
}

/// Wire-level string for [SdkErrorReason] — used in `SdkError.toString()`,
/// JSON serialization for log forwarding, and the parity test fixture.
extension SdkErrorReasonWire on SdkErrorReason {
  String get wire {
    switch (this) {
      case SdkErrorReason.oauthUserCancelled:
        return 'oauth_user_cancelled';
      case SdkErrorReason.oauthLocked:
        return 'oauth_locked';
      case SdkErrorReason.oauthStateMismatch:
        return 'oauth_state_mismatch';
      case SdkErrorReason.oauthRedirectMismatch:
        return 'oauth_redirect_mismatch';
      case SdkErrorReason.oauthMissingParams:
        return 'oauth_missing_params';
      case SdkErrorReason.oauthProviderError:
        return 'oauth_provider_error';
      case SdkErrorReason.biometricCancelled:
        return 'biometric_cancelled';
      case SdkErrorReason.biometricLockout:
        return 'biometric_lockout';
      case SdkErrorReason.biometricNotEnrolled:
        return 'biometric_not_enrolled';
      case SdkErrorReason.biometricUnavailable:
        return 'biometric_unavailable';
      case SdkErrorReason.sessionExpired:
        return 'session_expired';
      case SdkErrorReason.sessionRevoked:
        return 'session_revoked';
      case SdkErrorReason.refreshExpired:
        return 'refresh_expired';
      case SdkErrorReason.refreshRevoked:
        return 'refresh_revoked';
      case SdkErrorReason.refreshNetwork:
        return 'refresh_network';
      case SdkErrorReason.certPinMismatch:
        return 'cert_pin_mismatch';
      case SdkErrorReason.network:
        return 'network';
      case SdkErrorReason.unknown:
        return 'unknown';
    }
  }
}

/// Wire-level string for [SdkErrorCode] — see [SdkErrorReasonWire] for rationale.
extension SdkErrorCodeWire on SdkErrorCode {
  String get wire {
    switch (this) {
      case SdkErrorCode.refreshFailed:
        return 'REFRESH_FAILED';
      case SdkErrorCode.oauthCallbackError:
        return 'OAUTH_CALLBACK_ERROR';
      case SdkErrorCode.tenantSuspended:
        return 'TENANT_SUSPENDED';
      case SdkErrorCode.csrfMismatch:
        return 'CSRF_MISMATCH';
      case SdkErrorCode.codeExchangeFailed:
        return 'CODE_EXCHANGE_FAILED';
      case SdkErrorCode.signInFailed:
        return 'SIGN_IN_FAILED';
      case SdkErrorCode.invalidConfig:
        return 'INVALID_CONFIG';
      case SdkErrorCode.networkError:
        return 'NETWORK_ERROR';
      case SdkErrorCode.providerError:
        return 'PROVIDER_ERROR';
      case SdkErrorCode.biometricError:
        return 'BIOMETRIC_ERROR';
      case SdkErrorCode.storageError:
        return 'STORAGE_ERROR';
      case SdkErrorCode.rateLimited:
        return 'RATE_LIMITED';
      case SdkErrorCode.invalidCredentials:
        return 'INVALID_CREDENTIALS';
      case SdkErrorCode.mfaStepUpRequired:
        return 'MFA_STEP_UP_REQUIRED';
      case SdkErrorCode.mfaStepUpUnavailable:
        return 'MFA_STEP_UP_UNAVAILABLE';
      case SdkErrorCode.unknown:
        return 'UNKNOWN';
    }
  }
}

/// Sealed SDK error envelope. Always emitted via `authStateChanges` —
/// never thrown across the public API. (Programmer errors throw via
/// `ArgumentError` synchronously on construction.)
class SdkError {
  const SdkError({
    required this.code,
    required this.reason,
    this.errorMessage,
    this.providerError,
    this.cause,
  });

  final SdkErrorCode code;
  final SdkErrorReason reason;
  final String? errorMessage;
  final String? providerError;
  final Object? cause;

  /// JWT-shape redaction regex.
  ///
  /// Matches: any compact-form JWT (`eyJ...eyJ...`-style header.payload pair,
  /// trailing signature included) anywhere in the string, AND the literal
  /// `Bearer <token>` prefix anywhere. NOT anchored — embedded tokens in
  /// wrapped error messages must be redacted — a token that survives redaction
  /// is a token leak.
  static final RegExp _jwtShape = RegExp(
    r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
  );
  // caseInsensitive: RFC 7235 §2.1 makes the auth-scheme case-insensitive, so
  // `bearer <token>` is a real wire form. Matching only `Bearer` let it through
  // redaction untouched. The Swift port already had this flag.
  static final RegExp _bearerShape = RegExp(
    r'Bearer\s+[A-Za-z0-9_\-\.]+',
    caseSensitive: false,
  );

  /// Redact bearer tokens / JWTs from any string before it is logged or
  /// emitted. Takes its input as a parameter so EVERY carried string can be
  /// passed through it — `errorMessage` was redacted while `providerError`,
  /// which arrives on the OAuth callback URL, was not.
  static String _redact(String? value) {
    if (value == null) return '';
    return value
        .replaceAll(_jwtShape, '[redacted]')
        .replaceAll(_bearerShape, '[redacted]');
  }

  /// Redacted form of [errorMessage].
  String get _redactedMessage => _redact(errorMessage);

  @override
  String toString() {
    final parts = <String>[
      'code=${code.wire}',
      'reason=${reason.wire}',
      if (errorMessage != null) 'message=$_redactedMessage',
      // Redacted: the value comes from the provider's `error_description`,
      // which arrives on the callback URL and is therefore attacker-influenced.
      if (providerError != null) 'provider=${_redact(providerError)}',
    ];
    return 'SdkError(${parts.join(', ')})';
  }

  Map<String, Object?> toJson() => <String, Object?>{
    'code': code.wire,
    'reason': reason.wire,
    if (errorMessage != null) 'errorMessage': _redactedMessage,
    if (providerError != null) 'providerError': _redact(providerError),
  };
}
