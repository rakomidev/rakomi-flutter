/// Fine-grained auth lifecycle events.
///
/// Emitted via `RakomiAuth.instance.events` (broadcast `Stream<AuthEvent>`).
/// Distinct from [AuthState] — events are append-only audit log entries,
/// state is the discriminated current snapshot.
///
/// Mirrors `@rakomi/react-native`'s `AuthEvent.type` literal-union plus the
/// 5 cross-SDK parity events.
///
/// **Audit significance** (per CRA Art. 14 + GDPR Art. 30): the consumer app
/// is responsible for forwarding events to its audit log. The SDK does NOT
/// auto-forward to any sink — `events` is a consumer-pull only Stream.
library;

/// Fine-grained auth event type. Values mirror the React Native SDK 1:1 (parity-asserted in
/// CI). Severity is a separate field on [AuthEventEnvelope]; see [AuthEvent].
enum AuthEventType {
  // Lifecycle
  initialized,
  restoreAttempted,
  restoreSucceeded,
  restoreFailed,
  // Tokens
  tokenReceived,
  refreshStarted,
  refreshSucceeded,
  refreshFailed,
  // Sign-in
  signInAttempted,
  signInFailed,
  signedIn,
  signedOut,
  // Cross-tab / lock
  tabSyncReceived,
  lockAcquired,
  lockTimeout,
  // Recovery
  networkRetry,
  preflightComplete,
  sessionMismatch,
  bfcacheRestore,
  // Component bus
  componentStepChanged,
  componentError,
  // Consent / context
  consentGranted,
  invalidContext,
  sessionExpiringSoon,
  // Cross-SDK parity events
  biometricFailed,
  offlineQueueDrained,
  clockSkewDetected,
  appStateForeground,
  deepLinkReceived,
  // Flutter-specific
  mfaChallengeRequired,
  mfaChallengeVerified,
  userUpdated,
}

/// Severity of an [AuthEvent]. Three levels:
/// - [info] — routine lifecycle (signedIn, refreshSucceeded).
/// - [warning] — non-fatal anomaly (refreshFailed-network, networkRetry).
/// - [security] — security-relevant (sessionMismatch, clockSkewDetected,
///   biometricFailed, deepLinkReceived). Forward to SOC/SIEM if applicable.
enum AuthEventSeverity { info, warning, security }

/// Auth event envelope. Carries the type + severity + timestamp + optional
/// metadata.
class AuthEvent {
  AuthEvent({
    required this.type,
    required this.severity,
    DateTime? timestamp,
    this.duration,
    this.tabId,
    this.errorMessage,
    this.metadata,
  }) : timestamp = timestamp ?? DateTime.now().toUtc();

  final AuthEventType type;
  final AuthEventSeverity severity;
  final DateTime timestamp;
  final Duration? duration;
  final String? tabId;
  final String? errorMessage;
  final Map<String, Object?>? metadata;

  Map<String, Object?> toJson() => <String, Object?>{
    'type': type.name,
    'severity': severity.name,
    'timestamp': timestamp.toIso8601String(),
    if (duration != null) 'durationMs': duration!.inMilliseconds,
    if (tabId != null) 'tabId': tabId,
    if (errorMessage != null) 'errorMessage': errorMessage,
    if (metadata != null) 'metadata': metadata,
  };

  @override
  String toString() => 'AuthEvent(${type.name}, ${severity.name}, $timestamp)';
}
