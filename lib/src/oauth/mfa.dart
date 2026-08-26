import 'package:http/http.dart' as http;

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../auth/auth_state.dart';
import '../auth/errors.dart';
import '../internal/http_client.dart';

/// MFA TOTP / step-up handling.
///
/// **Contract**:
///
/// - The API responds to a primary login with `{"next_action": "verify_mfa",
///   "challenge_id": "ch_…", "available_methods": ["totp"]}` when MFA is
///   required. The SDK consumes `next_action` literally; legacy
///   `mfa_challenge_token` is NOT consumed.
/// - Mid-session step-up (`MfaStepUpRequiredError`) — re-render the TOTP
///   view; the SDK transparently transitions back to authenticated on
///   verify-success.
/// - `MfaStepUpUnavailableError` — passwordless-only user; surface as
///   `SdkError(reason: mfa_step_up_unavailable,...)` with the SDK guidance
///   string.
extension RakomiMfaFlow on RakomiAuth {
  /// Verify a TOTP code against the API. [challengeId] is the value returned
  /// from the primary login's `verify_mfa` response.
  Future<AuthState> verifyMfaImpl(
    String code, {
    required String challengeId,
  }) async {
    // Client-side input format guard. 6 numeric chars; leading
    // zeros preserved. Reject non-conforming input BEFORE any API call.
    final ok = RegExp(r'^\d{6}$').hasMatch(code);
    if (!ok) {
      const state = AuthStateError(
        SdkError(
          code: SdkErrorCode.invalidCredentials,
          reason: SdkErrorReason.unknown,
          errorMessage: 'totp_format',
        ),
      );
      setState(state);
      emitAppState(
        AuthEventType.signInFailed,
        AuthEventSeverity.security,
        errorMessage: 'totp_format',
      );
      return state;
    }

    final inner = adapter.httpClient;
    if (inner is! http.Client) {
      throw StateError('Adapter httpClient must be a package:http Client');
    }
    final client = RakomiHttpClient(inner, userAgent: 'rakomi_flutter/0.1.0');
    try {
      final r = await client.postJson(
        Uri.parse('$apiBaseUrl/v1/auth/mfa/totp/verify'),
        <String, Object?>{
          'challenge_id': challengeId,
          'code': code,
          'tenant_id': tenantId,
        },
      );
      if (r.statusCode == 401) {
        const state = AuthStateError(
          SdkError(
            code: SdkErrorCode.invalidCredentials,
            reason: SdkErrorReason.unknown,
            errorMessage: 'totp_invalid',
          ),
        );
        setState(state);
        return state;
      }
      if (r.statusCode == 403) {
        const state = AuthStateError(
          SdkError(
            code: SdkErrorCode.mfaStepUpUnavailable,
            reason: SdkErrorReason.unknown,
          ),
        );
        setState(state);
        return state;
      }
      if (r.statusCode != 200) {
        const state = AuthStateError(
          SdkError(
            code: SdkErrorCode.networkError,
            reason: SdkErrorReason.network,
          ),
        );
        setState(state);
        return state;
      }
      final body = decodeJsonBody(r);
      emitAppState(
        AuthEventType.componentStepChanged,
        AuthEventSeverity.info,
        metadata: <String, Object?>{'step': 'mfa_verified'},
      );
      return completeSignIn(body);
    } catch (e) {
      final state = AuthStateError(
        SdkError(
          code: SdkErrorCode.networkError,
          reason: SdkErrorReason.network,
          errorMessage: '$e',
        ),
      );
      setState(state);
      return state;
    }
  }
}
