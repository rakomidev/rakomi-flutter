import 'package:http/http.dart' as http;

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../auth/auth_state.dart';
import '../auth/errors.dart';
import '../internal/http_client.dart';
import '../internal/version.dart';

/// MFA TOTP / step-up handling.
///
/// **Contract** (the login-response MFA-challenge union member and
/// `POST /v1/auth/mfa/verify-login`):
///
/// - The API responds to a primary login with `{"next_step": "mfa_verify",
///   "mfa_challenge_token": "…", "expires_in": …, "available_methods": [...]}`
///   when MFA is required.
/// - The challenge is redeemed at `POST /v1/auth/mfa/verify-login` with
///   `{"mfa_challenge_token": "…", "code": "…"}` — `apiKeyAuth()`-guarded, so
///   the publishable key travels as `X-API-Key` like every other
///   `apiKeyAuth()` endpoint this SDK calls.
/// - Mid-session step-up (`MfaStepUpRequiredError`) — re-render the TOTP
///   view; the SDK transparently transitions back to authenticated on
///   verify-success.
/// - `MfaStepUpUnavailableError` — passwordless-only user; surface as
///   `SdkError(reason: mfa_step_up_unavailable,...)` with the SDK guidance
///   string.
extension RakomiMfaFlow on RakomiAuth {
  /// Verify a TOTP code against the API. [challengeId] is the
  /// `mfa_challenge_token` value returned from the primary login's
  /// `mfa_verify` response.
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
    final client = RakomiHttpClient(inner, userAgent: rakomiFlutterUserAgent);
    try {
      final r = await client.postJson(
        Uri.parse('$apiBaseUrl/v1/auth/mfa/verify-login'),
        <String, Object?>{'mfa_challenge_token': challengeId, 'code': code},
        headers: <String, String>{'X-API-Key': publishableKey},
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
      return completeSignIn(body, oauthClientId: null);
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
