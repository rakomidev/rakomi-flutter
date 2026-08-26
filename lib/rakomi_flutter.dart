/// Rakomi Flutter SDK — RFC 8252-compliant OAuth/PKCE authentication for
/// Flutter apps targeting iOS, Android and Flutter Web.
///
/// See [RakomiProvider] for the entry point and `README.md` for the
/// <15-line quickstart.
library;

// Auth — controller, state, errors, models
export 'src/auth/auth_controller.dart' show RakomiAuth, kDefaultRefreshLeadtime;
export 'src/auth/auth_event.dart'
    show AuthEvent, AuthEventType, AuthEventSeverity;
export 'src/auth/auth_state.dart'
    show
        AuthState,
        AuthStateAuthenticated,
        AuthStateUnauthenticated,
        AuthStateLoading,
        AuthStateError;
// DPoP (RFC 9449) sender-constrained refresh — prover contract + session handle
//. The native-keystore prover is wired
// by the consumer; the JS/Dart layer never holds the private key.
export 'src/auth/dpop_prover.dart'
    show
        DpopProver,
        DpopProofInput,
        NativeDpopSigner,
        NativeKeystoreDpopProver,
        base64UrlNoPad;
export 'src/auth/dpop_refresh.dart'
    show
        DpopRefreshError,
        DpopRefreshErrorClass,
        DpopRefreshErrorClassWire,
        DpopRefreshOutcome,
        DpopRefreshPoster,
        TokenPostResult,
        refreshWithDpop;
export 'src/auth/dpop_session.dart' show DpopSession, DpopDowngradeInfo;
export 'src/auth/errors.dart'
    show
        SdkError,
        SdkErrorCode,
        SdkErrorReason,
        SdkErrorCodeWire,
        SdkErrorReasonWire;
export 'src/auth/social_provider.dart' show SocialProvider, SocialProviderWire;
export 'src/auth/user.dart' show User, Session;
// Publisher-webhook receiver helpers. `verifyWebhook` is the
// raw generic; `verifyPublisherWebhook` is the recommended publisher entry point.
export 'src/internal/webhook_verify.dart'
    show
        WebhookVerifyResult,
        WebhookVerifyOk,
        WebhookVerifyFailure,
        WebhookVerifyErrorClass,
        verifyWebhook,
        verifyPublisherWebhook,
        kDefaultWebhookTolerance,
        kMaxWebhookTolerance;
// Native adapter
export 'src/native/adapter.dart'
    show
        RakomiNativeAdapter,
        BiometricResult,
        BiometricSuccess,
        BiometricCancelled,
        BiometricLockout,
        BiometricNotEnrolled,
        BiometricUnavailable;
export 'src/native/default_adapter.dart' show DefaultRakomiNativeAdapter;
// OAuth — public facade for programmatic social sign-in (the widgets
// `RakomiSignInForm` / `RakomiSignInButton` use this internally).
export 'src/oauth/social_auth.dart' show performSocialSignIn;
export 'src/widgets/auth_gate.dart' show RakomiAuthGate;
// Widgets
export 'src/widgets/provider.dart' show RakomiProvider;
export 'src/widgets/sign_in_button.dart' show RakomiSignInButton;
export 'src/widgets/sign_in_form.dart' show RakomiSignInForm;
export 'src/widgets/user_avatar.dart' show RakomiUserAvatar;
