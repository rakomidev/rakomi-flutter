import 'package:flutter/cupertino.dart';
import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../auth/auth_state.dart';
import '../auth/errors.dart';
import '../auth/social_provider.dart';
import '../oauth/mfa.dart';
import '../oauth/social_auth.dart';
import 'provider.dart';

/// Pre-built sign-in form covering password / passwordless / social /
/// MFA-TOTP flows. Material on Android/Web; Cupertino on iOS.
///
/// **Input hardening**:
/// - Password `TextField` — `obscureText: true`, `enableInteractiveSelection: false`,
///   `autocorrect: false`, `enableSuggestions: false`.
/// - TOTP `TextField` — `enableInteractiveSelection: false`, `autocorrect: false`,
///   `enableSuggestions: false`, `keyboardType: number`, `maxLength: 6`,
///   `autofillHints: [oneTimeCode]`.
class RakomiSignInForm extends StatefulWidget {
  const RakomiSignInForm({
    super.key,
    this.providers = const <SocialProvider>[],
    this.onAuthenticated,
    this.style,
  });

  final List<SocialProvider> providers;
  final VoidCallback? onAuthenticated;
  final RakomiSignInFormStyle? style;

  @override
  State<RakomiSignInForm> createState() => _RakomiSignInFormState();
}

class RakomiSignInFormStyle {
  const RakomiSignInFormStyle({
    this.spacing = 12.0,
    this.padding = const EdgeInsets.all(16),
    this.formWidth,
    this.fieldDecoration,
  });
  final double spacing;
  final EdgeInsets padding;
  final double? formWidth;
  final InputDecoration? fieldDecoration;
}

enum _Step { credentials, mfa }

class _RakomiSignInFormState extends State<RakomiSignInForm> {
  final _emailCtrl = TextEditingController();
  final _passwordCtrl = TextEditingController();
  final _otpCtrl = TextEditingController();

  _Step _step = _Step.credentials;
  String? _challengeId;
  SdkError? _lastError;
  bool _busy = false;

  bool get _isCupertino => defaultTargetPlatform == TargetPlatform.iOS;

  @override
  void dispose() {
    _emailCtrl.dispose();
    _passwordCtrl.dispose();
    _otpCtrl.dispose();
    super.dispose();
  }

  Future<void> _signIn(RakomiAuth auth) async {
    setState(() {
      _busy = true;
      _lastError = null;
    });
    final state = await auth.signIn(
      email: _emailCtrl.text,
      password: _passwordCtrl.text,
    );
    if (!mounted) return;
    if (state is AuthStateAuthenticated) {
      setState(() => _busy = false);
      widget.onAuthenticated?.call();
      return;
    }
    if (state is AuthStateError &&
        state.error.code == SdkErrorCode.mfaStepUpRequired) {
      setState(() {
        _busy = false;
        _step = _Step.mfa;
        _challengeId = state.error.errorMessage;
      });
      return;
    }
    if (state is AuthStateError) {
      setState(() {
        _busy = false;
        _lastError = state.error;
      });
      return;
    }
    setState(() => _busy = false);
  }

  Future<void> _verifyMfa(RakomiAuth auth) async {
    if (_challengeId == null) return;
    setState(() => _busy = true);
    final result = await auth.verifyMfaImpl(
      _otpCtrl.text,
      challengeId: _challengeId!,
    );
    if (!mounted) return;
    if (result is AuthStateAuthenticated) {
      setState(() => _busy = false);
      widget.onAuthenticated?.call();
      return;
    }
    if (result is AuthStateError) {
      setState(() {
        _busy = false;
        _lastError = result.error;
      });
    }
  }

  Future<void> _provider(RakomiAuth auth, SocialProvider provider) async {
    setState(() => _busy = true);
    auth.emitAppState(AuthEventType.signInAttempted, AuthEventSeverity.info);
    await performSocialSignIn(
      auth,
      provider,
      redirectUri: _resolveRedirect(auth),
    );
    if (mounted) setState(() => _busy = false);
  }

  String _resolveRedirect(RakomiAuth auth) {
    // The provider passes redirectUri through context — keep this widget
    // self-contained by reading from the provider widget directly.
    final provider = context.findAncestorWidgetOfExactType<RakomiProvider>();
    return provider?.redirectUri ?? 'rakomi://callback';
  }

  @override
  Widget build(BuildContext context) {
    final auth = RakomiProvider.maybeOf(context);
    if (auth == null) {
      return const Center(child: SizedBox.shrink());
    }
    final style = widget.style ?? const RakomiSignInFormStyle();
    final form = Padding(
      padding: style.padding,
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: style.formWidth ?? 360),
        child: _step == _Step.mfa
            ? _buildMfa(style, auth)
            : _buildCredentials(style, auth),
      ),
    );
    return SafeArea(
      child: Center(child: SingleChildScrollView(child: form)),
    );
  }

  Widget _buildCredentials(RakomiSignInFormStyle style, RakomiAuth auth) {
    final children = <Widget>[
      Semantics(
        label: 'Email',
        textField: true,
        child: TextField(
          controller: _emailCtrl,
          keyboardType: TextInputType.emailAddress,
          autofillHints: const <String>[AutofillHints.email],
          decoration:
              style.fieldDecoration ??
              const InputDecoration(labelText: 'Email'),
          enableInteractiveSelection: false,
          autocorrect: false,
          enableSuggestions: false,
        ),
      ),
      SizedBox(height: style.spacing),
      Semantics(
        label: 'Password',
        textField: true,
        obscured: true,
        child: TextField(
          controller: _passwordCtrl,
          obscureText: true,
          autofillHints: const <String>[AutofillHints.password],
          decoration:
              style.fieldDecoration ??
              const InputDecoration(labelText: 'Password'),
          enableInteractiveSelection: false,
          autocorrect: false,
          enableSuggestions: false,
        ),
      ),
      SizedBox(height: style.spacing * 1.5),
      _busy
          ? _spinner()
          : (_isCupertino
                ? CupertinoButton.filled(
                    onPressed: () => _signIn(auth),
                    child: const Text('Sign in'),
                  )
                : ElevatedButton(
                    onPressed: () => _signIn(auth),
                    child: const Text('Sign in'),
                  )),
      if (widget.providers.isNotEmpty) ...<Widget>[
        SizedBox(height: style.spacing * 2),
        for (final p in widget.providers)
          Padding(
            padding: EdgeInsets.only(bottom: style.spacing),
            child: _isCupertino
                ? CupertinoButton(
                    onPressed: _busy ? null : () => _provider(auth, p),
                    child: Text('Continue with ${p.wire}'),
                  )
                : OutlinedButton(
                    onPressed: _busy ? null : () => _provider(auth, p),
                    child: Text('Continue with ${p.wire}'),
                  ),
          ),
      ],
      if (_lastError != null)
        Padding(
          padding: EdgeInsets.only(top: style.spacing),
          child: Text(
            _humaniseError(_lastError!),
            style: TextStyle(
              color: _isCupertino
                  ? CupertinoColors.systemRed
                  : Theme.of(context).colorScheme.error,
            ),
          ),
        ),
    ];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: children,
    );
  }

  Widget _buildMfa(RakomiSignInFormStyle style, RakomiAuth auth) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text(
          'Verify',
          style: _isCupertino
              ? const TextStyle(fontSize: 20, fontWeight: FontWeight.w600)
              : Theme.of(context).textTheme.headlineSmall,
        ),
        SizedBox(height: style.spacing),
        Semantics(
          label: 'Authentication code',
          textField: true,
          child: TextField(
            controller: _otpCtrl,
            keyboardType: TextInputType.number,
            maxLength: 6,
            autofillHints: const <String>[AutofillHints.oneTimeCode],
            decoration:
                style.fieldDecoration ??
                const InputDecoration(labelText: 'Code'),
            enableInteractiveSelection: false,
            autocorrect: false,
            enableSuggestions: false,
          ),
        ),
        SizedBox(height: style.spacing),
        _busy
            ? _spinner()
            : (_isCupertino
                  ? CupertinoButton.filled(
                      onPressed: () => _verifyMfa(auth),
                      child: const Text('Verify'),
                    )
                  : ElevatedButton(
                      onPressed: () => _verifyMfa(auth),
                      child: const Text('Verify'),
                    )),
        if (_lastError != null)
          Padding(
            padding: EdgeInsets.only(top: style.spacing),
            child: Text(
              _humaniseError(_lastError!),
              style: TextStyle(
                color: _isCupertino
                    ? CupertinoColors.systemRed
                    : Theme.of(context).colorScheme.error,
              ),
            ),
          ),
      ],
    );
  }

  Widget _spinner() => Center(
    child: _isCupertino
        ? const CupertinoActivityIndicator()
        : const CircularProgressIndicator(),
  );

  String _humaniseError(SdkError e) {
    switch (e.code) {
      case SdkErrorCode.invalidCredentials:
      case SdkErrorCode.signInFailed:
        return 'Invalid email or password.';
      case SdkErrorCode.networkError:
        return 'Network error. Please try again.';
      case SdkErrorCode.rateLimited:
        return 'Too many attempts. Try again later.';
      case SdkErrorCode.mfaStepUpUnavailable:
        return 'Multi-factor not available — sign in via your registered passwordless flow.';
      default:
        return 'Something went wrong.';
    }
  }
}
