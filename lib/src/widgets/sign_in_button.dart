import 'package:flutter/cupertino.dart';
import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';

import '../auth/social_provider.dart';
import '../oauth/social_auth.dart';
import 'provider.dart';

/// One-tap social sign-in button. Wraps `RakomiAuth.signInWithProvider`.
class RakomiSignInButton extends StatelessWidget {
  const RakomiSignInButton({
    super.key,
    required this.provider,
    this.label,
    this.style,
  });

  final SocialProvider provider;
  final String? label;
  final ButtonStyle? style;

  bool get _isCupertino => defaultTargetPlatform == TargetPlatform.iOS;

  @override
  Widget build(BuildContext context) {
    final auth = RakomiProvider.maybeOf(context);
    if (auth == null) return const SizedBox.shrink();
    final providerWidget = context
        .findAncestorWidgetOfExactType<RakomiProvider>();
    final redirectUri = providerWidget?.redirectUri ?? 'rakomi://callback';
    final text = label ?? 'Continue with ${provider.wire}';
    return Semantics(
      button: true,
      label: text,
      child: _isCupertino
          ? CupertinoButton(
              onPressed: () =>
                  performSocialSignIn(auth, provider, redirectUri: redirectUri),
              child: Text(text),
            )
          : OutlinedButton(
              style: style,
              onPressed: () =>
                  performSocialSignIn(auth, provider, redirectUri: redirectUri),
              child: Text(text),
            ),
    );
  }
}
