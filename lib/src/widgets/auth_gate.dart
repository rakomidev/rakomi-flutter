import 'package:flutter/widgets.dart';

import '../auth/auth_controller.dart';
import '../auth/auth_state.dart';
import '../auth/errors.dart';
import '../auth/user.dart';
import 'provider.dart';

typedef RakomiSignedInBuilder =
    Widget Function(BuildContext context, User user);
typedef RakomiSignedOutBuilder = Widget Function(BuildContext context);
typedef RakomiLoadingBuilder = Widget Function(BuildContext context);
typedef RakomiErrorBuilder =
    Widget Function(BuildContext context, SdkError error);

/// Conditional renderer keyed off `RakomiAuth.authStateChanges`.
///
/// Builders for each variant of `AuthState`. `loading` and `error` are
/// optional — `loading` defaults to a shrunken `SizedBox`; `error` defaults
/// to the `signedOut` builder.
class RakomiAuthGate extends StatelessWidget {
  const RakomiAuthGate({
    super.key,
    required this.signedIn,
    required this.signedOut,
    this.loading,
    this.error,
  });

  final RakomiSignedInBuilder signedIn;
  final RakomiSignedOutBuilder signedOut;
  final RakomiLoadingBuilder? loading;
  final RakomiErrorBuilder? error;

  @override
  Widget build(BuildContext context) {
    final auth = RakomiProvider.maybeOf(context);
    if (auth == null) {
      return loading?.call(context) ?? const SizedBox.shrink();
    }
    return StreamBuilder<AuthState>(
      stream: auth.authStateChanges,
      initialData: auth.authState,
      builder: (BuildContext c, AsyncSnapshot<AuthState> snap) {
        final s = snap.data ?? const AuthStateLoading();
        return s.when<Widget>(
          loading: () => loading?.call(c) ?? const SizedBox.shrink(),
          unauthenticated: () => signedOut(c),
          authenticated: (User user, _) => signedIn(c, user),
          error: (SdkError e) => error?.call(c, e) ?? signedOut(c),
        );
      },
    );
  }
}

/// Re-export of [RakomiAuth] (per-tree) for non-widget call-sites. Looks up
/// the nearest `RakomiProvider` from [context].
RakomiAuth rakomiAuthOf(BuildContext context) => RakomiProvider.of(context);
