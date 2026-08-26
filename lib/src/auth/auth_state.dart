import 'package:meta/meta.dart';

import 'errors.dart';
import 'user.dart';

/// Discriminated current auth-state snapshot. Emitted via
/// `RakomiAuth.instance.authStateChanges` (broadcast `Stream<AuthState>`).
///
/// Sealed-class pattern: pattern-match via `switch` (Dart 3 sealed enums) or
/// the [AuthState.when] helper.
@immutable
sealed class AuthState {
  const AuthState();

  /// Pattern-match helper. `Loading` is the only state without a typed
  /// payload; all others carry typed data.
  T when<T>({
    required T Function() loading,
    required T Function() unauthenticated,
    required T Function(User user, Session session) authenticated,
    required T Function(SdkError error) error,
  }) {
    final self = this;
    if (self is AuthStateLoading) return loading();
    if (self is AuthStateUnauthenticated) return unauthenticated();
    if (self is AuthStateAuthenticated) {
      return authenticated(self.user, self.session);
    }
    if (self is AuthStateError) return error(self.error);
    throw StateError('Unhandled AuthState variant: $self');
  }

  bool get isAuthenticated => this is AuthStateAuthenticated;
  bool get isLoaded => this is! AuthStateLoading;
}

class AuthStateLoading extends AuthState {
  const AuthStateLoading();

  @override
  String toString() => 'AuthState.loading()';

  @override
  bool operator ==(Object other) => other is AuthStateLoading;

  @override
  int get hashCode => 0;
}

class AuthStateUnauthenticated extends AuthState {
  const AuthStateUnauthenticated();

  @override
  String toString() => 'AuthState.unauthenticated()';

  @override
  bool operator ==(Object other) => other is AuthStateUnauthenticated;

  @override
  int get hashCode => 1;
}

class AuthStateAuthenticated extends AuthState {
  const AuthStateAuthenticated(this.user, this.session);

  final User user;
  final Session session;

  @override
  String toString() =>
      'AuthState.authenticated(user=${user.id}, session=${session.id})';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is AuthStateAuthenticated &&
          other.user == user &&
          other.session.id == session.id);

  @override
  int get hashCode => Object.hash(user, session.id);
}

class AuthStateError extends AuthState {
  const AuthStateError(this.error);

  final SdkError error;

  @override
  String toString() => 'AuthState.error($error)';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is AuthStateError &&
          other.error.code == error.code &&
          other.error.reason == error.reason);

  @override
  int get hashCode => Object.hash(error.code, error.reason);
}
