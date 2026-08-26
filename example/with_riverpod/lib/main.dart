import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

/// Riverpod recipe for `rakomi_flutter`. NON-NORMATIVE — the SDK does NOT
/// depend on Riverpod. This demo shows how a Riverpod-based app reads
/// `authStateChanges` via a `StreamProvider`.

final authStateProvider = StreamProvider.autoDispose<AuthState>((ref) {
  // Resolve the per-tree RakomiAuth from the BuildContext via the
  // ProviderScope's child (which mounts RakomiProvider).
  final auth = ref.read(rakomiAuthProvider);
  return auth.authStateChanges;
});

/// Bridge provider — reads `RakomiAuth` from the InheritedNotifier scope.
/// Configure via `ProviderScope(overrides: [...])`.
final rakomiAuthProvider = Provider<RakomiAuth>((ref) {
  throw UnimplementedError(
    'Override rakomiAuthProvider from a ConsumerWidget under RakomiProvider — '
    'see example main() below for the wiring.',
  );
});

void main() {
  runApp(const ProviderScope(child: _Bootstrap()));
}

class _Bootstrap extends StatelessWidget {
  const _Bootstrap();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: RakomiProvider(
        publishableKey: 'pk_test_demo',
        redirectUri: 'rakomi://callback',
        child: Builder(
          builder: (BuildContext c) {
            final auth = RakomiProvider.of(c);
            return ProviderScope(
              overrides: <Override>[rakomiAuthProvider.overrideWithValue(auth)],
              child: const _Home(),
            );
          },
        ),
      ),
    );
  }
}

class _Home extends ConsumerWidget {
  const _Home();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(authStateProvider);
    return Scaffold(
      appBar: AppBar(title: const Text('Riverpod recipe')),
      body: state.when(
        data: (AuthState s) => s.when<Widget>(
          loading: () => const Center(child: CircularProgressIndicator()),
          unauthenticated: () => const Center(child: RakomiSignInForm()),
          authenticated: (User u, _) => Center(child: Text('Hello ${u.email}')),
          error: (SdkError e) => Center(child: Text('Error: $e')),
        ),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (Object e, _) => Center(child: Text('$e')),
      ),
    );
  }
}
