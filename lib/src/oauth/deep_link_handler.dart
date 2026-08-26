import 'dart:async';

import '../auth/auth_controller.dart';
import '../auth/auth_event.dart';
import '../native/adapter.dart';

/// Deep-link OAuth callback handler.
///
/// **Lifecycle**: subscribed in `RakomiProvider.initState` (warm + cold
/// start).  Idempotent ingest: each callback URI is processed exactly once
/// (the OAuth state's single-use enforcement is the actual deduper —
/// re-ingesting the same URI is a no-op once the state has been consumed).
class DeepLinkOAuthHandler {
  DeepLinkOAuthHandler({required this.adapter, required this.auth});

  final RakomiNativeAdapter adapter;
  final RakomiAuth auth;

  StreamSubscription<Uri>? _sub;

  Future<void> start() async {
    // Cold-start link first.
    final initial = await adapter.getInitialDeepLink();
    if (initial != null) await _onLink(initial);
    // Warm subscription.
    _sub = adapter.deepLinkStream.listen(_onLink);
  }

  Future<void> _onLink(Uri uri) async {
    auth.emitAppState(
      AuthEventType.deepLinkReceived,
      AuthEventSeverity.security,
      metadata: <String, Object?>{'host': uri.host, 'scheme': uri.scheme},
    );
    // The actual OAuth callback routing lives in `social_auth.dart` —
    // `signInWithProviderImpl` awaits the result of `launchSystemBrowser`
    // synchronously, so warm deep-link delivery is the cold-start fallback
    // path only. We leave a hook here for platforms where the system browser
    // doesn't return inline (e.g. external Custom Tabs without a callback
    // bridge).
  }

  Future<void> dispose() async {
    await _sub?.cancel();
  }
}
