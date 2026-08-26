import 'dart:io';

import 'package:flutter/material.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

/// Configuration for the demo app, read from the environment.
class DemoConfig {
  const DemoConfig({required this.apiBaseUrl, required this.publishableKey});

  final String apiBaseUrl;
  final String publishableKey;
}

/// Reads `RAKOMI_API_BASE_URL` and `RAKOMI_PUBLISHABLE_KEY`, falling back to
/// the public API host and a test publishable key.
DemoConfig loadDemoConfig() => DemoConfig(
  apiBaseUrl:
      Platform.environment['RAKOMI_API_BASE_URL'] ?? 'https://api.rakomi.com',
  publishableKey:
      Platform.environment['RAKOMI_PUBLISHABLE_KEY'] ?? 'pk_test_demo',
);

/// Demo app for `rakomi_flutter`. Single screen: sign-in form + user avatar
/// after authentication. End users sign in through the normal flow — the
/// demo has no privileged bootstrap path.
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(DemoApp(config: loadDemoConfig()));
}

class DemoApp extends StatelessWidget {
  const DemoApp({super.key, required this.config});
  final DemoConfig config;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Rakomi Flutter Demo',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.indigo),
      home: RakomiProvider(
        publishableKey: config.publishableKey,
        apiBaseUrl: config.apiBaseUrl,
        redirectUri: 'rakomi://callback',
        child: Scaffold(
          appBar: AppBar(
            title: const Text('Rakomi Flutter Demo'),
            actions: const <Widget>[
              Padding(
                padding: EdgeInsets.symmetric(horizontal: 12),
                child: RakomiUserAvatar(),
              ),
            ],
          ),
          body: RakomiAuthGate(
            signedIn: (BuildContext c, User u) => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: <Widget>[
                    Text(
                      'Hello, ${u.displayName ?? u.email}!',
                      style: Theme.of(c).textTheme.headlineMedium,
                    ),
                    const SizedBox(height: 12),
                    Text('User ID: ${u.id}'),
                    Text('Email: ${u.email}${u.emailVerified ? ' ✓' : ''}'),
                    if (u.tenantId != null) Text('Tenant: ${u.tenantId}'),
                    const SizedBox(height: 24),
                    // There is no `biometric` provider prop — biometric
                    // unlock is an on-demand call, not a mount-time gate.
                    // `hydrate()`/session refresh already read the stored
                    // credential unprompted; this button is an ADDITIONAL,
                    // opt-in re-confirmation the app triggers itself.
                    OutlinedButton.icon(
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Unlock with biometric'),
                      onPressed: () async {
                        final ok = await RakomiProvider.of(
                          c,
                        ).unlockWithBiometric(reason: 'Confirm it is you');
                        if (!c.mounted) return;
                        ScaffoldMessenger.of(c).showSnackBar(
                          SnackBar(
                            content: Text(
                              ok
                                  ? 'Biometric unlock succeeded'
                                  : 'Biometric unlock failed or unavailable',
                            ),
                          ),
                        );
                      },
                    ),
                  ],
                ),
              ),
            ),
            signedOut: (BuildContext c) => const RakomiSignInForm(
              providers: <SocialProvider>[
                SocialProvider.google,
                SocialProvider.github,
                SocialProvider.apple,
              ],
            ),
            loading: (BuildContext c) =>
                const Center(child: CircularProgressIndicator()),
          ),
        ),
      ),
    );
  }
}
