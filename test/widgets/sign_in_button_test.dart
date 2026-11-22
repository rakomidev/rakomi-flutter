import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

import '../helpers/fake_adapter.dart';

void main() {
  testWidgets('RakomiSignInButton renders provider label', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiProvider(
          publishableKey: 'pk_test',
          apiBaseUrl: 'http://localhost:3001',
          redirectUri: 'rakomi://callback',
          clientId: 'oauth_client_test',
          adapter: FakeRakomiNativeAdapter(),
          child: const Scaffold(
            body: RakomiSignInButton(provider: SocialProvider.google),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));
    expect(find.text('Continue with google'), findsOneWidget);
  });

  testWidgets('RakomiSignInButton accepts custom label', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiProvider(
          publishableKey: 'pk_test',
          apiBaseUrl: 'http://localhost:3001',
          redirectUri: 'rakomi://callback',
          clientId: 'oauth_client_test',
          adapter: FakeRakomiNativeAdapter(),
          child: const Scaffold(
            body: RakomiSignInButton(
              provider: SocialProvider.github,
              label: 'Sign in with GitHub',
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));
    expect(find.text('Sign in with GitHub'), findsOneWidget);
  });

  testWidgets('RakomiSignInButton has Semantics(button:true)', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiProvider(
          publishableKey: 'pk_test',
          apiBaseUrl: 'http://localhost:3001',
          redirectUri: 'rakomi://callback',
          clientId: 'oauth_client_test',
          adapter: FakeRakomiNativeAdapter(),
          child: const Scaffold(
            body: RakomiSignInButton(provider: SocialProvider.apple),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));
    expect(
      find.bySemanticsLabel('Continue with apple'),
      findsAtLeastNWidgets(1),
    );
  });

  group('fail-closed — no configured clientId', () {
    testWidgets('renders nothing when RakomiProvider has no clientId', (
      tester,
    ) async {
      await tester.pumpWidget(
        MaterialApp(
          home: RakomiProvider(
            publishableKey: 'pk_test',
            apiBaseUrl: 'http://localhost:3001',
            redirectUri: 'rakomi://callback',
            // clientId intentionally omitted.
            adapter: FakeRakomiNativeAdapter(),
            child: const Scaffold(
              body: RakomiSignInButton(provider: SocialProvider.google),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle(const Duration(seconds: 1));
      // Companion to the "renders provider label" case above: the ONLY
      // difference is the missing `clientId` — proves the gate fires on
      // that condition specifically, not on some other difference between
      // the two widget trees.
      expect(find.text('Continue with google'), findsNothing);
      expect(find.byType(RakomiSignInButton), findsOneWidget);
    });

    testWidgets('renders nothing when clientId is the empty string', (
      tester,
    ) async {
      await tester.pumpWidget(
        MaterialApp(
          home: RakomiProvider(
            publishableKey: 'pk_test',
            apiBaseUrl: 'http://localhost:3001',
            redirectUri: 'rakomi://callback',
            clientId: '',
            adapter: FakeRakomiNativeAdapter(),
            child: const Scaffold(
              body: RakomiSignInButton(provider: SocialProvider.google),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle(const Duration(seconds: 1));
      expect(find.text('Continue with google'), findsNothing);
    });
  });
}
