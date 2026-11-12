import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

import '../helpers/fake_adapter.dart';

void main() {
  testWidgets(
    'input_flags — password TextField has obscureText + hardening flags',
    (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: RakomiProvider(
            publishableKey: 'pk_test',
            apiBaseUrl: 'http://localhost:3001',
            redirectUri: 'rakomi://callback',
            adapter: FakeRakomiNativeAdapter(),
            child: const Scaffold(body: RakomiSignInForm()),
          ),
        ),
      );
      await tester.pumpAndSettle(const Duration(seconds: 1));
      final fields = tester
          .widgetList<TextField>(find.byType(TextField))
          .toList();
      // Find the obscured (password) field.
      final pwd = fields.firstWhere((f) => f.obscureText);
      expect(pwd.enableInteractiveSelection, isFalse);
      expect(pwd.autocorrect, isFalse);
      expect(pwd.enableSuggestions, isFalse);
      expect(pwd.obscureText, isTrue);
    },
  );

  testWidgets('email field has correct keyboardType + autofill', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiProvider(
          publishableKey: 'pk_test',
          apiBaseUrl: 'http://localhost:3001',
          redirectUri: 'rakomi://callback',
          adapter: FakeRakomiNativeAdapter(),
          child: const Scaffold(body: RakomiSignInForm()),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));
    final fields = tester
        .widgetList<TextField>(find.byType(TextField))
        .toList();
    final email = fields.firstWhere((f) => !f.obscureText);
    expect(email.keyboardType, equals(TextInputType.emailAddress));
    expect(email.autofillHints, contains(AutofillHints.email));
  });

  testWidgets('Submit button visible by default', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiProvider(
          publishableKey: 'pk_test',
          apiBaseUrl: 'http://localhost:3001',
          redirectUri: 'rakomi://callback',
          adapter: FakeRakomiNativeAdapter(),
          child: const Scaffold(body: RakomiSignInForm()),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));
    expect(find.text('Sign in'), findsAtLeastNWidgets(1));
  });
}
