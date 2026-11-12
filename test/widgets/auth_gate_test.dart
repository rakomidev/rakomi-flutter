import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/rakomi_flutter.dart';

void main() {
  testWidgets('RakomiAuthGate without RakomiProvider renders loading slot', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiAuthGate(
          signedIn: (c, u) => const Text('SIGNED_IN'),
          signedOut: (c) => const Text('SIGNED_OUT'),
          loading: (c) => const Text('LOADING_SLOT'),
        ),
      ),
    );
    expect(find.text('LOADING_SLOT'), findsOneWidget);
  });

  testWidgets('RakomiAuthGate without loading prop renders SizedBox.shrink', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: RakomiAuthGate(
          signedIn: (c, u) => const Text('SIGNED_IN'),
          signedOut: (c) => const Text('SIGNED_OUT'),
        ),
      ),
    );
    expect(find.text('SIGNED_IN'), findsNothing);
    expect(find.text('SIGNED_OUT'), findsNothing);
  });
}
