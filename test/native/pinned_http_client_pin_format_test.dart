import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/native/pinned_http_client.dart';

void main() {
  // Substrate: one deterministic DER-like blob -> the exact digest the
  // production code compares against at _verifyPin (base64, mixed case).
  final der = List<int>.generate(256, (i) => i);
  final runtime = base64.encode(sha256.convert(der).bytes);
  final hex = sha256
      .convert(der)
      .bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  test(
    'SUBSTRATE: runtime digest is mixed-case base64 (else this probe is vacuous)',
    () {
      expect(
        runtime,
        isNot(equals(runtime.toLowerCase())),
        reason: 'digest must contain uppercase, or the bug is unobservable',
      );
    },
  );

  test(
    'should-PASS: base64 pin (the DOCUMENTED canonical format) normalises to the runtime digest',
    () {
      final c = PinnedHttpClient(pins: [runtime]);
      expect(
        c.debugNormalisedPins.contains(runtime),
        isTrue,
        // The failure message carries the substrate, so a red run still
        // shows WHAT was compared without an unconditional print.
        reason: 'normalised=${c.debugNormalisedPins} runtime=$runtime',
      );
    },
  );

  test(
    'should-PASS: hex and hex:colon pins normalise to the same runtime digest',
    () {
      final colon = RegExp(r'.{2}').allMatches(hex).map((m) => m[0]!).join(':');
      expect(
        PinnedHttpClient(pins: [hex]).debugNormalisedPins.contains(runtime),
        isTrue,
      );
      expect(
        PinnedHttpClient(
          pins: [hex.toUpperCase()],
        ).debugNormalisedPins.contains(runtime),
        isTrue,
      );
      expect(
        PinnedHttpClient(pins: [colon]).debugNormalisedPins.contains(runtime),
        isTrue,
      );
    },
  );

  test(
    'should-FAIL: a WRONG base64 pin must NOT normalise to the runtime digest',
    () {
      final wrong = base64.encode(sha256.convert([...der, 1]).bytes);
      expect(
        PinnedHttpClient(pins: [wrong]).debugNormalisedPins.contains(runtime),
        isFalse,
      );
    },
  );

  test(
    'should-FAIL: the case-folded pin is REJECTED at construction (that WAS the bug)',
    () {
      // Folding the case of a base64 pin yields a different pin. It used to be
      // accepted silently and then never match, so every request to the pinned
      // host failed as `cert_pin_mismatch` — a config typo shown as a MITM.
      // It is now a configuration error raised where the pin is entered.
      expect(
        () => PinnedHttpClient(pins: [runtime.toLowerCase()]),
        throwsA(isA<ArgumentError>()),
      );
    },
  );

  test(
    'should-FAIL: a pin that is neither hex nor 32-byte base64 is rejected',
    () {
      expect(
        () => PinnedHttpClient(pins: ['not-a-pin']),
        throwsA(isA<ArgumentError>()),
      );
      // 31 bytes of base64 — right alphabet, wrong digest length.
      final short = base64.encode(List<int>.filled(31, 7));
      expect(
        () => PinnedHttpClient(pins: [short]),
        throwsA(isA<ArgumentError>()),
      );
    },
  );
}
