// The version the SDK reports in its User-Agent is the version pubspec.yaml
// publishes; a release bump that misses one of them fails here.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rakomi_flutter/src/internal/version.dart';

void main() {
  test('rakomiFlutterVersion equals the pubspec version', () {
    final pubspec = File('pubspec.yaml').readAsLinesSync();
    final line = pubspec.firstWhere((l) => l.startsWith('version:'));
    expect(rakomiFlutterVersion, line.substring('version:'.length).trim());
    expect(rakomiFlutterUserAgent, 'rakomi_flutter/$rakomiFlutterVersion');
  });

  test('no request path hardcodes a User-Agent version', () {
    final offenders = Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))
        .where(
          (f) => RegExp(r"'rakomi_flutter/\d").hasMatch(f.readAsStringSync()),
        )
        .map((f) => f.path)
        .toList();
    expect(offenders, isEmpty);
  });
}
