import 'dart:async';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_test;
import 'package:rakomi_flutter/rakomi_flutter.dart';

/// In-memory fake `RakomiNativeAdapter` for tests.
class FakeRakomiNativeAdapter extends RakomiNativeAdapter {
  FakeRakomiNativeAdapter({
    this.biometricResult = const BiometricSuccess(),
    this.systemBrowserResult,
    this.connectivityInitial = true,
  });

  BiometricResult biometricResult;
  String? systemBrowserResult;
  bool connectivityInitial;

  final Map<String, String> _secure = <String, String>{};
  final Map<String, String> _marker = <String, String>{};
  final StreamController<Uri> _deepLink = StreamController<Uri>.broadcast();
  final StreamController<void> _resumed = StreamController<void>.broadcast();
  final StreamController<bool> _connectivity =
      StreamController<bool>.broadcast();

  http_test.MockClient mockClient = http_test.MockClient((
    http.Request r,
  ) async {
    return http.Response(
      '{}',
      200,
      headers: <String, String>{'content-type': 'application/json'},
    );
  });

  @override
  Future<String?> storageRead(String key) async => _secure[key];

  @override
  Future<void> storageWrite(String key, String value) async {
    _secure[key] = value;
  }

  @override
  Future<void> storageDelete(String key) async {
    _secure.remove(key);
  }

  @override
  Future<Map<String, String>> storageReadByPrefix(String prefix) async {
    return Map.fromEntries(
      _secure.entries.where((e) => e.key.startsWith(prefix)),
    );
  }

  @override
  Future<String?> markerRead(String key) async => _marker[key];

  @override
  Future<void> markerWrite(String key, String value) async {
    _marker[key] = value;
  }

  @override
  Future<String> launchSystemBrowser(
    Uri url, {
    required String callbackScheme,
  }) async {
    final r = systemBrowserResult;
    if (r == null) throw Exception('CANCELED');
    return r;
  }

  @override
  Stream<Uri> get deepLinkStream => _deepLink.stream;

  @override
  Future<Uri?> getInitialDeepLink() async => null;

  @override
  Future<bool> get biometricAvailable async => true;

  @override
  Future<bool> get supportsNativePasskey async => false;

  /// How many times a biometric prompt was requested.
  int biometricRequestCount = 0;

  @override
  Future<BiometricResult> requestBiometric({required String reason}) async {
    biometricRequestCount++;
    return biometricResult;
  }

  @override
  Stream<void> get appResumed => _resumed.stream;

  void simulateAppResume() => _resumed.add(null);
  void simulateDeepLink(Uri u) => _deepLink.add(u);
  void simulateConnectivity(bool online) => _connectivity.add(online);

  @override
  Future<bool> get online async => connectivityInitial;

  @override
  Stream<bool> get connectivityChanges => _connectivity.stream;

  @override
  Object get httpClient => mockClient;

  @override
  Future<void> dispose() async {
    await _deepLink.close();
    await _resumed.close();
    await _connectivity.close();
  }
}
