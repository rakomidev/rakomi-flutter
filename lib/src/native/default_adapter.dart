import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/widgets.dart'
    show AppLifecycleState, WidgetsBinding, WidgetsBindingObserver;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:http/http.dart' as http;
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'adapter.dart';
import 'pinned_http_client.dart';

/// Default adapter wiring the platform plugins:
///
/// - `flutter_secure_storage` v10 — durable token + JWKS persistence.
/// - `flutter_web_auth_2` v5 — RFC 8252 system browser.
/// - `app_links` v7 — deep-link callback ingest.
/// - `local_auth` v3 — biometric gate.
/// - `connectivity_plus` v7 — online/offline transitions.
/// - `package:http` v1.6 — HTTP client (single long-lived instance per
///   adapter; optional cert pinning via [certificateFingerprints]).
/// - `shared_preferences` v2.5 — non-encrypted lifecycle markers (paired
///   with Keychain for fresh-install detection).
class DefaultRakomiNativeAdapter extends RakomiNativeAdapter
    with WidgetsBindingObserver {
  DefaultRakomiNativeAdapter({this.certificateFingerprints})
    : _secureStorage = const FlutterSecureStorage(
        aOptions: AndroidOptions(
          keyCipherAlgorithm:
              KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
          storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
          migrateOnAlgorithmChange: true,
          resetOnError: true,
        ),
        // `first_unlock_this_device` — NOT `first_unlock` — to prevent the
        // refresh token from entering iCloud/iTunes backup and being restored
        // onto a different device. Mirrors the Swift SDK's
        // `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
        iOptions: IOSOptions(
          accessibility: KeychainAccessibility.first_unlock_this_device,
        ),
        mOptions: MacOsOptions(
          accessibility: KeychainAccessibility.first_unlock_this_device,
        ),
      ) {
    _initObservers();
  }

  /// SHA-256 fingerprints of pinned server certificates. Accepted formats:
  /// hex (with or without colons) or base64 — all normalised to canonical
  /// base64(SHA-256(cert.der)) before comparison. When non-empty, the SDK
  /// performs an out-of-band TLS handshake to the target host before each
  /// HTTPS request and aborts (`HandshakeException('cert_pin_mismatch')`)
  /// unless the peer cert's hash matches one of the pins. Mobile-only
  /// (Web platform short-circuits via the browser's TLS stack); HTTP and
  /// dev-loopback URLs (`localhost` / `127.0.0.1` / `::1`) skip the check.
  ///
  /// Multiple pins are supported — ship a backup pin alongside the current
  /// one to absorb cert rotation without forcing an SDK update.
  final List<String>? certificateFingerprints;

  final FlutterSecureStorage _secureStorage;
  final AppLinks _appLinks = AppLinks();
  final LocalAuthentication _localAuth = LocalAuthentication();
  final Connectivity _connectivity = Connectivity();

  late final http.Client _httpClient = _buildHttpClient();
  final StreamController<void> _appResumedController =
      StreamController<void>.broadcast();
  StreamSubscription<List<ConnectivityResult>>? _connSub;
  final StreamController<bool> _connController =
      StreamController<bool>.broadcast();

  void _initObservers() {
    WidgetsBinding.instance.addObserver(this);
    _connSub = _connectivity.onConnectivityChanged.listen((results) {
      final online =
          !results.contains(ConnectivityResult.none) && results.isNotEmpty;
      _connController.add(online);
    });
  }

  http.Client _buildHttpClient() {
    final pins = certificateFingerprints;
    if (pins == null || pins.isEmpty) return http.Client();
    if (kIsWeb) {
      // Web: browser TLS stack handles pinning via HSTS / Expect-CT. Pure-
      // Dart SecureSocket is not available on Web. Fall back to plain
      // client; pin enforcement is a no-op on this platform by design.
      return http.Client();
    }
    return PinnedHttpClient(pins: pins);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _appResumedController.add(null);
    }
  }

  // ─── Storage ────────────────────────────────────────────────────────── //

  @override
  Future<String?> storageRead(String key) => _secureStorage.read(key: key);

  @override
  Future<void> storageWrite(String key, String value) =>
      _secureStorage.write(key: key, value: value);

  @override
  Future<void> storageDelete(String key) => _secureStorage.delete(key: key);

  @override
  Future<Map<String, String>> storageReadByPrefix(String prefix) async {
    final all = await _secureStorage.readAll();
    return Map.fromEntries(all.entries.where((e) => e.key.startsWith(prefix)));
  }

  @override
  Future<String?> markerRead(String key) async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(key);
  }

  @override
  Future<void> markerWrite(String key, String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(key, value);
  }

  // ─── System browser ─────────────────────────────────────────────────── //

  @override
  Future<String> launchSystemBrowser(
    Uri url, {
    required String callbackScheme,
  }) {
    return FlutterWebAuth2.authenticate(
      url: url.toString(),
      callbackUrlScheme: callbackScheme,
      options: const FlutterWebAuth2Options(preferEphemeral: true),
    );
  }

  // ─── Deep links ─────────────────────────────────────────────────────── //

  @override
  Stream<Uri> get deepLinkStream => _appLinks.uriLinkStream;

  @override
  Future<Uri?> getInitialDeepLink() => _appLinks.getInitialLink();

  // ─── Biometric ──────────────────────────────────────────────────────── //

  @override
  Future<bool> get biometricAvailable async {
    if (kIsWeb) return false;
    try {
      return await _localAuth.canCheckBiometrics;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> get supportsNativePasskey async => false;

  @override
  Future<BiometricResult> requestBiometric({required String reason}) async {
    if (kIsWeb) {
      return const BiometricUnavailable(reason: 'web_unsupported');
    }
    try {
      final ok = await _localAuth.authenticate(
        localizedReason: reason,
        biometricOnly: false,
        // local_auth v3 public API: `persistAcrossBackgrounding` is the
        // RENAMED public-surface alias for the platform_interface's
        // `stickyAuth` field (the changelog WAS accurate at this layer).
        // Keeps the prompt alive across short foreground/background flips
        // during the auth gesture (matches the React Native SDK's parity).
        persistAcrossBackgrounding: true,
      );
      return ok ? const BiometricSuccess() : const BiometricCancelled();
    } on LocalAuthException catch (e) {
      // local_auth v3 introduces structured `LocalAuthExceptionCode`. Map
      // each case to a typed `BiometricResult` variant. Default fallback
      // covers any future enum addition (the platform_interface marks the
      // enum as non-exhaustive).
      switch (e.code) {
        case LocalAuthExceptionCode.userCanceled:
        case LocalAuthExceptionCode.systemCanceled:
        case LocalAuthExceptionCode.userRequestedFallback:
          return const BiometricCancelled();
        case LocalAuthExceptionCode.noBiometricsEnrolled:
          return const BiometricNotEnrolled();
        case LocalAuthExceptionCode.temporaryLockout:
          return const BiometricLockout(permanent: false);
        case LocalAuthExceptionCode.biometricLockout:
          return const BiometricLockout(permanent: true);
        case LocalAuthExceptionCode.noCredentialsSet:
          return const BiometricUnavailable(reason: 'no_device_passcode');
        case LocalAuthExceptionCode.noBiometricHardware:
          return const BiometricUnavailable(reason: 'no_biometric_hardware');
        case LocalAuthExceptionCode.biometricHardwareTemporarilyUnavailable:
          return const BiometricUnavailable(
            reason: 'hardware_temporarily_unavailable',
          );
        case LocalAuthExceptionCode.uiUnavailable:
          return const BiometricUnavailable(reason: 'ui_unavailable');
        case LocalAuthExceptionCode.timeout:
          return const BiometricCancelled();
        case LocalAuthExceptionCode.authInProgress:
        case LocalAuthExceptionCode.deviceError:
        case LocalAuthExceptionCode.unknownError:
          return BiometricUnavailable(reason: e.code.name);
      }
    } catch (_) {
      return const BiometricUnavailable();
    }
  }

  // ─── App lifecycle ──────────────────────────────────────────────────── //

  @override
  Stream<void> get appResumed => _appResumedController.stream;

  // ─── Connectivity ───────────────────────────────────────────────────── //

  @override
  Future<bool> get online async {
    final r = await _connectivity.checkConnectivity();
    return !r.contains(ConnectivityResult.none) && r.isNotEmpty;
  }

  @override
  Stream<bool> get connectivityChanges => _connController.stream;

  // ─── HTTP ───────────────────────────────────────────────────────────── //

  @override
  Object get httpClient => _httpClient;

  // ─── Teardown ───────────────────────────────────────────────────────── //

  @override
  Future<void> dispose() async {
    WidgetsBinding.instance.removeObserver(this);
    await _connSub?.cancel();
    await _connController.close();
    await _appResumedController.close();
    _httpClient.close();
  }
}
