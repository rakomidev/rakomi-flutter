import 'dart:async';
import 'package:meta/meta.dart';

/// Result of a biometric prompt. Sealed — switch on the variant.
@immutable
sealed class BiometricResult {
  const BiometricResult();
}

class BiometricSuccess extends BiometricResult {
  const BiometricSuccess();
}

class BiometricCancelled extends BiometricResult {
  const BiometricCancelled();
}

class BiometricLockout extends BiometricResult {
  /// Permanent vs transient lockout. `local_auth` v3 distinguishes these
  /// via [LocalAuthExceptionCode.lockedOut] (transient — N-second cooldown)
  /// vs [LocalAuthExceptionCode.permanentlyLockedOut] (requires PIN re-entry).
  const BiometricLockout({this.permanent = false});
  final bool permanent;
}

class BiometricNotEnrolled extends BiometricResult {
  const BiometricNotEnrolled();
}

class BiometricUnavailable extends BiometricResult {
  /// Why biometric is unavailable. Populated for diagnostic surface — e.g.
  /// `'no_device_passcode'` (iOS Keychain `KeychainAccessibility.first_unlock`
  /// degrades when the device has no passcode set).
  const BiometricUnavailable({this.reason});
  final String? reason;
}

/// Pluggable native adapter. Default implementation
/// (`DefaultRakomiNativeAdapter`) wires the platform plugins.
/// Bare-Flutter consumers MAY swap the adapter for testability or for
/// alternative plugins.
///
/// **Stability**: marked `@sealed` for 0.x — additive-only. Breaking changes
/// require a minor version bump (0.1.x → 0.2.0).
@sealed
abstract class RakomiNativeAdapter {
  const RakomiNativeAdapter();

  // --- Storage --- //

  /// Read [key] from durable encrypted storage. Returns `null` if absent.
  Future<String?> storageRead(String key);

  /// Write [key] = [value] to durable encrypted storage.
  Future<void> storageWrite(String key, String value);

  /// Delete [key] from durable encrypted storage.
  Future<void> storageDelete(String key);

  /// Read all keys matching the [prefix] (rakomi.v1.* namespace pattern).
  /// Used for fresh-install detection sweep + signOut purge.
  Future<Map<String, String>> storageReadByPrefix(String prefix);

  /// Read [key] from a non-encrypted store (e.g. `shared_preferences`). Used
  /// for fresh-install detection markers.
  Future<String?> markerRead(String key);

  /// Write [key] to non-encrypted marker store.
  Future<void> markerWrite(String key, String value);

  // --- System browser (RFC 8252) --- //

  /// Open the system browser at [url] and await the OAuth callback whose
  /// scheme matches [callbackScheme]. Throws on cancel — maps to
  /// `SdkErrorReason.oauthUserCancelled` at the call-site.
  Future<String> launchSystemBrowser(Uri url, {required String callbackScheme});

  // --- Deep-link callback ingest --- //

  /// Stream of incoming deep links (warm). Emitted by `app_links` once the
  /// system browser hands the URI back.
  Stream<Uri> get deepLinkStream;

  /// Cold-start initial link. Returns `null` if the app was not launched via
  /// a deep link.
  Future<Uri?> getInitialDeepLink();

  // --- Biometric --- //

  /// Whether biometric is available at all on the device. Returns `false` on
  /// `kIsWeb` and on devices with no biometric hardware.
  Future<bool> get biometricAvailable;

  /// Whether the device supports a NATIVE platform-passkey ceremony
  /// (`ASAuthorization` / Android Credential Manager). Default adapter
  /// returns `false`; a platform-passkey adapter overrides it.
  Future<bool> get supportsNativePasskey;

  /// Trigger the biometric prompt. [reason] is the localized prompt copy
  /// shown to the user.
  Future<BiometricResult> requestBiometric({required String reason});

  // --- AppLifecycle --- //

  /// Stream of foreground transitions. Emits when the app moves from
  /// background → foreground. Used by the auth controller's
  /// AppLifecycleState.resumed-driven proactive refresh logic.
  Stream<void> get appResumed;

  // --- Connectivity --- //

  /// Whether the device is online. Polled on construction; subsequent
  /// transitions emitted via [connectivityChanges].
  Future<bool> get online;

  /// Stream of online/offline transitions. `true` = online, `false` = offline.
  Stream<bool> get connectivityChanges;

  // --- HTTP --- //

  /// Long-lived `package:http` Client. ONE instance per adapter — never
  /// per-call. Adapter is responsible for closing on
  /// teardown.
  ///
  /// Optional certificate pinning: adapter MAY validate against a
  /// caller-provided `certificateFingerprints` list (mobile-only — Web
  /// ignored, browser TLS) via `HttpClient.badCertificateCallback`.
  /// Wire via `RakomiProvider(certificateFingerprints: [...])`.
  Object get httpClient;

  /// Release any held resources (HTTP client, plugin streams).
  Future<void> dispose();
}
