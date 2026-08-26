import 'package:meta/meta.dart';

/// Authenticated user snapshot. Decoded from the JWT `id_token` payload OR
/// from `/v1/auth/me`. Open-ended `claims` map carries forward-compat slots
/// used for roles, metadata and `org_id`.
@immutable
class User {
  const User({
    required this.id,
    required this.email,
    this.emailVerified = false,
    this.displayName,
    this.imageUrl,
    this.locale,
    this.tenantId,
    this.claims = const <String, Object?>{},
  });

  final String id;
  final String email;
  final bool emailVerified;
  final String? displayName;
  final String? imageUrl;
  final String? locale;
  final String? tenantId;

  /// Open-ended forward-compat slot. SDK does NOT impose schema on `claims` —
  /// downstream consumers (e.g. Rakomi RBAC layer, custom roles) read whatever
  /// keys they need. `claims` is open-ended; consumers read the keys their
  /// tenant issues.
  final Map<String, Object?> claims;

  factory User.fromJson(Map<String, Object?> json) {
    return User(
      id: json['sub'] as String? ?? json['id'] as String,
      email: json['email'] as String? ?? '',
      emailVerified: json['email_verified'] as bool? ?? false,
      displayName: json['name'] as String? ?? json['displayName'] as String?,
      imageUrl: json['picture'] as String? ?? json['imageUrl'] as String?,
      locale: json['locale'] as String?,
      tenantId: json['tenant_id'] as String? ?? json['tenantId'] as String?,
      claims: Map<String, Object?>.unmodifiable(json),
    );
  }

  Map<String, Object?> toJson() => <String, Object?>{
    'sub': id,
    'email': email,
    'email_verified': emailVerified,
    if (displayName != null) 'name': displayName,
    if (imageUrl != null) 'picture': imageUrl,
    if (locale != null) 'locale': locale,
    if (tenantId != null) 'tenant_id': tenantId,
  };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is User && other.id == id && other.tenantId == tenantId);

  @override
  int get hashCode => Object.hash(id, tenantId);
}

/// Active session snapshot. Carries the access-token lifetime metadata
/// (NOT the access token itself — that's held in the controller's in-memory
/// state and never exposed via session objects).
@immutable
class Session {
  const Session({
    required this.id,
    required this.userId,
    required this.tenantId,
    required this.expiresAt,
    required this.issuedAt,
    this.notBefore,
  });

  final String id;
  final String userId;
  final String tenantId;
  final DateTime expiresAt;
  final DateTime issuedAt;
  final DateTime? notBefore;

  /// Whether the access token is past its `exp` claim.
  bool isExpired({DateTime? now}) {
    final t = now ?? DateTime.now().toUtc();
    return !t.isBefore(expiresAt);
  }

  /// Whether the access token is within `leadtime` of expiry. Used by the
  /// auth controller's AppState-driven proactive refresh path.
  bool isExpiringSoon({
    DateTime? now,
    Duration leadtime = const Duration(seconds: 60),
  }) {
    final t = now ?? DateTime.now().toUtc();
    return !t.isBefore(expiresAt.subtract(leadtime));
  }
}
