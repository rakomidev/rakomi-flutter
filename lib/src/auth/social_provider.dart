/// Supported social identity providers.
///
/// Mirrors `@rakomi/react-native`'s `LinkProvider` literal-union. Server-side
/// provider configuration drives which of these are available for a given
/// tenant.
///
/// **Extensibility (additive-only in 0.x)**: future EUDI Wallet and other
/// regulated providers (post-2026 mandate) plug in as new enum values.
/// Consumer-side `switch` statements MUST be non-exhaustive (use `default:`)
/// to allow additive extension without breakage.
library;

enum SocialProvider {
  google,
  github,
  microsoft,
  apple,
  discord,
  facebook,
  slack,
  twitter,
  gitlab,
  linkedin,
  // Reserved slot for the EUDI Wallet bridge (Reg. 2024/1183 implementing
  // acts, mandate end-of-2026). Not yet wired — placeholder ensures the
  // extensibility hook exists in 0.x without a major bump when it lands.
  eudiWallet,
}

extension SocialProviderWire on SocialProvider {
  /// Wire-level identifier — sent to `/v1/auth/oauth/{provider}/start`.
  String get wire {
    switch (this) {
      case SocialProvider.google:
        return 'google';
      case SocialProvider.github:
        return 'github';
      case SocialProvider.microsoft:
        return 'microsoft';
      case SocialProvider.apple:
        return 'apple';
      case SocialProvider.discord:
        return 'discord';
      case SocialProvider.facebook:
        return 'facebook';
      case SocialProvider.slack:
        return 'slack';
      case SocialProvider.twitter:
        return 'twitter';
      case SocialProvider.gitlab:
        return 'gitlab';
      case SocialProvider.linkedin:
        return 'linkedin';
      case SocialProvider.eudiWallet:
        return 'eudi_wallet';
    }
  }
}
