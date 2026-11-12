# Verify rakomi_flutter releases

A release of `rakomi_flutter` is a tag `vX.Y.Z` on this repository. The `publish.yml` workflow of this
repository uploads that version to pub.dev with a GitHub Actions OIDC token (pub.dev automated
publishing), after checking that `dart pub publish --dry-run` lists exactly the files of the tag commit
outside `.github/`, `test/`, `.pubignore` and `sbom.cdx.json`, and that the uploaded archive holds exactly
those files with the bytes of the tag commit. The tests stay in this repository;
the SBOM is attached to the GitHub Release. The GitHub Release of the tag carries:

- `rakomi_flutter-X.Y.Z.tar.gz`: `git archive` of the tag commit;
- `rakomi_flutter-X.Y.Z.cdx.json`: the CycloneDX SBOM (`sbom.cdx.json`) of the tag commit;
- `*.sigstore.json`: Sigstore bundles for both files, signed keylessly by the `publish.yml` workflow of
  this repository and recorded in the public Rekor transparency log;
- `SHA256SUMS`.

The archive also carries GitHub artifact attestations (build provenance and SBOM).

## What this proves, and what it does not

The signatures and attestations prove that the files were produced by the `publish.yml` workflow of this
repository for that tag. They say nothing about the quality of the code. A tag is created only for the
head of a merged pull request, and the publish workflow refuses a tag that is not.

## Commands

```sh
V=X.Y.Z
gh release download "v$V" --repo rakomidev/rakomi-flutter

cosign verify-blob --bundle "rakomi_flutter-$V.tar.gz.sigstore.json" \
  --certificate-identity "https://github.com/rakomidev/rakomi-flutter/.github/workflows/publish.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "rakomi_flutter-$V.tar.gz"

gh attestation verify "rakomi_flutter-$V.tar.gz" --repo rakomidev/rakomi-flutter

# The pub.dev archive holds the files of the tag (outside .github/, test/, .pubignore and the SBOM):
git clone https://github.com/rakomidev/rakomi-flutter
git -C rakomi-flutter checkout "v$V"
curl -fsSL "$(curl -fsSL "https://pub.dev/api/packages/rakomi_flutter/versions/$V" | jq -r .archive_url)" -o pub.tar.gz
mkdir pub && tar -xzf pub.tar.gz -C pub
diff -r --exclude=.git --exclude=.github --exclude=test --exclude=.pubignore --exclude=sbom.cdx.json rakomi-flutter pub
```

## Report a vulnerability

See `SECURITY.md`.
