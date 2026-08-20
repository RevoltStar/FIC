# FIC release process

FIC has no published stable release yet. The first planned stable release is `0.1.0`.

## Version authority

An exact annotated Git tag is the only authority for an official release:

```text
vMAJOR.MINOR.PATCH
vMAJOR.MINOR.PATCH-alpha.N
vMAJOR.MINOR.PATCH-beta.N
vMAJOR.MINOR.PATCH-rc.N
```

The release gate also accepts other SemVer prerelease identifiers, but release
names should use the `alpha`, `beta`, and `rc` progression above. Build metadata
(`+...`) is intentionally forbidden. A commit hash identifies the build and is
reported separately by `--build-info`.

Ordinary CMake builds default to `0.0.0-alpha` and are marked
`build_kind=development`. Native package entry points require exactly one
explicit product version.

## Product and native package versions

The embedded product version always remains SemVer. Native package versions use
the ordering rules expected by DEB and RPM:

| Git tag | Product and `--version` | DEB/RPM `Version` |
|---|---|---|
| `v0.1.0-rc.1` | `0.1.0-rc.1` | `0.1.0~rc.1` |
| `v0.1.0` | `0.1.0` | `0.1.0` |

The tilde ensures a prerelease sorts below its stable release. Package builders
verify both binary provenance and native package metadata before reporting
success.

## Preparing a release

1. Complete the intended changes and checks.
2. Replace the `Unreleased` changelog entries with a heading exactly matching
   `## [VERSION] - YYYY-MM-DD`, then commit the release preparation.
3. Create an annotated tag on that commit, for example:

   ```bash
   git tag -a v0.1.0-rc.1 -m "FIC 0.1.0-rc.1"
   ```

4. Verify the gate without building packages:

   ```bash
   ./packaging/release/build-release.sh --verify-only
   ```

5. Build all supported package sets:

   ```bash
   ./packaging/release/build-release.sh
   ```

The build refuses a dirty tree, a non-exact or lightweight tag, a tag/version
mismatch, an abbreviated commit, or a missing changelog heading. It archives
the tagged commit into a temporary source tree and builds Debian 12, Debian 13,
Ubuntu 24.04, Ubuntu 26.04, and ALT p11 packages from that immutable snapshot.

Successful output is written to `dist/release/VERSION/`. The directory contains
25 packages and a deterministic `release-manifest.json` with product version,
native package version, tag, full commit, artifact names, and SHA-256 hashes.
Existing release output is never overwritten.

Package signing, SBOM generation and publication are deliberately not claimed
by this contract and remain separate release-engineering work.
