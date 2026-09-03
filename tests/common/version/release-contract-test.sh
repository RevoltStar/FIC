#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$ROOT_DIR/packaging/lib/version-contract.sh"
source "$ROOT_DIR/packaging/lib/release-contract.sh"

fail() {
    echo "release-contract-test: $1" >&2
    exit 1
}

TEMP_DIR="$(mktemp -d /tmp/fic-release-contract-test-XXXXXX)"
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

git -C "$TEMP_DIR" init -q
git -C "$TEMP_DIR" config user.name "FIC Release Test"
git -C "$TEMP_DIR" config user.email "release-test.invalid@example.invalid"
mkdir -p "$TEMP_DIR/packaging/lib" "$TEMP_DIR/packaging/release" \
    "$TEMP_DIR/packaging/deb" "$TEMP_DIR/packaging/rpm"
cp "$ROOT_DIR/packaging/lib/version-contract.sh" "$TEMP_DIR/packaging/lib/"
cp "$ROOT_DIR/packaging/lib/release-contract.sh" "$TEMP_DIR/packaging/lib/"
cp "$ROOT_DIR/packaging/lib/corresponding-source.py" "$TEMP_DIR/packaging/lib/"
cp "$ROOT_DIR/packaging/release/build-release.sh" "$TEMP_DIR/packaging/release/"
chmod +x "$TEMP_DIR/packaging/release/build-release.sh"
for mock_builder in \
    packaging/deb/build-fic-debian12-deb-docker.sh \
    packaging/deb/build-fic-debian13-deb-docker.sh \
    packaging/deb/build-fic-ubuntu2404-deb-docker.sh \
    packaging/deb/build-fic-ubuntu2604-deb-docker.sh \
    packaging/rpm/build-fic-alt-p11-rpm-docker.sh; do
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'MOCK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"' \
        'mkdir -p "$MOCK_ROOT/dist"' \
        'builder="$(basename "$0" .sh)"' \
        'case "$builder" in *rpm*) extension=rpm ;; *) extension=deb ;; esac' \
        'for component in fic fic-cli fic-dick fic-gui fic-session-agent; do' \
        '    touch "$MOCK_ROOT/dist/${component}_${builder}.${extension}"' \
        'done' \
        'cat > "$MOCK_ROOT/dist/fic-gui_${builder}.${extension}.third-party-components.json" <<EOF' \
        '{"components":[{"source_package":"qt6-base","source_version":"6.test"}]}' \
        'EOF' > "$TEMP_DIR/$mock_builder"
    chmod +x "$TEMP_DIR/$mock_builder"
done
printf '# Changelog\n\n## [0.1.0-rc.1] - 2026-08-02\n' > "$TEMP_DIR/CHANGELOG.md"
printf 'release fixture\n' > "$TEMP_DIR/README.md"
mkdir -p "$TEMP_DIR/release-sources"
printf 'qt source fixture\n' > "$TEMP_DIR/release-sources/qt6-base-6.test.tar.xz"
source_hash="$(sha256sum "$TEMP_DIR/release-sources/qt6-base-6.test.tar.xz" | cut -d ' ' -f 1)"
cat > "$TEMP_DIR/release-sources/corresponding-source.json" <<EOF
{
  "schema_version": 1,
  "sources": [{
    "source_package": "qt6-base",
    "source_version": "6.test",
    "artifacts": [{"file": "qt6-base-6.test.tar.xz", "sha256": "$source_hash"}]
  }]
}
EOF
git -C "$TEMP_DIR" add CHANGELOG.md README.md packaging
git -C "$TEMP_DIR" add release-sources
git -C "$TEMP_DIR" commit -qm "release fixture"
git -C "$TEMP_DIR" tag -a v0.1.0-rc.1 -m "release fixture"

fic_validate_release_checkout "$TEMP_DIR"
[ "$FIC_RELEASE_TAG" = "v0.1.0-rc.1" ] || fail "wrong release tag"
[ "$FIC_PRODUCT_VERSION" = "0.1.0-rc.1" ] || fail "wrong product version"
[ "$FIC_PACKAGE_VERSION" = "0.1.0~rc.1" ] || fail "wrong native package version"
[ "${#FIC_RELEASE_COMMIT}" -eq 40 ] || fail "release commit is abbreviated"
"$TEMP_DIR/packaging/release/build-release.sh" --verify-only >/dev/null
if "$TEMP_DIR/packaging/release/build-release.sh" >/dev/null 2>&1; then
    fail "release build accepted missing FIC_CORRESPONDING_SOURCE_DIR"
fi
FIC_CORRESPONDING_SOURCE_DIR="$TEMP_DIR/release-sources" \
    "$TEMP_DIR/packaging/release/build-release.sh" >/dev/null
RELEASE_OUTPUT="$TEMP_DIR/dist/release/0.1.0-rc.1"
[ -f "$RELEASE_OUTPUT/release-manifest.json" ] || fail "release manifest is missing"
[ "$(find "$RELEASE_OUTPUT" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | wc -l)" -eq 25 ] ||
    fail "release entry point did not collect 25 packages"
grep -Fq "\"commit\": \"$FIC_RELEASE_COMMIT\"" \
    "$RELEASE_OUTPUT/release-manifest.json" || fail "manifest commit is wrong"
[ -f "$RELEASE_OUTPUT/corresponding-source/corresponding-source.json" ] ||
    fail "corresponding source index is missing from release output"
rm -rf "$TEMP_DIR/dist"

printf 'dirty\n' >> "$TEMP_DIR/README.md"
if (fic_validate_release_checkout "$TEMP_DIR" >/dev/null 2>&1); then
    fail "accepted a dirty release tree"
fi
git -C "$TEMP_DIR" restore README.md

git -C "$TEMP_DIR" tag -d v0.1.0-rc.1 >/dev/null
git -C "$TEMP_DIR" tag v0.1.0-rc.1
if (fic_validate_release_checkout "$TEMP_DIR" >/dev/null 2>&1); then
    fail "accepted a lightweight release tag"
fi

git -C "$TEMP_DIR" tag -d v0.1.0-rc.1 >/dev/null
printf 'next release\n' >> "$TEMP_DIR/README.md"
git -C "$TEMP_DIR" add README.md
git -C "$TEMP_DIR" commit -qm "next release fixture"
git -C "$TEMP_DIR" tag -a v0.1.0 -m "release without changelog"
if (fic_validate_release_checkout "$TEMP_DIR" >/dev/null 2>&1); then
    fail "accepted a release without a matching changelog heading"
fi
