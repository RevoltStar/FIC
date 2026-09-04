#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:?repository root is required}"
VERIFIER="$ROOT_DIR/packaging/lib/corresponding-source.py"
TEMP_DIR="$(mktemp -d /tmp/fic-source-contract-test-XXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT

fail() {
    echo "corresponding-source-test: $1" >&2
    exit 1
}

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$label was accepted"
    fi
}

write_runtime_manifest() {
    local family="$1"
    local version="$2"
    cat > "$TEMP_DIR/runtime.json" <<EOF
{"components":[{
  "source_family":"$family",
  "source_package":"qt6-base",
  "source_version":"$version"
}]}
EOF
}

write_deb_index() {
    local directory="$1"
    local descriptor="$2"
    local descriptor_hash
    descriptor_hash="$(sha256sum "$directory/$descriptor" | awk '{print $1}')"
    cat > "$directory/corresponding-source.json" <<EOF
{"schema_version":1,"sources":[{
  "family":"deb",
  "source_package":"qt6-base",
  "source_version":"1:6.8.2-1",
  "descriptor":{"file":"$descriptor","sha256":"$descriptor_hash"}
}]}
EOF
}

make_dsc() {
    local directory="$1"
    local source_name="$2"
    local source_version="$3"
    local artifact_name="$4"
    local artifact_hash="0f"
    local artifact_size=1
    if [ -f "$directory/$artifact_name" ]; then
        artifact_hash="$(sha256sum "$directory/$artifact_name" | awk '{print $1}')"
        artifact_size="$(stat -c %s "$directory/$artifact_name")"
    else
        artifact_hash="$(printf '0%.0s' {1..64})"
    fi
    cat > "$directory/qt6-base.dsc" <<EOF
Format: 3.0 (quilt)
Source: $source_name
Version: $source_version
Checksums-Sha256:
 $artifact_hash $artifact_size $artifact_name
EOF
}

DEB_DIR="$TEMP_DIR/deb"
mkdir -p "$DEB_DIR"
printf 'valid Debian source archive\n' > "$DEB_DIR/qt6-base_6.8.2.orig.tar.xz"
make_dsc "$DEB_DIR" qt6-base '1:6.8.2-1' qt6-base_6.8.2.orig.tar.xz
write_deb_index "$DEB_DIR" qt6-base.dsc
write_runtime_manifest deb '1:6.8.2-1'
python3 "$VERIFIER" --source-dir "$DEB_DIR" --manifest "$TEMP_DIR/runtime.json"

RANDOM_DIR="$TEMP_DIR/random"
mkdir -p "$RANDOM_DIR"
printf 'not a source descriptor\n' > "$RANDOM_DIR/source.txt"
write_deb_index "$RANDOM_DIR" source.txt
expect_failure "random text artifact" \
    python3 "$VERIFIER" --source-dir "$RANDOM_DIR" --manifest "$TEMP_DIR/runtime.json"

WRONG_SOURCE_DIR="$TEMP_DIR/wrong-source"
mkdir -p "$WRONG_SOURCE_DIR"
cp "$DEB_DIR/qt6-base_6.8.2.orig.tar.xz" "$WRONG_SOURCE_DIR/"
make_dsc "$WRONG_SOURCE_DIR" not-qt6-base '1:6.8.2-1' qt6-base_6.8.2.orig.tar.xz
write_deb_index "$WRONG_SOURCE_DIR" qt6-base.dsc
expect_failure "Debian descriptor with the wrong Source" \
    python3 "$VERIFIER" --source-dir "$WRONG_SOURCE_DIR" --manifest "$TEMP_DIR/runtime.json"

WRONG_VERSION_DIR="$TEMP_DIR/wrong-version"
mkdir -p "$WRONG_VERSION_DIR"
cp "$DEB_DIR/qt6-base_6.8.2.orig.tar.xz" "$WRONG_VERSION_DIR/"
make_dsc "$WRONG_VERSION_DIR" qt6-base '1:6.8.2-2' qt6-base_6.8.2.orig.tar.xz
write_deb_index "$WRONG_VERSION_DIR" qt6-base.dsc
expect_failure "Debian descriptor with the wrong Version" \
    python3 "$VERIFIER" --source-dir "$WRONG_VERSION_DIR" --manifest "$TEMP_DIR/runtime.json"

MISSING_DIR="$TEMP_DIR/missing"
mkdir -p "$MISSING_DIR"
make_dsc "$MISSING_DIR" qt6-base '1:6.8.2-1' missing.tar.xz
write_deb_index "$MISSING_DIR" qt6-base.dsc
expect_failure "missing file from Checksums-Sha256" \
    python3 "$VERIFIER" --source-dir "$MISSING_DIR" --manifest "$TEMP_DIR/runtime.json"

TAMPERED_DIR="$TEMP_DIR/tampered"
cp -a "$DEB_DIR" "$TAMPERED_DIR"
printf 'tampered\n' >> "$TAMPERED_DIR/qt6-base_6.8.2.orig.tar.xz"
expect_failure "modified Debian source archive" \
    python3 "$VERIFIER" --source-dir "$TAMPERED_DIR" --manifest "$TEMP_DIR/runtime.json"

if command -v rpm >/dev/null 2>&1 && command -v rpmbuild >/dev/null 2>&1; then
    make_rpm_fixture() {
        local version="$1"
        local release="$2"
        local topdir="$TEMP_DIR/rpmbuild-$version-$release"
        mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
        mkdir -p "$topdir/source/qt6-base-$version"
        printf 'source fixture\n' > "$topdir/source/qt6-base-$version/README"
        tar -C "$topdir/source" -czf "$topdir/SOURCES/qt6-base-$version.tar.gz" \
            "qt6-base-$version"
        cat > "$topdir/SPECS/qt6-base.spec" <<EOF
Name: qt6-base
Version: $version
Release: $release
Summary: Qt source verification fixture
License: LGPL-3.0-only
Group: Development/KDE and QT
BuildArch: noarch
Source0: qt6-base-$version.tar.gz

%description
Qt source verification fixture.

%prep
%setup -q

%build
:

%install
mkdir -p %buildroot/usr/share/qt-source-fixture
install -m 0644 README %buildroot/usr/share/qt-source-fixture/README

%files
/usr/share/qt-source-fixture/README
EOF
        rpmbuild --define "_topdir $topdir" -bs "$topdir/SPECS/qt6-base.spec" \
            >/dev/null 2>&1 || return 1
        rpmbuild --define "_topdir $topdir" -bb "$topdir/SPECS/qt6-base.spec" \
            >/dev/null 2>&1 || return 1
        printf '%s\n' "$topdir"
    }

    write_rpm_index() {
        local directory="$1"
        local rpm_file="$2"
        local expected_version="$3"
        local rpm_hash
        rpm_hash="$(sha256sum "$directory/$rpm_file" | awk '{print $1}')"
        cat > "$directory/corresponding-source.json" <<EOF
{"schema_version":1,"sources":[{
  "family":"rpm",
  "source_package":"qt6-base",
  "source_version":"$expected_version",
  "source_rpm":{"file":"$rpm_file","sha256":"$rpm_hash"}
}]}
EOF
    }

    RPM_TOPDIR="$(make_rpm_fixture 6.10.3 alt5)"
    RPM_DIR="$TEMP_DIR/rpm"
    mkdir -p "$RPM_DIR"
    cp "$RPM_TOPDIR/SRPMS/qt6-base-6.10.3-alt5.src.rpm" "$RPM_DIR/"
    write_rpm_index "$RPM_DIR" qt6-base-6.10.3-alt5.src.rpm 6.10.3-alt5
    write_runtime_manifest rpm 6.10.3-alt5
    python3 "$VERIFIER" --source-dir "$RPM_DIR" --manifest "$TEMP_DIR/runtime.json"

    FAKE_RPM_DIR="$TEMP_DIR/fake-rpm"
    mkdir -p "$FAKE_RPM_DIR"
    printf 'not an RPM\n' > "$FAKE_RPM_DIR/qt6-base.src.rpm"
    write_rpm_index "$FAKE_RPM_DIR" qt6-base.src.rpm 6.10.3-alt5
    expect_failure "fake source RPM" \
        python3 "$VERIFIER" --source-dir "$FAKE_RPM_DIR" --manifest "$TEMP_DIR/runtime.json"

    BINARY_RPM_DIR="$TEMP_DIR/binary-rpm"
    mkdir -p "$BINARY_RPM_DIR"
    binary_rpm="$(find "$RPM_TOPDIR/RPMS" -type f -name '*.rpm' | head -n 1)"
    cp "$binary_rpm" "$BINARY_RPM_DIR/qt6-base-binary.rpm"
    write_rpm_index "$BINARY_RPM_DIR" qt6-base-binary.rpm 6.10.3-alt5
    expect_failure "binary RPM" \
        python3 "$VERIFIER" --source-dir "$BINARY_RPM_DIR" --manifest "$TEMP_DIR/runtime.json"

    WRONG_RPM_TOPDIR="$(make_rpm_fixture 6.10.4 alt1)"
    WRONG_RPM_DIR="$TEMP_DIR/wrong-rpm"
    mkdir -p "$WRONG_RPM_DIR"
    cp "$WRONG_RPM_TOPDIR/SRPMS/qt6-base-6.10.4-alt1.src.rpm" "$WRONG_RPM_DIR/"
    write_rpm_index "$WRONG_RPM_DIR" qt6-base-6.10.4-alt1.src.rpm 6.10.3-alt5
    expect_failure "source RPM with the wrong version/release" \
        python3 "$VERIFIER" --source-dir "$WRONG_RPM_DIR" --manifest "$TEMP_DIR/runtime.json"
else
    echo "SKIP: rpm/rpmbuild are unavailable; RPM semantic fixtures were not run" >&2
fi
