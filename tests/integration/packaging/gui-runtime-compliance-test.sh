#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:?repository root is required}"
TEMP_DIR="$(mktemp -d /tmp/fic-gui-compliance-test-XXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT

export ROOT_DIR
export STAGING_BASE="$TEMP_DIR"
export GUI_QT_BUNDLE_ROOT=/opt/fic/qt
export FIC_GUI_BUILD_DIR="$TEMP_DIR/build"
source "$ROOT_DIR/packaging/lib/gui-runtime-compliance.sh"

PACKAGE_ROOT="$TEMP_DIR/package"
mkdir -p "$PACKAGE_ROOT/opt/fic/bin"
cat > "$PACKAGE_ROOT/opt/fic/bin/fic-gui.real" <<'EOF'
#!/bin/sh
printf '%s\n%s\n%s\n' \
    "$LD_LIBRARY_PATH" "$QT_PLUGIN_PATH" "$QT_QPA_PLATFORM_PLUGIN_PATH"
EOF
chmod 0755 "$PACKAGE_ROOT/opt/fic/bin/fic-gui.real"
fic_gui_create_launcher "$PACKAGE_ROOT"

default_output="$(LD_LIBRARY_PATH=/system/lib "$PACKAGE_ROOT/opt/fic/bin/fic-gui")"
expected_default="$PACKAGE_ROOT/opt/fic/qt/lib:/system/lib
$PACKAGE_ROOT/opt/fic/qt/plugins
$PACKAGE_ROOT/opt/fic/qt/plugins/platforms"
[ "$default_output" = "$expected_default" ] || {
    echo "Default launcher paths are incorrect" >&2
    exit 1
}

override_output="$(FIC_QT_ROOT=/custom/qt LD_LIBRARY_PATH=/system/lib \
    "$PACKAGE_ROOT/opt/fic/bin/fic-gui")"
expected_override="/custom/qt/lib:/system/lib
/custom/qt/plugins
/custom/qt/plugins/platforms"
[ "$override_output" = "$expected_override" ] || {
    echo "FIC_QT_ROOT launcher paths are incorrect" >&2
    exit 1
}

if FIC_QT_ROOT= "$PACKAGE_ROOT/opt/fic/bin/fic-gui" >/dev/null 2>&1; then
    echo "Empty FIC_QT_ROOT must be rejected" >&2
    exit 1
fi

[ "$(fic_gui_classify_runtime_dependency deb /tmp/libQt6Core.so.6)" = bundle ]

for packaging_script in \
    "$ROOT_DIR/packaging/deb/build-fic-debian12-deb.sh" \
    "$ROOT_DIR/packaging/rpm/build-fic-alt-p11-rpm.sh"; do
    if grep -Fq -- "-name 'libQt6*.so*'" "$packaging_script"; then
        echo "Broad Qt glob remains in $packaging_script" >&2
        exit 1
    fi
    if grep -Fq 'License: Proprietary' "$packaging_script"; then
        echo "Misleading RPM license metadata remains in $packaging_script" >&2
        exit 1
    fi
done
grep -Fq 'package_license="SUL-1.0 AND LGPL-3.0-only"' \
    "$ROOT_DIR/packaging/rpm/build-fic-alt-p11-rpm.sh" || {
    echo "fic-gui RPM license expression is missing" >&2
    exit 1
}

DOC_ROOT="$PACKAGE_ROOT/usr/share/doc/fic-gui"
mkdir -p "$PACKAGE_ROOT/opt/fic/qt/lib" "$DOC_ROOT/licenses/packages"
printf 'library\n' > "$PACKAGE_ROOT/opt/fic/qt/lib/libQt6Core.so.6"
for license_file in FIC-SUL-1.0.txt LGPL-3.0-only.txt GPL-3.0-only.txt; do
    printf 'license\n' > "$DOC_ROOT/licenses/$license_file"
done
printf 'notice\n' > "$DOC_ROOT/licenses/packages/qt.txt"
printf 'source offer\n' > "$DOC_ROOT/SOURCE_OFFER.md"
cat > "$DOC_ROOT/third-party-components.json" <<EOF
{
  "components": [{
    "name": "libQt6Core.so.6",
    "installed_path": "/opt/fic/qt/lib/libQt6Core.so.6",
    "source_path": "/usr/lib/libQt6Core.so.6",
    "package": "qt6-base",
    "version": "6.test",
    "license": "LGPL-3.0-only",
    "source_package": "qt6-base",
    "source_version": "6.test",
    "kind": "library",
    "sha256": "$(sha256sum "$PACKAGE_ROOT/opt/fic/qt/lib/libQt6Core.so.6" | awk '{print $1}')",
    "license_file": "/usr/share/doc/fic-gui/licenses/packages/qt.txt"
  }]
}
EOF
python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" verify \
    --package-root "$PACKAGE_ROOT"

rm "$DOC_ROOT/licenses/LGPL-3.0-only.txt"
if python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" verify \
    --package-root "$PACKAGE_ROOT" >/dev/null 2>&1; then
    echo "Compliance verification accepted a missing LGPL text" >&2
    exit 1
fi
printf 'license\n' > "$DOC_ROOT/licenses/LGPL-3.0-only.txt"

printf 'modified library\n' > "$PACKAGE_ROOT/opt/fic/qt/lib/libQt6Core.so.6"
if python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" verify \
    --package-root "$PACKAGE_ROOT" >/dev/null 2>&1; then
    echo "Manifest verification accepted a component SHA-256 mismatch" >&2
    exit 1
fi
printf 'library\n' > "$PACKAGE_ROOT/opt/fic/qt/lib/libQt6Core.so.6"

printf 'unlisted\n' > "$PACKAGE_ROOT/opt/fic/qt/lib/libQt6Unexpected.so.6"
if python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" verify \
    --package-root "$PACKAGE_ROOT" >/dev/null 2>&1; then
    echo "Manifest verification accepted an unlisted runtime library" >&2
    exit 1
fi
