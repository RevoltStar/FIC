#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:?repository root is required}"
RPM_DIR="${2:?RPM artifact directory is required}"
[ "${FIC_DISPOSABLE_ALT_RUNTIME_TEST:-}" = "1" ] || {
    echo "ALT runtime installation test must run in a disposable container" >&2
    exit 2
}

qt_packages() {
    rpm -qa --queryformat '%{NAME}\t%{SOURCERPM}\n' |
        awk -F '\t' 'tolower($1) ~ /^(lib)?qt[0-9]/ || tolower($2) ~ /^qt[0-9].*\.src\.rpm$/ {print}'
}

assert_no_system_qt() {
    local stage="$1"
    local installed
    installed="$(qt_packages)"
    if [ -n "$installed" ]; then
        echo "System Qt packages are installed $stage:" >&2
        printf '%s\n' "$installed" >&2
        exit 1
    fi
}

find_one_rpm() {
    local pattern="$1"
    local result
    result="$(find "$RPM_DIR" -maxdepth 1 -type f -name "$pattern" | head -n 1)"
    [ -n "$result" ] || {
        echo "Missing RPM artifact matching $pattern" >&2
        exit 1
    }
    printf '%s\n' "$result"
}

assert_no_system_qt "before FIC installation"

fic_dick_rpm="$(find_one_rpm 'fic-dick-*.rpm')"
fic_rpm="$(find_one_rpm 'fic-[0-9]*.rpm')"
fic_gui_rpm="$(find_one_rpm 'fic-gui-*.rpm')"

echo "fic-gui Requires:"
rpm -qp --requires "$fic_gui_rpm" | sort
echo "fic-gui Provides:"
rpm -qp --provides "$fic_gui_rpm" | sort
if rpm -qp --requires "$fic_gui_rpm" | grep -q '^libQt6'; then
    echo "fic-gui exposes external Qt requirements" >&2
    exit 1
fi

mkdir -p /var/cache/apt/archives/partial
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
    -u http_proxy -u https_proxy -u all_proxy \
    apt-get install -y "$fic_dick_rpm" "$fic_rpm" "$fic_gui_rpm"
rpm -q fic-dick fic fic-gui
assert_no_system_qt "after FIC installation"

python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" verify --package-root /
bash "$ROOT_DIR/tests/integration/packaging/fic-gui-license-info-test.sh" \
    /opt/fic/bin/fic-gui

run_smoke() {
    local expected_root="$1"
    shift
    local output
    if ! output="$(LD_DEBUG=libs QT_DEBUG_PLUGINS=1 "$@" 2>&1)"; then
        printf '%s\n' "$output" >&2
        return 1
    fi
    grep -Fq 'qpa-platform=xcb' <<<"$output"
    grep -Fq 'jpeg-plugin=ok' <<<"$output"
    local component
    for component in Core Gui Widgets; do
        grep -Fq "calling init: $expected_root/lib/libQt6${component}.so" \
            <<<"$output"
    done
    grep -Fq "$expected_root/plugins/platforms/libqxcb.so" <<<"$output"
    grep -Fq "$expected_root/plugins/imageformats/libqjpeg.so" <<<"$output"
    if grep -E 'calling init: .*libQt6[^/]*\.so' <<<"$output" |
        grep -Fv "calling init: $expected_root/lib/" >/dev/null; then
        echo "Qt library was loaded outside $expected_root" >&2
        exit 1
    fi
    grep -E '^(qpa-platform|jpeg-plugin|qt-core-path)=' <<<"$output"
}

run_smoke /opt/fic/qt xvfb-run -a /opt/fic/bin/fic-gui --gui-smoke-test

custom_root="$(mktemp -d /tmp/fic-custom-qt-XXXXXX)"
cp -a /opt/fic/qt/. "$custom_root/"
run_smoke "$custom_root" env FIC_QT_ROOT="$custom_root" \
    xvfb-run -a /opt/fic/bin/fic-gui --gui-smoke-test

assert_no_system_qt "after GUI smoke tests"
