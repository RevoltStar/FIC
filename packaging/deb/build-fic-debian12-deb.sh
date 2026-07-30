#!/usr/bin/env bash
set -euo pipefail

PACKAGE_VERSION="${1:-0.1.0}"
FIC_PACKAGING_TARGET_PLATFORM="${FIC_PACKAGING_TARGET_PLATFORM:-debian-12}"
case "$FIC_PACKAGING_TARGET_PLATFORM" in
    debian-12)
        DEFAULT_PACKAGE_DISTRO_TAG="debian12"
        ;;
    debian-13)
        DEFAULT_PACKAGE_DISTRO_TAG="debian13"
        ;;
    ubuntu-24.04)
        DEFAULT_PACKAGE_DISTRO_TAG="ubuntu2404"
        ;;
    *)
        echo "Unsupported Debian-family packaging platform: $FIC_PACKAGING_TARGET_PLATFORM" >&2
        exit 1
        ;;
esac
PACKAGE_DISTRO_TAG="${PACKAGE_DISTRO_TAG:-$DEFAULT_PACKAGE_DISTRO_TAG}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
STAGING_BASE="${STAGING_BASE:-$(mktemp -d /tmp/fic-deb-XXXXXX)}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build-linux}"
ARCH="$(dpkg --print-architecture)"
DEB_COMPRESSOR="${DEB_COMPRESSOR:-gzip}"
GUI_QT_BUNDLE_ROOT="/opt/fic/qt"

source "$ROOT_DIR/packaging/lib/build-resources.sh"
fic_configure_build_resources
fic_apply_build_priority

FIC_SRC_DIR="$ROOT_DIR/fic"
FIC_SESSION_AGENT_SRC_DIR="$ROOT_DIR/fic-session-agent"
FIC_DICK_SRC_DIR="$ROOT_DIR/fic-dick"
FIC_CLI_SRC_DIR="$ROOT_DIR/fic-cli"
FIC_GUI_SRC_DIR="$ROOT_DIR/fic-gui"

FIC_BUILD_DIR="$BUILD_ROOT/fic"
FIC_SESSION_AGENT_BUILD_DIR="$BUILD_ROOT/fic-session-agent"
FIC_DICK_BUILD_DIR="$BUILD_ROOT/fic-dick"
FIC_CLI_BUILD_DIR="$BUILD_ROOT/fic-cli"
FIC_GUI_BUILD_DIR="$BUILD_ROOT/fic-gui"

cleanup() {
    rm -rf "$STAGING_BASE"
}

trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

copy_shared_library_with_metadata() {
    local source_path="$1"
    local destination_dir="$2"
    local real_source
    local source_dir
    local source_base
    local real_base
    local library_prefix
    local soname
    local candidate
    local candidate_name

    [ -e "$source_path" ] || return 0

    mkdir -p "$destination_dir"

    real_source="$(readlink -f "$source_path")"
    source_dir="$(dirname "$source_path")"
    source_base="$(basename "$source_path")"
    real_base="$(basename "$real_source")"
    library_prefix="${real_base%%.so*}.so"

    install -m 0644 "$real_source" "$destination_dir/$real_base"

    if [ "$source_base" != "$real_base" ] && [ ! -e "$destination_dir/$source_base" ]; then
        ln -s "$real_base" "$destination_dir/$source_base"
    fi

    soname="$(objdump -p "$real_source" 2>/dev/null | awk '/SONAME/ { print $2; exit }')"
    if [ -n "$soname" ] && [ "$soname" != "$real_base" ] && [ ! -e "$destination_dir/$soname" ]; then
        ln -s "$real_base" "$destination_dir/$soname"
    fi

    for candidate in "$source_dir"/"$library_prefix"*; do
        [ -e "$candidate" ] || continue
        [ "$(readlink -f "$candidate")" = "$real_source" ] || continue

        candidate_name="$(basename "$candidate")"
        if [ "$candidate_name" = "$real_base" ]; then
            continue
        fi

        if [ -L "$candidate" ] && [ ! -e "$destination_dir/$candidate_name" ]; then
            ln -s "$real_base" "$destination_dir/$candidate_name"
        fi
    done
}

append_unique_line() {
    local file_path="$1"
    local value="$2"

    if [ -z "$value" ]; then
        return 0
    fi

    touch "$file_path"
    if ! grep -Fxq "$value" "$file_path"; then
        printf '%s\n' "$value" >> "$file_path"
    fi
}

build_deb_package() {
    local package_root="$1"
    local output_deb="$2"

    dpkg-deb \
        -Z"$DEB_COMPRESSOR" \
        --root-owner-group \
        --build "$package_root" "$output_deb" >&2
}

write_conffiles() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/conffiles" <<'EOF'
/opt/fic/config/DAC.conf
/opt/fic/config/DC.conf
/opt/fic/config/GLOBAL.conf
/opt/fic/config/NET.conf
/opt/fic/config/OSS.conf
/opt/fic/config/SYSCTL.conf
EOF
}

write_platform_trust_triggers() {
    local package_root="$1"
    local fic_binary="$2"
    local candidate_path

    : > "$package_root/DEBIAN/triggers"
    while IFS= read -r candidate_path; do
        [ -n "$candidate_path" ] || continue
        append_unique_line \
            "$package_root/DEBIAN/triggers" \
            "interest-noawait $candidate_path"
    done < <("$fic_binary" --trust-list-platform-paths)

    if [ ! -s "$package_root/DEBIAN/triggers" ]; then
        echo "Compiled platform profile has no trust-sync paths" >&2
        exit 1
    fi
}

copy_tree_contents() {
    local source_dir="$1"
    local target_dir="$2"

    mkdir -p "$target_dir"
    if [ -d "$source_dir" ]; then
        cp -a "$source_dir"/. "$target_dir"/
    fi
}

find_qt_plugin_dir() {
    if command -v qtpaths6 >/dev/null 2>&1; then
        qtpaths6 --query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    if command -v qtpaths >/dev/null 2>&1; then
        qtpaths --query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    if command -v qmake6 >/dev/null 2>&1; then
        qmake6 -query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    if command -v qmake >/dev/null 2>&1; then
        qmake -query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    return 1
}

find_qt_lib_dir() {
    if command -v qtpaths6 >/dev/null 2>&1; then
        qtpaths6 --query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    if command -v qtpaths >/dev/null 2>&1; then
        qtpaths --query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    if command -v qmake6 >/dev/null 2>&1; then
        qmake6 -query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    if command -v qmake >/dev/null 2>&1; then
        qmake -query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    return 1
}

should_bundle_gui_runtime_library() {
    local library_name="$1"

    case "$library_name" in
        ld-linux*.so*|libc.so*|libm.so*|libpthread.so*|librt.so*|libdl.so*|libutil.so*|libanl.so*|libnsl.so*|libresolv.so*|libnss_*.so*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

detect_binary_depends() {
    local binary_path="$1"
    local deps

    deps="$(dpkg-shlibdeps -O "$binary_path" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
    if [ -z "$deps" ]; then
        deps="libc6, libstdc++6"
    fi

    printf '%s' "$deps"
}

sanitize_gui_depends() {
    local raw_depends="$1"
    local sanitized

    sanitized="$(
        printf '%s\n' "$raw_depends" |
        tr ',' '\n' |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
        sed '/^$/d' |
        grep -Evi '^(libqt5|libqt6|qt5-|qt6-|libicu[0-9]+|libdouble-conversion[0-9-]*|libpcre2-16-0)( |$)' || true
    )"

    sanitized="$(printf '%s\n' "$sanitized" | paste -sd ', ' - | sed 's/,/, /g; s/,,*/,/g; s/^, //; s/, $//')"

    if [ -z "$sanitized" ]; then
        sanitized="libc6, libstdc++6"
    fi

    printf '%s' "$sanitized"
}

join_depends() {
    local result=""
    local part

    for part in "$@"; do
        if [ -n "$part" ]; then
            if [ -n "$result" ]; then
                result+=", "
            fi
            result+="$part"
        fi
    done

    printf '%s' "$result"
}

init_package_root() {
    local package_name="$1"
    local package_root="$STAGING_BASE/${package_name}_${PACKAGE_VERSION}_${ARCH}"

    rm -rf "$package_root"
    mkdir -p "$package_root/DEBIAN"
    chmod 0755 "$package_root/DEBIAN"

    printf '%s' "$package_root"
}

write_control_file() {
    local package_root="$1"
    local package_name="$2"
    local depends="$3"
    local description="$4"
    local recommends="${5:-}"
    local installed_size

    installed_size="$(du -sk "$package_root" | awk '{print $1}')"

    cat > "$package_root/DEBIAN/control" <<EOF
Package: ${package_name}
Version: ${PACKAGE_VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: FIC Maintainers <maintainers@example.com>
Depends: ${depends}
Installed-Size: ${installed_size}
Description: ${description}
EOF

    if [ -n "$recommends" ]; then
        sed -i "/^Installed-Size:/i Recommends: ${recommends}" "$package_root/DEBIAN/control"
    fi
}

write_common_preinst() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/preinst"
}

write_common_postinst() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2770 {} \;
    find /opt/fic -type f -exec chmod 0660 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \;
    fi
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/postinst"
}

write_symlink_postinst() {
    local package_root="$1"
    local command_name="$2"
    local target_path="$3"

    cat > "$package_root/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2770 {} \;
    find /opt/fic -type f -exec chmod 0660 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \;
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/postinst"
}

write_system_integration_postinst() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2770 {} \;
    find /opt/fic -type f -exec chmod 0660 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \;
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/postinst"
}

write_system_integration_symlink_postinst() {
    local package_root="$1"
    local command_name="$2"
    local target_path="$3"

    cat > "$package_root/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e

if [ "\${1:-}" = "triggered" ]; then
    shift
    printf '%s\n' "\$@" |
        /opt/fic/bin/fic --trust-sync-platform-affected
    exit \$?
fi

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2770 {} \;
    find /opt/fic -type f -exec chmod 0660 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \;
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

if [ -x /opt/fic/bin/fic ]; then
    /opt/fic/bin/fic --trust-sync-platform
fi

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/fic.conf || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable --now fic.service || true
    systemctl enable --now fic-device.service || true
    systemctl enable --now fic_get_device_udev_info.service || true
    systemctl enable --now fic-notify.service || true
fi

if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/postinst"
}

write_system_integration_prerm() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/prerm"
}

write_symlink_prerm() {
    local package_root="$1"
    local command_name="$2"
    local target_path="$3"

    cat > "$package_root/DEBIAN/prerm" <<EOF
#!/bin/sh
set -e

if [ "\$1" = "remove" ] && [ -L "/bin/$command_name" ] && [ "\$(readlink -f "/bin/$command_name")" = "$target_path" ]; then
    rm -f "/bin/$command_name"
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/prerm"
}

write_system_integration_symlink_prerm() {
    local package_root="$1"
    local command_name="$2"
    local target_path="$3"

    cat > "$package_root/DEBIAN/prerm" <<EOF
#!/bin/sh
set -e

if [ "\$1" = "remove" ] && [ -L "/bin/$command_name" ] && [ "\$(readlink -f "/bin/$command_name")" = "$target_path" ]; then
    rm -f "/bin/$command_name"
fi

if [ "\$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now fic-notify.service || true
    systemctl disable --now fic-device.service || true
    systemctl disable --now fic.service || true
    systemctl disable fic_get_device_udev_info.service || true
    systemctl daemon-reload || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/prerm"
}

write_fic_dick_postinst() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

if [ -d /opt/fic ]; then
    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2770 {} \;
    find /opt/fic -type f -exec chmod 0660 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \;
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable fic-device.service || true
    systemctl enable fic_get_device_info.service || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/postinst"
}

write_fic_dick_prerm() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable fic-device.service || true
    systemctl disable fic_get_device_info.service || true
    systemctl daemon-reload || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/prerm"
}

build_project() {
    local source_dir="$1"
    local build_dir="$2"
    local cmake_args=(-DCMAKE_BUILD_TYPE=Release)

    if [ "$source_dir" = "$FIC_SRC_DIR" ]; then
        cmake_args+=("-DFIC_TARGET_PLATFORM=$FIC_PACKAGING_TARGET_PLATFORM")
    fi

    cmake -S "$source_dir" -B "$build_dir" "${cmake_args[@]}"
    cmake --build "$build_dir" --parallel "$BUILD_JOBS"
}

install_cmake_component() {
    local build_dir="$1"
    local component="$2"
    local package_root="$3"

    DESTDIR="$package_root" cmake --install "$build_dir" --component "$component"
}

collect_bundled_runtime_closure() {
    local list_file="$1"
    shift
    local pending=("$@")
    local seen_file
    local current
    local dep_path
    local dep_name

    seen_file="$(mktemp "$STAGING_BASE/gui-runtime-seen-XXXXXX")"
    : > "$list_file"

    while [ "${#pending[@]}" -gt 0 ]; do
        current="${pending[0]}"
        pending=("${pending[@]:1}")

        if [ -z "$current" ] || [ ! -e "$current" ]; then
            continue
        fi

        if grep -Fxq "$current" "$seen_file"; then
            continue
        fi

        printf '%s\n' "$current" >> "$seen_file"

        while IFS= read -r dep_path; do
            [ -n "$dep_path" ] || continue

            dep_name="$(basename "$dep_path")"
            if ! should_bundle_gui_runtime_library "$dep_name"; then
                continue
            fi

            append_unique_line "$list_file" "$dep_path"
            pending+=("$dep_path")
        done < <(ldd "$current" 2>/dev/null | awk '/=> \// { print $3 }')
    done

    rm -f "$seen_file"
}

create_fic_gui_launcher() {
    local package_root="$1"

    cat > "$package_root/opt/fic/bin/fic-gui" <<'EOF'
#!/bin/sh
set -e

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
FIC_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

export LD_LIBRARY_PATH="$FIC_ROOT/qt/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export QT_PLUGIN_PATH="$FIC_ROOT/qt/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="$FIC_ROOT/qt/plugins/platforms"

exec "$SCRIPT_DIR/fic-gui.real" "$@"
EOF

    chmod 0755 "$package_root/opt/fic/bin/fic-gui"
}

create_fic_gui_qt_conf() {
    local package_root="$1"

    cat > "$package_root/opt/fic/bin/qt.conf" <<'EOF'
[Paths]
Prefix = ../qt
Plugins = plugins
Libraries = lib
EOF

    chmod 0644 "$package_root/opt/fic/bin/qt.conf"
}

bundle_fic_gui_qt_runtime() {
    local package_root="$1"
    local qt_plugin_dir
    local qt_lib_dir
    local qt_runtime_list
    local plugin_subdir
    local plugin_dir
    local plugin_file
    local qt_lib_file

    qt_plugin_dir="$(find_qt_plugin_dir)" || {
        echo "Failed to locate Qt plugin directory for fic-gui bundling" >&2
        exit 1
    }
    qt_lib_dir="$(find_qt_lib_dir)" || {
        echo "Failed to locate Qt library directory for fic-gui bundling" >&2
        exit 1
    }

    if [ -z "$qt_plugin_dir" ] || [ ! -d "$qt_plugin_dir" ]; then
        echo "Qt plugin directory is empty or does not exist: '$qt_plugin_dir'" >&2
        exit 1
    fi

    if [ -z "$qt_lib_dir" ] || [ ! -d "$qt_lib_dir" ]; then
        echo "Qt library directory is empty or does not exist: '$qt_lib_dir'" >&2
        exit 1
    fi
    qt_runtime_list="$(mktemp "$STAGING_BASE/gui-runtime-list-XXXXXX")"

    mkdir -p "$package_root${GUI_QT_BUNDLE_ROOT}/lib"
    mkdir -p "$package_root${GUI_QT_BUNDLE_ROOT}/plugins"

    # Bundle the whole Qt6 shared runtime from the build environment to avoid
    # mixing packaged Qt modules with system Qt modules on the target host.
    find "$qt_lib_dir" -maxdepth 1 \( -type f -o -type l \) -name 'libQt6*.so*' | while IFS= read -r qt_lib_file; do
        copy_shared_library_with_metadata "$qt_lib_file" "$package_root${GUI_QT_BUNDLE_ROOT}/lib"
    done

    for plugin_subdir in platforms platformthemes xcbglintegrations imageformats iconengines styles platforminputcontexts; do
        plugin_dir="$qt_plugin_dir/$plugin_subdir"
        if [ -d "$plugin_dir" ]; then
            mkdir -p "$package_root${GUI_QT_BUNDLE_ROOT}/plugins/$plugin_subdir"
            find "$plugin_dir" -maxdepth 1 -type f -name '*.so*' | while IFS= read -r plugin_file; do
                if [ "$plugin_subdir" = "platformthemes" ] && [ "$(basename "$plugin_file")" = "libqgtk3.so" ]; then
                    continue
                fi
                install -m 0755 "$plugin_file" "$package_root${GUI_QT_BUNDLE_ROOT}/plugins/$plugin_subdir/$(basename "$plugin_file")"
            done
        fi
    done

    collect_bundled_runtime_closure \
        "$qt_runtime_list" \
        "$FIC_GUI_BUILD_DIR/fic-gui"

    while IFS= read -r plugin_dir; do
        [ -n "$plugin_dir" ] || continue
        append_unique_line "$qt_runtime_list" "$plugin_dir"
    done < <(
        find "$package_root${GUI_QT_BUNDLE_ROOT}/plugins" -type f -name '*.so*' 2>/dev/null || true
    )

    collect_bundled_runtime_closure "$qt_runtime_list" $(cat "$qt_runtime_list")

    while IFS= read -r plugin_file; do
        [ -n "$plugin_file" ] || continue
        copy_shared_library_with_metadata "$plugin_file" "$package_root${GUI_QT_BUNDLE_ROOT}/lib"
    done < "$qt_runtime_list"

    rm -f "$qt_runtime_list"
}

build_fic_dick_package() {
    local package_name="fic-dick"
    local package_root
    local binary_depends
    local output_deb

    package_root="$(init_package_root "$package_name")"
    output_deb="$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    install_cmake_component "$FIC_DICK_BUILD_DIR" fic-dick "$package_root"

    binary_depends="$(detect_binary_depends "$package_root/opt/fic/bin/fic-dick")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$binary_depends" \
        "Free Integrity Control device collector binary"

    write_common_preinst "$package_root"
    write_fic_dick_postinst "$package_root"
    write_fic_dick_prerm "$package_root"

    rm -f "$output_deb"
    build_deb_package "$package_root" "$output_deb"

    printf '%s\n' "$output_deb"
}

build_fic_cli_package() {
    local package_name="fic-cli"
    local package_root
    local binary_depends
    local package_depends
    local output_deb

    package_root="$(init_package_root "$package_name")"
    output_deb="$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    install_cmake_component "$FIC_CLI_BUILD_DIR" fic-cli "$package_root"
    sed -i 's/\r$//' "$package_root/usr/share/bash-completion/completions/fic-cli"

    binary_depends="$(detect_binary_depends "$package_root/opt/fic/bin/fic-cli")"
    package_depends="$(join_depends "$binary_depends" "fic (= ${PACKAGE_VERSION})")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$package_depends" \
        "Free Integrity Control terminal client"

    write_common_preinst "$package_root"
    write_symlink_postinst "$package_root" "fic-cli" "/opt/fic/bin/fic-cli"
    write_symlink_prerm "$package_root" "fic-cli" "/opt/fic/bin/fic-cli"

    rm -f "$output_deb"
    build_deb_package "$package_root" "$output_deb"

    printf '%s\n' "$output_deb"
}

build_fic_session_agent_package() {
    local package_name="fic-session-agent"
    local package_root
    local binary_depends
    local output_deb

    package_root="$(init_package_root "$package_name")"
    output_deb="$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    install_cmake_component "$FIC_SESSION_AGENT_BUILD_DIR" fic-session-agent "$package_root"

    binary_depends="$(detect_binary_depends "$package_root/opt/fic/bin/fic-session-agent")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$binary_depends" \
        "Free Integrity Control graphical session agent package"

    cat >> "$package_root/DEBIAN/control" <<EOF
Replaces: fic (<< ${PACKAGE_VERSION})
Breaks: fic (<< ${PACKAGE_VERSION})
EOF

    write_common_preinst "$package_root"

    rm -f "$output_deb"
    build_deb_package "$package_root" "$output_deb"

    printf '%s\n' "$output_deb"
}

build_fic_package() {
    local package_name="fic"
    local package_root
    local binary_depends
    local package_depends
    local output_deb
    local data_dir

    package_root="$(init_package_root "$package_name")"
    output_deb="$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    install_cmake_component "$FIC_BUILD_DIR" fic "$package_root"
    mkdir -p "$package_root/opt/fic/log"
    mkdir -p "$package_root/opt/fic/notify"

    binary_depends="$(detect_binary_depends "$package_root/opt/fic/bin/fic")"
    package_depends="$(join_depends "$binary_depends" "fic-dick (= ${PACKAGE_VERSION})" "libnotify-bin")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$package_depends" \
        "Free Integrity Control daemon package with runtime data" \
        "fic-session-agent (= ${PACKAGE_VERSION})"

    write_common_preinst "$package_root"
    write_conffiles "$package_root"
    write_platform_trust_triggers "$package_root" "$FIC_BUILD_DIR/fic"
    write_system_integration_symlink_postinst "$package_root" "fic" "/opt/fic/bin/fic"
    write_system_integration_symlink_prerm "$package_root" "fic" "/opt/fic/bin/fic"

    rm -f "$output_deb"
    build_deb_package "$package_root" "$output_deb"

    printf '%s\n' "$output_deb"
}

build_fic_gui_package() {
    local package_name="fic-gui"
    local package_root
    local binary_depends
    local package_depends
    local output_deb

    package_root="$(init_package_root "$package_name")"
    output_deb="$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    mkdir -p "$package_root/opt/fic/bin"
    install_cmake_component "$FIC_GUI_BUILD_DIR" fic-gui "$package_root"
    mv "$package_root/opt/fic/bin/fic-gui" "$package_root/opt/fic/bin/fic-gui.real"
    create_fic_gui_launcher "$package_root"
    create_fic_gui_qt_conf "$package_root"
    bundle_fic_gui_qt_runtime "$package_root"

    binary_depends="$(detect_binary_depends "$FIC_GUI_BUILD_DIR/fic-gui")"
    binary_depends="$(sanitize_gui_depends "$binary_depends")"
    package_depends="$(join_depends "$binary_depends" "fic (= ${PACKAGE_VERSION})" "fic-dick (= ${PACKAGE_VERSION})")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$package_depends" \
        "Free Integrity Control GUI package"

    write_common_preinst "$package_root"
    write_symlink_postinst "$package_root" "fic-gui" "/opt/fic/bin/fic-gui"
    write_symlink_prerm "$package_root" "fic-gui" "/opt/fic/bin/fic-gui"

    rm -f "$output_deb"
    build_deb_package "$package_root" "$output_deb"

    printf '%s\n' "$output_deb"
}

main() {
    require_command cmake
    require_command dpkg-deb
    require_command dpkg-shlibdeps
    require_command groupadd
    require_command getent
    require_command ldd
    require_command objdump
    require_command readlink

    mkdir -p "$DIST_DIR"

    build_project "$FIC_DICK_SRC_DIR" "$FIC_DICK_BUILD_DIR"
    build_project "$FIC_SRC_DIR" "$FIC_BUILD_DIR"
    build_project "$FIC_SESSION_AGENT_SRC_DIR" "$FIC_SESSION_AGENT_BUILD_DIR"
    build_project "$FIC_CLI_SRC_DIR" "$FIC_CLI_BUILD_DIR"
    build_project "$FIC_GUI_SRC_DIR" "$FIC_GUI_BUILD_DIR"

    local dick_deb
    local fic_deb
    local session_agent_deb
    local cli_deb
    local gui_deb

    dick_deb="$(build_fic_dick_package)"
    fic_deb="$(build_fic_package)"
    session_agent_deb="$(build_fic_session_agent_package)"
    cli_deb="$(build_fic_cli_package)"
    gui_deb="$(build_fic_gui_package)"

    echo "Packages created:"
    echo "  $dick_deb"
    echo "  $fic_deb"
    echo "  $session_agent_deb"
    echo "  $cli_deb"
    echo "  $gui_deb"
}

main "$@"
