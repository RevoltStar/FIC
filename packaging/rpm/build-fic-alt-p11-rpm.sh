#!/usr/bin/env bash
set -euo pipefail

PACKAGE_VERSION="${1:-0.1.0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
STAGING_BASE="${STAGING_BASE:-$(mktemp -d /tmp/fic-rpm-stage-XXXXXX)}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build-rpm}"
RPM_TOPDIR="${RPM_TOPDIR:-$(mktemp -d /tmp/fic-rpmbuild-XXXXXX)}"
RPM_RELEASE="${RPM_RELEASE:-1.altp11}"
RPM_ALLOW_ROOT_BUILD="${RPM_ALLOW_ROOT_BUILD:-1}"
ARCH="$(rpm --eval '%{_arch}')"
GUI_QT_BUNDLE_ROOT="/opt/fic/qt"
SYSTEMD_UNIT_DIR="/usr/lib/systemd/system"
BUILD_LOCALE="${BUILD_LOCALE:-C.UTF-8}"

export LANG="$BUILD_LOCALE"
export LC_ALL="$BUILD_LOCALE"

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
    rm -rf "$STAGING_BASE" "$RPM_TOPDIR"
}

trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
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

copy_matching_files() {
    local source_dir="$1"
    local target_dir="$2"
    local pattern="$3"
    local source_file

    mkdir -p "$target_dir"
    if [ ! -d "$source_dir" ]; then
        return 0
    fi

    find "$source_dir" -maxdepth 1 -type f -name "$pattern" | while IFS= read -r source_file; do
        install -m 0644 "$source_file" "$target_dir/$(basename "$source_file")"
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

find_qt_plugin_dir() {
    local candidate

    if command -v qtpaths6 >/dev/null 2>&1; then
        qtpaths6 --query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64/qt6/bin/qtpaths6 /usr/lib/qt6/bin/qtpaths6; do
        if [ -x "$candidate" ]; then
            "$candidate" --query QT_INSTALL_PLUGINS 2>/dev/null && return 0
        fi
    done

    if command -v qtpaths >/dev/null 2>&1; then
        qtpaths --query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64/qt6/bin/qtpaths /usr/lib/qt6/bin/qtpaths; do
        if [ -x "$candidate" ]; then
            "$candidate" --query QT_INSTALL_PLUGINS 2>/dev/null && return 0
        fi
    done

    if command -v qmake6 >/dev/null 2>&1; then
        qmake6 -query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64/qt6/bin/qmake6 /usr/lib/qt6/bin/qmake6; do
        if [ -x "$candidate" ]; then
            "$candidate" -query QT_INSTALL_PLUGINS 2>/dev/null && return 0
        fi
    done

    if command -v qmake >/dev/null 2>&1; then
        qmake -query QT_INSTALL_PLUGINS 2>/dev/null && return 0
    fi

    for candidate in \
        /usr/lib64/qt6/plugins \
        /usr/lib/qt6/plugins \
        /usr/lib64/plugins \
        /usr/lib/plugins
    do
        if [ -d "$candidate/platforms" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

find_qt_lib_dir() {
    local candidate

    if command -v qtpaths6 >/dev/null 2>&1; then
        qtpaths6 --query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64/qt6/bin/qtpaths6 /usr/lib/qt6/bin/qtpaths6; do
        if [ -x "$candidate" ]; then
            "$candidate" --query QT_INSTALL_LIBS 2>/dev/null && return 0
        fi
    done

    if command -v qtpaths >/dev/null 2>&1; then
        qtpaths --query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64/qt6/bin/qtpaths /usr/lib/qt6/bin/qtpaths; do
        if [ -x "$candidate" ]; then
            "$candidate" --query QT_INSTALL_LIBS 2>/dev/null && return 0
        fi
    done

    if command -v qmake6 >/dev/null 2>&1; then
        qmake6 -query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64/qt6/bin/qmake6 /usr/lib/qt6/bin/qmake6; do
        if [ -x "$candidate" ]; then
            "$candidate" -query QT_INSTALL_LIBS 2>/dev/null && return 0
        fi
    done

    if command -v qmake >/dev/null 2>&1; then
        qmake -query QT_INSTALL_LIBS 2>/dev/null && return 0
    fi

    for candidate in /usr/lib64 /usr/lib64/qt6/lib /usr/lib /usr/lib/qt6/lib; do
        if find "$candidate" -maxdepth 1 \( -type f -o -type l \) -name 'libQt6Core.so*' | grep -q .; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

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

    while IFS= read -r plugin_file; do
        [ -n "$plugin_file" ] || continue
        append_unique_line "$qt_runtime_list" "$plugin_file"
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

build_project() {
    local source_dir="$1"
    local build_dir="$2"

    cmake -S "$source_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$build_dir" --parallel
}

init_rpm_tree() {
    mkdir -p \
        "$RPM_TOPDIR/BUILD" \
        "$RPM_TOPDIR/BUILDROOT" \
        "$RPM_TOPDIR/RPMS" \
        "$RPM_TOPDIR/SOURCES" \
        "$RPM_TOPDIR/SPECS" \
        "$RPM_TOPDIR/SRPMS"
}

run_rpmbuild() {
    local spec_path="$1"
    local rpmbuild_args=("--define" "_topdir $RPM_TOPDIR")

    if [ "$(id -u)" -eq 0 ] && [ "$RPM_ALLOW_ROOT_BUILD" = "1" ]; then
        rpmbuild_args+=("--define" "_allow_root_build 1")
    fi

    rpmbuild "${rpmbuild_args[@]}" -bb "$spec_path" >&2
}

init_package_root() {
    local package_name="$1"
    local package_root="$STAGING_BASE/${package_name}-${PACKAGE_VERSION}-${ARCH}"

    rm -rf "$package_root"
    mkdir -p "$package_root"

    printf '%s' "$package_root"
}

write_file_list() {
    local package_root="$1"
    local file_list="$2"

    : > "$file_list"

    find "$package_root" -type d | sort | while IFS= read -r path; do
        path="${path#$package_root}"
        [ -n "$path" ] || continue

        case "$path" in
            /opt/fic|/opt/fic/*)
                printf '%%dir %s\n' "$path" >> "$file_list"
                ;;
        esac
    done

    find "$package_root" \( -type f -o -type l \) | sort | while IFS= read -r path; do
        path="${path#$package_root}"
        [ -n "$path" ] || continue
        case "$path" in
            /opt/fic/config/DAC.conf|/opt/fic/config/DC.conf|/opt/fic/config/GLOBAL.conf|/opt/fic/config/NET.conf|/opt/fic/config/OSS.conf|/opt/fic/config/SYSCTL.conf)
                printf '%%config(noreplace) %s\n' "$path" >> "$file_list"
                ;;
            *)
                printf '%s\n' "$path" >> "$file_list"
                ;;
        esac
    done
}

write_spec_file() {
    local spec_path="$1"
    local package_name="$2"
    local summary="$3"
    local description="$4"
    local requires="$5"
    local recommends="$6"
    local source_name="$7"
    local file_list_source="$8"
    local pre_script="$9"
    local post_script="${10}"
    local preun_script="${11}"

    {
        printf 'Name: %s\n' "$package_name"
        printf 'Version: %s\n' "$PACKAGE_VERSION"
        printf 'Release: %s\n' "$RPM_RELEASE"
        printf 'Summary: %s\n' "$summary"
        printf 'License: Proprietary\n'
        printf 'Group: System/Configuration/Other\n'
        printf 'BuildArch: %s\n' "$ARCH"
        printf '%%undefine __find_debuginfo_files\n'
        printf 'Source0: %s\n' "$source_name"
        printf 'Source1: %s\n' "$file_list_source"
        if [ -n "$requires" ]; then
            printf 'Requires: %s\n' "$requires"
        fi
        if [ -n "$recommends" ]; then
            printf 'Recommends: %s\n' "$recommends"
        fi
        printf '\n%%description\n%s\n' "$description"
        printf '\n%%prep\n'
        printf 'mkdir -p %%{_builddir}/%%{name}-%%{version}\n'
        printf 'cd %%{_builddir}/%%{name}-%%{version}\n'
        printf 'tar -xzf %%{SOURCE0}\n'
        printf '\n%%build\n:\n'
        printf '\n%%install\n'
        printf 'rm -rf %%{buildroot}\n'
        printf 'mkdir -p %%{buildroot}\n'
        printf 'cp -a %%{_builddir}/%%{name}-%%{version}/. %%{buildroot}/\n'
        printf '\n%%pre\n%s\n' "$pre_script"
        printf '\n%%post\n%s\n' "$post_script"
        printf '\n%%preun\n%s\n' "$preun_script"
        printf '\n%%files -f %%{SOURCE1}\n'
        printf '%%defattr(-,root,root,-)\n'
        printf '\n%%changelog\n'
        printf '* Tue May 13 2026 OpenAI Codex <codex@example.com> - %s-%s\n' "$PACKAGE_VERSION" "$RPM_RELEASE"
        printf -- '- Automated ALT p11 RPM build\n'
    } > "$spec_path"
}

build_rpm_package() {
    local package_root="$1"
    local package_name="$2"
    local summary="$3"
    local description="$4"
    local requires="$5"
    local recommends="$6"
    local pre_script="$7"
    local post_script="$8"
    local preun_script="$9"
    local source_name="${package_name}-${PACKAGE_VERSION}.tar.gz"
    local source_path="$RPM_TOPDIR/SOURCES/$source_name"
    local file_list_source="${package_name}.files"
    local file_list_path="$RPM_TOPDIR/SOURCES/$file_list_source"
    local spec_path="$RPM_TOPDIR/SPECS/${package_name}.spec"
    local output_rpm

    tar -C "$package_root" -czf "$source_path" .
    write_file_list "$package_root" "$file_list_path"
    write_spec_file \
        "$spec_path" \
        "$package_name" \
        "$summary" \
        "$description" \
        "$requires" \
        "$recommends" \
        "$source_name" \
        "$file_list_source" \
        "$pre_script" \
        "$post_script" \
        "$preun_script"

    run_rpmbuild "$spec_path"

    output_rpm="$(find "$RPM_TOPDIR/RPMS/$ARCH" -maxdepth 1 -type f -name "${package_name}-${PACKAGE_VERSION}-${RPM_RELEASE}.${ARCH}.rpm" | head -n 1)"
    if [ -z "$output_rpm" ]; then
        echo "Failed to locate built RPM for $package_name" >&2
        exit 1
    fi

    mkdir -p "$DIST_DIR"
    if ! cp -f "$output_rpm" "$DIST_DIR/"; then
        echo "Failed to copy built RPM to $DIST_DIR" >&2
        exit 1
    fi

    printf '%s\n' "$DIST_DIR/$(basename "$output_rpm")"
}

common_pre_script() {
    cat <<'EOF'
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

exit 0
EOF
}

common_post_script() {
    cat <<'EOF'
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db || true
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus || true
    fi

    if [ ! -f /opt/fic/config/commandhash.conf ]; then
        : > /opt/fic/config/commandhash.conf || true
    fi

    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2770 {} \; || true
    find /opt/fic -type f -exec chmod 0660 {} \; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \; || true
    fi
fi

exit 0
EOF
}

symlink_post_script() {
    local command_name="$1"
    local target_path="$2"

    cat <<EOF
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db || true
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus || true
    fi

    if [ ! -f /opt/fic/config/commandhash.conf ]; then
        : > /opt/fic/config/commandhash.conf || true
    fi

    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2770 {} \\; || true
    find /opt/fic -type f -exec chmod 0660 {} \\; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \\; || true
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

exit 0
EOF
}

system_integration_symlink_post_script() {
    local command_name="$1"
    local target_path="$2"

    cat <<EOF
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify /opt/fic/share

    if [ ! -f /opt/fic/db/devices.db ] && [ -f /opt/fic/share/devices.seed.db ]; then
        cp /opt/fic/share/devices.seed.db /opt/fic/db/devices.db || true
    fi

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus || true
    fi

    if [ ! -f /opt/fic/config/commandhash.conf ]; then
        : > /opt/fic/config/commandhash.conf || true
    fi

    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2770 {} \\; || true
    find /opt/fic -type f -exec chmod 0660 {} \\; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \\; || true
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
    if [ -x "\$systemctl_bin" ]; then
        "\$systemctl_bin" daemon-reload >/dev/null 2>&1 || true
        "\$systemctl_bin" enable fic_get_device_info.service >/dev/null 2>&1 || true
        "\$systemctl_bin" enable fic_get_device_udev_info.service >/dev/null 2>&1 || true
        "\$systemctl_bin" enable --now fic.service >/dev/null 2>&1 || true
        "\$systemctl_bin" enable --now fic-notify.service >/dev/null 2>&1 || true
        break
    fi
done

for udevadm_bin in /usr/bin/udevadm /usr/sbin/udevadm /sbin/udevadm /bin/udevadm; do
    if [ -x "\$udevadm_bin" ]; then
        "\$udevadm_bin" control --reload-rules >/dev/null 2>&1 || true
        break
    fi
done

exit 0
EOF
}

simple_preun_script() {
    cat <<'EOF'
exit 0
EOF
}

symlink_preun_script() {
    local command_name="$1"
    local target_path="$2"

    cat <<EOF
if [ "\$1" -eq 0 ] && [ -L "/bin/$command_name" ] && [ "\$(readlink -f "/bin/$command_name")" = "$target_path" ]; then
    rm -f "/bin/$command_name"
fi

exit 0
EOF
}

system_integration_symlink_preun_script() {
    local command_name="$1"
    local target_path="$2"

    cat <<EOF
if [ "\$1" -eq 0 ] && [ -L "/bin/$command_name" ] && [ "\$(readlink -f "/bin/$command_name")" = "$target_path" ]; then
    rm -f "/bin/$command_name"
fi

if [ "\$1" -eq 0 ]; then
    for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
        if [ -x "\$systemctl_bin" ]; then
            "\$systemctl_bin" disable --now fic.service >/dev/null 2>&1 || true
            "\$systemctl_bin" disable --now fic-notify.service >/dev/null 2>&1 || true
            "\$systemctl_bin" disable fic_get_device_udev_info.service >/dev/null 2>&1 || true
            "\$systemctl_bin" daemon-reload >/dev/null 2>&1 || true
            break
        fi
    done
fi

exit 0
EOF
}

fic_dick_post_script() {
    cat <<'EOF'
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2770 {} \; || true
    find /opt/fic -type f -exec chmod 0660 {} \; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0770 {} \; || true
    fi
fi

for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
    if [ -x "$systemctl_bin" ]; then
        "$systemctl_bin" daemon-reload >/dev/null 2>&1 || true
        "$systemctl_bin" enable fic_get_device_info.service >/dev/null 2>&1 || true
        break
    fi
done

exit 0
EOF
}

fic_dick_preun_script() {
    cat <<'EOF'
if [ "$1" -eq 0 ]; then
    for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
        if [ -x "$systemctl_bin" ]; then
            "$systemctl_bin" disable fic_get_device_info.service >/dev/null 2>&1 || true
            "$systemctl_bin" daemon-reload >/dev/null 2>&1 || true
            break
        fi
    done
fi

exit 0
EOF
}

build_fic_dick_package() {
    local package_name="fic-dick"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    mkdir -p "$package_root/opt/fic/bin"
    mkdir -p "$package_root$SYSTEMD_UNIT_DIR"
    install -m 0755 "$FIC_DICK_BUILD_DIR/fic-dick" "$package_root/opt/fic/bin/fic-dick"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/service/fic_get_device_info.service" "$package_root$SYSTEMD_UNIT_DIR/fic_get_device_info.service"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control device collector binary" \
        "Free Integrity Control device collector binary." \
        "" \
        "" \
        "$(common_pre_script)" \
        "$(fic_dick_post_script)" \
        "$(fic_dick_preun_script)")"

    printf '%s\n' "$output_rpm"
}

build_fic_cli_package() {
    local package_name="fic-cli"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    mkdir -p "$package_root/opt/fic/bin"
    install -m 0755 "$FIC_CLI_BUILD_DIR/fic-cli" "$package_root/opt/fic/bin/fic-cli"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control terminal client" \
        "Free Integrity Control terminal socket client." \
        "fic = ${PACKAGE_VERSION}-${RPM_RELEASE}" \
        "" \
        "$(common_pre_script)" \
        "$(symlink_post_script "fic-cli" "/opt/fic/bin/fic-cli")" \
        "$(symlink_preun_script "fic-cli" "/opt/fic/bin/fic-cli")")"

    printf '%s\n' "$output_rpm"
}

build_fic_session_agent_package() {
    local package_name="fic-session-agent"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    mkdir -p "$package_root/opt/fic/bin"
    mkdir -p "$package_root/etc/xdg/autostart"

    install -m 0755 "$FIC_SESSION_AGENT_BUILD_DIR/fic-session-agent" "$package_root/opt/fic/bin/fic-session-agent"
    install -m 0644 "$FIC_SESSION_AGENT_SRC_DIR/fic-session-agent.desktop" "$package_root/etc/xdg/autostart/fic-session-agent.desktop"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control graphical session agent" \
        "Free Integrity Control graphical session agent." \
        "" \
        "" \
        "$(common_pre_script)" \
        "$(common_post_script)" \
        "$(simple_preun_script)")"

    printf '%s\n' "$output_rpm"
}

build_fic_package() {
    local package_name="fic"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    mkdir -p "$package_root/opt/fic/bin"
    mkdir -p "$package_root/opt/fic/config"
    mkdir -p "$package_root/opt/fic/db"
    mkdir -p "$package_root/opt/fic/share"
    mkdir -p "$package_root/opt/fic/log"
    mkdir -p "$package_root/opt/fic/notify"
    mkdir -p "$package_root$SYSTEMD_UNIT_DIR"
    mkdir -p "$package_root/etc/udev/rules.d"
    mkdir -p "$package_root/usr/share/bash-completion/completions"

    install -m 0755 "$FIC_BUILD_DIR/fic" "$package_root/opt/fic/bin/fic"
    install -m 0755 "$FIC_SRC_DIR/src/scripts/notify/fic-notify-dispatcher" "$package_root/opt/fic/bin/fic-notify-dispatcher"
    install -m 0755 "$FIC_SRC_DIR/src/scripts/service/fic-udevadm-trigger" "$package_root/opt/fic/bin/fic-udevadm-trigger"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/completion/fic" "$package_root/usr/share/bash-completion/completions/fic-cli"
    sed -i 's/\r$//' "$package_root/usr/share/bash-completion/completions/fic-cli"

    copy_tree_contents "$FIC_SRC_DIR/src/scripts/config" "$package_root/opt/fic/config"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/db/PCI_CLASS_ru.txt" "$package_root/opt/fic/db/PCI_CLASS_ru.txt"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/db/USB_CLASS_ru.txt" "$package_root/opt/fic/db/USB_CLASS_ru.txt"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/db/devices.db" "$package_root/opt/fic/share/devices.seed.db"
    copy_tree_contents "$FIC_SRC_DIR/src/scripts/image" "$package_root/opt/fic/image"
    copy_tree_contents "$FIC_SRC_DIR/src/scripts/lang" "$package_root/opt/fic/lang"

    install -m 0644 "$FIC_SRC_DIR/src/scripts/service/fic.service" "$package_root$SYSTEMD_UNIT_DIR/fic.service"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/service/fic-notify.service" "$package_root$SYSTEMD_UNIT_DIR/fic-notify.service"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/service/fic.timer" "$package_root$SYSTEMD_UNIT_DIR/fic.timer"
    install -m 0644 "$FIC_SRC_DIR/src/scripts/service/fic_get_device_udev_info.service" "$package_root$SYSTEMD_UNIT_DIR/fic_get_device_udev_info.service"
    copy_tree_contents "$FIC_SRC_DIR/src/scripts/udev" "$package_root/etc/udev/rules.d"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control daemon package with runtime data" \
        "Free Integrity Control daemon package with runtime data." \
        "fic-dick = ${PACKAGE_VERSION}-${RPM_RELEASE}, libnotify" \
        "fic-session-agent = ${PACKAGE_VERSION}-${RPM_RELEASE}" \
        "$(common_pre_script)" \
        "$(system_integration_symlink_post_script "fic" "/opt/fic/bin/fic")" \
        "$(system_integration_symlink_preun_script "fic" "/opt/fic/bin/fic")")"

    printf '%s\n' "$output_rpm"
}

build_fic_gui_package() {
    local package_name="fic-gui"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    mkdir -p "$package_root/opt/fic/bin"
    install -m 0755 "$FIC_GUI_BUILD_DIR/fic-gui" "$package_root/opt/fic/bin/fic-gui.real"
    create_fic_gui_launcher "$package_root"
    create_fic_gui_qt_conf "$package_root"
    bundle_fic_gui_qt_runtime "$package_root"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control GUI package" \
        "Free Integrity Control GUI package." \
        "fic = ${PACKAGE_VERSION}-${RPM_RELEASE}, fic-dick = ${PACKAGE_VERSION}-${RPM_RELEASE}" \
        "" \
        "$(common_pre_script)" \
        "$(symlink_post_script "fic-gui" "/opt/fic/bin/fic-gui")" \
        "$(symlink_preun_script "fic-gui" "/opt/fic/bin/fic-gui")")"

    printf '%s\n' "$output_rpm"
}

main() {
    require_command cmake
    require_command cp
    require_command find
    require_command getent
    require_command groupadd
    require_command ld
    require_command ldd
    require_command objdump
    require_command readlink
    require_command rpm
    require_command rpmbuild
    require_command tar

    mkdir -p "$DIST_DIR"
    init_rpm_tree

    build_project "$FIC_DICK_SRC_DIR" "$FIC_DICK_BUILD_DIR"
    build_project "$FIC_SRC_DIR" "$FIC_BUILD_DIR"
    build_project "$FIC_SESSION_AGENT_SRC_DIR" "$FIC_SESSION_AGENT_BUILD_DIR"
    build_project "$FIC_CLI_SRC_DIR" "$FIC_CLI_BUILD_DIR"
    build_project "$FIC_GUI_SRC_DIR" "$FIC_GUI_BUILD_DIR"

    local dick_rpm
    local fic_rpm
    local session_agent_rpm
    local cli_rpm
    local gui_rpm

    dick_rpm="$(build_fic_dick_package)"
    fic_rpm="$(build_fic_package)"
    session_agent_rpm="$(build_fic_session_agent_package)"
    cli_rpm="$(build_fic_cli_package)"
    gui_rpm="$(build_fic_gui_package)"

    echo "Packages created:"
    echo "  $dick_rpm"
    echo "  $fic_rpm"
    echo "  $session_agent_rpm"
    echo "  $cli_rpm"
    echo "  $gui_rpm"
}

main "$@"
