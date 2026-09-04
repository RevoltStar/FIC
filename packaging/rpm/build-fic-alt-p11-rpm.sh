#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/packaging/lib/version-contract.sh"
fic_configure_product_version "$@"
PACKAGE_VERSION="$FIC_PACKAGE_VERSION"
FIC_BUILD_COMMIT="${FIC_BUILD_COMMIT:-unknown}"
FIC_RELEASE_TAG="${FIC_RELEASE_TAG:-none}"
FIC_RELEASE_BUILD="${FIC_RELEASE_BUILD:-OFF}"
case "$FIC_RELEASE_BUILD" in
    1|ON|on|TRUE|true|YES|yes)
        FIC_EXPECTED_BUILD_KIND=release
        ;;
    *)
        FIC_EXPECTED_BUILD_KIND=development
        ;;
esac
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
STAGING_BASE="${STAGING_BASE:-$(mktemp -d /tmp/fic-rpm-stage-XXXXXX)}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build-rpm}"
RPM_TOPDIR="${RPM_TOPDIR:-$(mktemp -d /tmp/fic-rpmbuild-XXXXXX)}"
RPM_RELEASE="${RPM_RELEASE:-1.altp11}"
RPM_ALLOW_ROOT_BUILD="${RPM_ALLOW_ROOT_BUILD:-1}"
ARCH="$(rpm --eval '%{_arch}')"
GUI_QT_BUNDLE_ROOT="/opt/fic/qt"
SYSTEMD_UNIT_DIR="/usr/lib/systemd/system"
TMPFILES_DIR="/usr/lib/tmpfiles.d"
BUILD_LOCALE="${BUILD_LOCALE:-C.UTF-8}"

export LANG="$BUILD_LOCALE"
export LC_ALL="$BUILD_LOCALE"

source "$ROOT_DIR/packaging/lib/build-resources.sh"
source "$ROOT_DIR/packaging/lib/gui-runtime-compliance.sh"
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
    rm -rf "$STAGING_BASE" "$RPM_TOPDIR"
}

trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

verify_built_binary() {
    local binary_path="$1"
    local component="$2"
    local version_output
    local actual_component
    local actual_version
    local remainder
    local build_info
    local expected

    version_output="$("$binary_path" --version)"
    read -r actual_component actual_version remainder <<< "$version_output"
    if [ "$actual_component" != "$component" ] ||
       [ "$actual_version" != "$FIC_PRODUCT_VERSION" ]; then
        echo "Version mismatch for $binary_path: $version_output" >&2
        exit 1
    fi

    build_info="$("$binary_path" --build-info)"
    for expected in \
        "component=$component" \
        "product_version=$FIC_PRODUCT_VERSION" \
        "build_kind=$FIC_EXPECTED_BUILD_KIND" \
        "build_commit=$FIC_BUILD_COMMIT" \
        "release_tag=$FIC_RELEASE_TAG"; do
        if ! grep -Fqx "$expected" <<< "$build_info"; then
            echo "Build-info mismatch for $binary_path: missing $expected" >&2
            exit 1
        fi
    done
}

verify_rpm_metadata() {
    local package_path="$1"
    local expected_name="$2"
    local actual_name
    local actual_version
    local actual_release

    actual_name="$(rpm -qp --queryformat '%{NAME}' "$package_path")"
    actual_version="$(rpm -qp --queryformat '%{VERSION}' "$package_path")"
    actual_release="$(rpm -qp --queryformat '%{RELEASE}' "$package_path")"
    if [ "$actual_name" != "$expected_name" ] ||
       [ "$actual_version" != "$PACKAGE_VERSION" ] ||
       [ "$actual_release" != "$RPM_RELEASE" ]; then
        echo "RPM metadata mismatch for $package_path: $actual_name $actual_version-$actual_release" >&2
        exit 1
    fi
}

verify_rpm_gui_license_metadata() {
    local package_path="$1"
    local actual_license

    actual_license="$(rpm -qp --queryformat '%{LICENSE}' "$package_path")"
    if [ "$actual_license" != "SUL-1.0 AND LGPL-3.0-only" ]; then
        echo "Unexpected fic-gui RPM License metadata: $actual_license" >&2
        return 1
    fi
}

verify_rpm_gui_dependency_metadata() {
    local package_path="$1"
    local qt_requirements

    qt_requirements="$(rpm -qp --requires "$package_path" | grep '^libQt6' || true)"
    if [ -n "$qt_requirements" ]; then
        echo "fic-gui RPM has external Qt requirements despite its private bundle:" >&2
        printf '%s\n' "$qt_requirements" >&2
        return 1
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

build_project() {
    local source_dir="$1"
    local build_dir="$2"
    local cmake_args=(
        -DCMAKE_BUILD_TYPE=Release
        "-DFIC_PRODUCT_VERSION=$FIC_PRODUCT_VERSION"
        "-DFIC_BUILD_COMMIT=$FIC_BUILD_COMMIT"
        "-DFIC_RELEASE_TAG=$FIC_RELEASE_TAG"
        "-DFIC_RELEASE_BUILD=$FIC_RELEASE_BUILD"
        "-DFIC_SYSTEMD_UNIT_DIR=$SYSTEMD_UNIT_DIR"
        "-DFIC_TMPFILES_DIR=$TMPFILES_DIR"
    )

    if [ "$source_dir" = "$FIC_SRC_DIR" ]; then
        cmake_args+=("-DFIC_TARGET_PLATFORM=alt-p11")
    fi

    cmake -S "$source_dir" -B "$build_dir" "${cmake_args[@]}"
    cmake --build "$build_dir" --parallel "$BUILD_JOBS"
}

install_cmake_component() {
    local build_dir="$1"
    local component="$2"
    local package_root="$3"

    DESTDIR="$package_root" cmake --install "$build_dir" --component "$component" >&2
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
            /etc/security/fic-pwhistory.conf)
                printf '%%config(noreplace) %s\n' "$path" >> "$file_list"
                ;;
            /usr/share/doc/fic-gui/*)
                printf '%%doc %s\n' "$path" >> "$file_list"
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
    local source_name="$6"
    local file_list_source="$7"
    local pre_script="$8"
    local post_script="$9"
    local preun_script="${10}"
    local package_license="SUL-1.0"

    if [ "$package_name" = "fic-gui" ]; then
        package_license="SUL-1.0 AND LGPL-3.0-only"
    fi

    {
        printf 'Name: %s\n' "$package_name"
        printf 'Version: %s\n' "$PACKAGE_VERSION"
        printf 'Release: %s\n' "$RPM_RELEASE"
        printf 'Summary: %s\n' "$summary"
        printf 'License: %s\n' "$package_license"
        printf 'Group: System/Configuration/Other\n'
        printf 'BuildArch: %s\n' "$ARCH"
        printf '%%undefine __find_debuginfo_files\n'
        if [ "$package_name" = "fic-gui" ]; then
            # Qt dependencies are satisfied by the verified private closure in
            # /opt/fic/qt. Keep automatic dependency generation for every
            # non-Qt runtime dependency.
            printf '%%filter_from_requires /^libQt6/d\n'
        fi
        printf 'Source0: %s\n' "$source_name"
        printf 'Source1: %s\n' "$file_list_source"
        if [ -n "$requires" ]; then
            printf 'Requires: %s\n' "$requires"
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
    local pre_script="$6"
    local post_script="$7"
    local preun_script="$8"
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
        "$source_name" \
        "$file_list_source" \
        "$pre_script" \
        "$post_script" \
        "$preun_script"

    if ! run_rpmbuild "$spec_path"; then
        echo "Failed to build RPM for $package_name" >&2
        return 1
    fi

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

system_integration_pre_script() {
    local lifecycle_hook="${1:-}"
    cat <<'EOF'
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /run/systemd/system ]; then
    for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
        if [ -x "$systemctl_bin" ]; then
            for unit in fic.service fic-device.service fic-notify.service; do
                if "$systemctl_bin" is-active --quiet "$unit"; then
                    "$systemctl_bin" stop "$unit" || exit 1
                fi
            done
            break
        fi
    done
fi
EOF
    printf '%s\n' "$lifecycle_hook"
    printf 'exit 0\n'
}

common_post_script() {
    cat <<'EOF'
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus || true
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt || true
    fi

    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2750 {} \; || true
    find /opt/fic -type f -exec chmod 0640 {} \; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \; || true
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
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus || true
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt || true
    fi

    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2750 {} \\; || true
    find /opt/fic -type f -exec chmod 0640 {} \\; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \\; || true
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

exit 0
EOF
}

system_integration_symlink_post_script() {
    local command_name="$1"
    local target_path="$2"
    local lifecycle_hook="${3:-}"

    cat <<EOF
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus || true
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt || true
    fi

    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2750 {} \\; || true
    find /opt/fic -type f -exec chmod 0640 {} \\; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \\; || true
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

unset FIC_SOCKET_PATH FIC_DEVICE_SOCKET_PATH
if [ -d /run/systemd/system ]; then
    for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
        if [ -x "\$systemctl_bin" ]; then
            for unit in fic.service fic-device.service fic-notify.service; do
                if "\$systemctl_bin" is-active --quiet "\$unit"; then
                    "\$systemctl_bin" stop "\$unit" || exit 1
                fi
            done
            break
        fi
    done
fi

/opt/fic/bin/fic --maintenance ensure-config || exit 1
/opt/fic/bin/fic-dick --maintenance initialize-db || exit 1
/opt/fic/bin/fic --maintenance check-config || exit 1
/opt/fic/bin/fic-dick --maintenance check-db || exit 1

chown -R root:fic /opt/fic || exit 1
find /opt/fic -type d -exec chmod 2750 {} \; || exit 1
find /opt/fic -type f -exec chmod 0640 {} \; || exit 1
find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \; || exit 1

/opt/fic/bin/fic --trust-sync-platform || exit 1

for tmpfiles_bin in /usr/bin/systemd-tmpfiles /bin/systemd-tmpfiles /usr/sbin/systemd-tmpfiles /sbin/systemd-tmpfiles; do
    if [ -x "\$tmpfiles_bin" ]; then
        "\$tmpfiles_bin" --create /usr/lib/tmpfiles.d/fic.conf >/dev/null 2>&1 || true
        break
    fi
done

$lifecycle_hook

if [ -d /run/systemd/system ]; then
    for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
        if [ -x "\$systemctl_bin" ]; then
            "\$systemctl_bin" daemon-reload >/dev/null 2>&1 || exit 1
            "\$systemctl_bin" enable fic_get_device_info.service >/dev/null 2>&1 || true
            "\$systemctl_bin" enable --now fic.service >/dev/null 2>&1 || exit 1
            "\$systemctl_bin" enable --now fic-device.service >/dev/null 2>&1 || exit 1
            "\$systemctl_bin" enable --now fic_get_device_udev_info.service >/dev/null 2>&1 || true
            "\$systemctl_bin" enable --now fic-notify.service >/dev/null 2>&1 || exit 1
            "\$systemctl_bin" is-active --quiet fic.service || exit 1
            "\$systemctl_bin" is-active --quiet fic-device.service || exit 1
            /opt/fic/bin/fic --maintenance wait-daemon 30 || exit 1
            /opt/fic/bin/fic-dick wait-daemon 10 || exit 1
            break
        fi
    done
fi

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
    local lifecycle_hook="${3:-}"

    cat <<EOF
$lifecycle_hook

if [ "\$1" -eq 0 ] && [ -L "/bin/$command_name" ] && [ "\$(readlink -f "/bin/$command_name")" = "$target_path" ]; then
    rm -f "/bin/$command_name"
fi

if [ "\$1" -eq 0 ]; then
    for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
        if [ -x "\$systemctl_bin" ]; then
            "\$systemctl_bin" disable --now fic.service >/dev/null 2>&1 || true
            "\$systemctl_bin" disable --now fic-device.service >/dev/null 2>&1 || true
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

fic_pam_facility_pre_upgrade_script() {
    cat <<'EOF'
if [ "$1" -ge 2 ] && [ -x /etc/control.d/facilities/fic-pam-faillock ]; then
    /usr/sbin/control-dump fic-pam-faillock || exit 1
fi
if [ "$1" -ge 2 ] && [ -x /etc/control.d/facilities/fic-pam-pwhistory ]; then
    /usr/sbin/control-dump fic-pam-pwhistory || exit 1
fi
EOF
}

fic_pam_facility_post_script() {
    cat <<'EOF'
/opt/fic/bin/fic --maintenance pam-alt-pwhistory prepare || exit 1
if [ "$1" -ge 2 ] && [ -s /var/run/control/fic-pam-faillock ]; then
    /usr/sbin/control-restore fic-pam-faillock || exit 1
fi
if [ "$1" -ge 2 ] && [ -s /var/run/control/fic-pam-pwhistory ]; then
    /usr/sbin/control-restore fic-pam-pwhistory || exit 1
fi
EOF
}

fic_pam_facility_preun_script() {
    cat <<'EOF'
if [ "$1" -eq 0 ]; then
    /usr/sbin/control fic-pam-pwhistory disabled || {
        echo "refusing to remove fic with unsafe FIC-owned pam_pwhistory topology" >&2
        exit 1
    }
    /usr/sbin/control fic-pam-faillock disabled || {
        echo "refusing to remove fic with unsafe FIC-owned PAM topology" >&2
        exit 1
    }
fi
EOF
}

fic_dick_post_script() {
    cat <<'EOF'
if ! getent group fic >/dev/null 2>&1; then
    groupadd -r fic >/dev/null 2>&1 || true
fi

if [ -d /opt/fic ]; then
    chown -R root:fic /opt/fic || true
    find /opt/fic -type d -exec chmod 2750 {} \; || true
    find /opt/fic -type f -exec chmod 0640 {} \; || true

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \; || true
    fi
fi

for systemctl_bin in /usr/bin/systemctl /bin/systemctl /usr/sbin/systemctl /sbin/systemctl; do
    if [ -x "$systemctl_bin" ]; then
        "$systemctl_bin" daemon-reload >/dev/null 2>&1 || true
        "$systemctl_bin" enable fic-device.service >/dev/null 2>&1 || true
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
            "$systemctl_bin" disable fic-device.service >/dev/null 2>&1 || true
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
    install_cmake_component "$FIC_DICK_BUILD_DIR" fic-dick "$package_root"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control device collector binary" \
        "Free Integrity Control device collector binary." \
        "" \
        "$(system_integration_pre_script)" \
        "$(fic_dick_post_script)" \
        "$(fic_dick_preun_script)")" || return 1

    printf '%s\n' "$output_rpm"
}

build_fic_cli_package() {
    local package_name="fic-cli"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    install_cmake_component "$FIC_CLI_BUILD_DIR" fic-cli "$package_root"
    sed -i 's/\r$//' "$package_root/usr/share/bash-completion/completions/fic-cli"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control terminal client" \
        "Free Integrity Control terminal socket client." \
        "fic = ${PACKAGE_VERSION}-${RPM_RELEASE}" \
        "$(common_pre_script)" \
        "$(symlink_post_script "fic-cli" "/opt/fic/bin/fic-cli")" \
        "$(symlink_preun_script "fic-cli" "/opt/fic/bin/fic-cli")")" || return 1

    printf '%s\n' "$output_rpm"
}

build_fic_session_agent_package() {
    local package_name="fic-session-agent"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    install_cmake_component "$FIC_SESSION_AGENT_BUILD_DIR" fic-session-agent "$package_root"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control graphical session agent" \
        "Free Integrity Control graphical session agent." \
        "" \
        "$(common_pre_script)" \
        "$(common_post_script)" \
        "$(simple_preun_script)")" || return 1

    printf '%s\n' "$output_rpm"
}

build_fic_package() {
    local package_name="fic"
    local package_root
    local output_rpm

    package_root="$(init_package_root "$package_name")"
    install_cmake_component "$FIC_BUILD_DIR" fic "$package_root"
    mkdir -p "$package_root/opt/fic/log"
    mkdir -p "$package_root/opt/fic/notify"
    mkdir -p "$package_root/usr/lib/rpm"
    mkdir -p "$package_root/etc/control.d/facilities"
    install -m 0755 \
        "$ROOT_DIR/packaging/rpm/fic-trust-sync.filetrigger" \
        "$package_root/usr/lib/rpm/fic-trust-sync.filetrigger"
    install -m 0755 \
        "$ROOT_DIR/packaging/rpm/fic-pam-faillock" \
        "$package_root/etc/control.d/facilities/fic-pam-faillock"
    install -m 0755 \
        "$ROOT_DIR/packaging/rpm/fic-pam-pwhistory" \
        "$package_root/etc/control.d/facilities/fic-pam-pwhistory"

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control daemon package with runtime data" \
        "Free Integrity Control daemon package with runtime data." \
        "fic-dick = ${PACKAGE_VERSION}-${RPM_RELEASE}, libnotify, nftables, control, pam >= 1.7.1, pam-config >= 1.10.0" \
        "$(system_integration_pre_script "$(fic_pam_facility_pre_upgrade_script)")" \
        "$(system_integration_symlink_post_script "fic" "/opt/fic/bin/fic" "$(fic_pam_facility_post_script)")" \
        "$(system_integration_symlink_preun_script "fic" "/opt/fic/bin/fic" "$(fic_pam_facility_preun_script)")")" || return 1

    printf '%s\n' "$output_rpm"
}

build_fic_gui_package() {
    local package_name="fic-gui"
    local package_root
    local output_rpm
    local qt_plugin_dir

    package_root="$(init_package_root "$package_name")"
    mkdir -p "$package_root/opt/fic/bin"
    install_cmake_component "$FIC_GUI_BUILD_DIR" fic-gui "$package_root"
    mv "$package_root/opt/fic/bin/fic-gui" "$package_root/opt/fic/bin/fic-gui.real"
    qt_plugin_dir="$(find_qt_plugin_dir)" || {
        echo "Failed to locate Qt plugin directory for fic-gui bundling" >&2
        exit 1
    }
    fic_gui_create_launcher "$package_root" || return 1
    fic_gui_create_qt_conf "$package_root" || return 1
    fic_gui_bundle_qt_runtime "$package_root" rpm "$qt_plugin_dir" || return 1
    fic_gui_verify_runtime_compliance "$package_root" || return 1

    output_rpm="$(build_rpm_package \
        "$package_root" \
        "$package_name" \
        "Free Integrity Control GUI package" \
        "Free Integrity Control GUI package." \
        "fic = ${PACKAGE_VERSION}-${RPM_RELEASE}, fic-dick = ${PACKAGE_VERSION}-${RPM_RELEASE}" \
        "$(common_pre_script)" \
        "$(symlink_post_script "fic-gui" "/opt/fic/bin/fic-gui")" \
        "$(symlink_preun_script "fic-gui" "/opt/fic/bin/fic-gui")")" || return 1

    cp "$package_root/usr/share/doc/fic-gui/third-party-components.json" \
        "$output_rpm.third-party-components.json"

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
    require_command python3
    require_command readelf
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

    verify_built_binary "$FIC_DICK_BUILD_DIR/fic-dick" fic-dick
    verify_built_binary "$FIC_BUILD_DIR/fic" fic
    verify_built_binary "$FIC_SESSION_AGENT_BUILD_DIR/fic-session-agent" fic-session-agent
    verify_built_binary "$FIC_CLI_BUILD_DIR/fic-cli" fic-cli
    verify_built_binary "$FIC_GUI_BUILD_DIR/fic-gui" fic-gui

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

    verify_rpm_metadata "$dick_rpm" fic-dick
    verify_rpm_metadata "$fic_rpm" fic
    verify_rpm_metadata "$session_agent_rpm" fic-session-agent
    verify_rpm_metadata "$cli_rpm" fic-cli
    verify_rpm_metadata "$gui_rpm" fic-gui
    verify_rpm_gui_license_metadata "$gui_rpm"
    verify_rpm_gui_dependency_metadata "$gui_rpm"

    echo "Packages created:"
    echo "  $dick_rpm"
    echo "  $fic_rpm"
    echo "  $session_agent_rpm"
    echo "  $cli_rpm"
    echo "  $gui_rpm"
}

main "$@"
