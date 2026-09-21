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
    ubuntu-26.04)
        DEFAULT_PACKAGE_DISTRO_TAG="ubuntu2604"
        ;;
    *)
        echo "Unsupported Debian-family packaging platform: $FIC_PACKAGING_TARGET_PLATFORM" >&2
        exit 1
        ;;
esac
PACKAGE_DISTRO_TAG="${PACKAGE_DISTRO_TAG:-$DEFAULT_PACKAGE_DISTRO_TAG}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
STAGING_BASE="${STAGING_BASE:-$(mktemp -d /tmp/fic-deb-XXXXXX)}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build-linux}"
ARCH="$(dpkg --print-architecture)"
DEB_COMPRESSOR="${DEB_COMPRESSOR:-gzip}"
GUI_QT_BUNDLE_ROOT="/opt/fic/qt"

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
    rm -rf "$STAGING_BASE"
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

verify_deb_metadata() {
    local package_path="$1"
    local expected_name="$2"
    local actual_name
    local actual_version

    actual_name="$(dpkg-deb -f "$package_path" Package)"
    actual_version="$(dpkg-deb -f "$package_path" Version)"
    if [ "$actual_name" != "$expected_name" ] ||
       [ "$actual_version" != "$PACKAGE_VERSION" ]; then
        echo "DEB metadata mismatch for $package_path: $actual_name $actual_version" >&2
        exit 1
    fi
}

verify_deb_gui_compliance_metadata() {
    local package_path="$1"
    local dependency

    while IFS= read -r dependency; do
        dependency="$(printf '%s' "$dependency" | sed 's/^[[:space:]]*//')"
        case "$dependency" in
            libqt5*|libqt6*|qt5-*|qt6-*)
                echo "Bundled fic-gui package retains a system Qt dependency: $dependency" >&2
                return 1
                ;;
        esac
    done < <(dpkg-deb -f "$package_path" Depends | tr ',' '\n')
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
        grep -Evi '^(libqt5|libqt6|qt5-|qt6-)' || true
    )"

    sanitized="$(printf '%s\n' "$sanitized" | paste -sd, - | sed 's/,/, /g; s/^, //; s/, $//')"

    if [ -z "$sanitized" ]; then
        sanitized="libc6, libstdc++6"
    fi

    printf '%s' "$sanitized"
}

detect_gui_depends() {
    local package_root="$1"
    local binaries=("$FIC_GUI_BUILD_DIR/fic-gui")
    local elf_file
    local deps
    local shlibdeps_work
    local shlibdeps_output
    local shlibdeps_error

    while IFS= read -r elf_file; do
        binaries+=("$elf_file")
    done < <(
        python3 - "$package_root/usr/share/doc/fic-gui/third-party-components.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
for source_path in sorted({entry["source_path"] for entry in manifest["components"]}):
    print(source_path)
PY
    )

    shlibdeps_work="$(mktemp -d "$STAGING_BASE/gui-shlibdeps-XXXXXX")"
    shlibdeps_error="$shlibdeps_work/error"
    mkdir -p "$shlibdeps_work/debian"
    cat > "$shlibdeps_work/debian/control" <<'EOF'
Source: fic-gui-runtime

Package: fic-gui-runtime
Architecture: any
Description: temporary dependency analysis package
EOF
    if ! shlibdeps_output="$(
        cd "$shlibdeps_work"
        dpkg-shlibdeps \
            --ignore-missing-info \
            -O \
            "${binaries[@]}" 2>"$shlibdeps_error"
    )"; then
        cat "$shlibdeps_error" >&2
        rm -rf "$shlibdeps_work"
        return 1
    fi
    deps="$(printf '%s\n' "$shlibdeps_output" | sed -n 's/^shlibs:Depends=//p')"
    rm -rf "$shlibdeps_work"
    if [ -z "$deps" ]; then
        echo "Failed to derive system dependencies for bundled fic-gui runtime" >&2
        exit 1
    fi
    sanitize_gui_depends "$deps"
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

write_fic_pam_preinst() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -e

fic_legacy_pam_selection_present() {
    for state in /var/lib/pam/auth /var/lib/pam/account \
        /var/lib/pam/password /var/lib/pam/session \
        /var/lib/pam/session-noninteractive; do
        [ -f "$state" ] || continue
        if grep -Eq '^Module: (fic-faillock-notify|fic-faillock-authfail|fic-faillock-preauth-required|fic-faillock-authsucc|fic-pwquality|fic-pwhistory)$' "$state"; then
            return 0
        fi
    done
    return 1
}

fic_legacy_pam_journal_present() {
    journal=/opt/fic/db/mutation-journal.json
    [ -f "$journal" ] || return 1

    # The journal is written by FIC as nlohmann::json dump(2). Parse one
    # top-level record object at a time instead of matching unrelated records
    # together. This check is intentionally read-only and conservative.
    awk '
        function evaluate_record() {
            if (record ~ /"backend": "pam"/ &&
                record ~ /"status": "(prepared|applied|rollback_failed)"/ &&
                record ~ /"capability": "enable_(authentication_lockout|password_history|password_quality)"/ &&
                record ~ /"activation_identifiers": \[/ &&
                record ~ /"fic-(faillock-notify|faillock-authfail|faillock-preauth-required|faillock-authsucc|pwquality|pwhistory)"/) {
                found = 1
            }
        }
        /^    \{$/ {
            in_record = 1
            record = $0 "\n"
            next
        }
        in_record {
            record = record $0 "\n"
        }
        in_record && /^    \}[,]?$/ {
            evaluate_record()
            in_record = 0
            record = ""
        }
        END {
            exit found ? 0 : 1
        }
    ' "$journal"
}

fic_legacy_pam_state_present() {
    fic_legacy_pam_selection_present || fic_legacy_pam_journal_present
}

fic_report_legacy_pam_upgrade_refusal() {
    cat >&2 <<'MSG'
FIC upgrade refused: legacy PAM ownership state is still active.
The new version cannot prove who selected an old fic-* pam-auth-update profile
and will not adopt or delete that state automatically. Disable/reconcile the
affected PAM activation policy with the currently installed FIC version, then
retry the upgrade.
MSG
}

if [ "${1:-}" = "upgrade" ] && fic_legacy_pam_state_present; then
    fic_report_legacy_pam_upgrade_refusal
    exit 1
fi

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

active_units=""
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for unit in fic.service fic-device.service fic-notify.service; do
        if systemctl is-active --quiet "$unit"; then
            active_units="$active_units $unit"
            systemctl stop "$unit"
        fi
    done
fi

# Close the race in which the old daemon could persist a legacy selection or
# journal record after the first check but before it was stopped.
if [ "${1:-}" = "upgrade" ] && fic_legacy_pam_state_present; then
    fic_report_legacy_pam_upgrade_refusal
    for unit in $active_units; do
        systemctl start "$unit" || true
    done
    exit 1
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/preinst"
}


write_fic_preinst() {
    local package_root="$1"

    cat > "$package_root/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group fic >/dev/null 2>&1; then
    groupadd --system fic
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for unit in fic.service fic-device.service fic-notify.service; do
        if systemctl is-active --quiet "$unit"; then
            systemctl stop "$unit"
        fi
    done
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
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2750 {} \;
    find /opt/fic -type f -exec chmod 0640 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;
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
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2750 {} \;
    find /opt/fic -type f -exec chmod 0640 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;
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
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2750 {} \;
    find /opt/fic -type f -exec chmod 0640 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;
    fi
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
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

    cat > "$package_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

EOF
    write_pam_hook_proof_function >> "$package_root/DEBIAN/postinst"
    cat >> "$package_root/DEBIAN/postinst" <<EOF

# Recovery path after a failed \`prerm remove\`. When the pre-removal script
# aborts, dpkg runs \`postinst abort-remove\` to restore the package. This is
# NOT a configure path: it only restores package-managed service
# enablement/runtime state and exits before any configure-specific mutation.
# The generated prerm contains its own PAM detach-failure recovery: whenever
# its \`pam-auth-update --remove\` fails, the prerm restores and proves the
# permanent hook infrastructure while every FIC writer is still stopped, so
# by the time dpkg reaches this path the PAM state is either intact (the
# detach never started or changed nothing) or restored and proven. The
# read-only guard below keeps that invariant complete: if the prerm-side
# recovery could not prove the permanent hooks attached, no FIC writer is
# restarted and the package is left in the dpkg error state for manual
# administrator recovery. PAM topology, managed slots, the mutation journal
# and the journal witness are never touched here.
if [ "\${1:-}" = "abort-remove" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        if ! fic_prove_permanent_hooks_attached; then
            echo "FIC: abort-remove refuses to restore FIC services: the permanent PAM hook infrastructure is not proven attached (the PAM recovery after the failed removal did not succeed); fix the PAM state and re-run the removal or reinstall the package" >&2
            exit 1
        fi
        systemctl daemon-reload || true
        # Restore package-owned enablement. The critical units must be
        # re-enabled; the optional udev helper keeps its existing optional
        # semantics.
        if ! systemctl enable fic.service; then
            echo "FIC: abort-remove could not re-enable fic.service" >&2
            exit 1
        fi
        if ! systemctl enable fic-device.service; then
            echo "FIC: abort-remove could not re-enable fic-device.service" >&2
            exit 1
        fi
        if ! systemctl enable fic-notify.service; then
            echo "FIC: abort-remove could not re-enable fic-notify.service" >&2
            exit 1
        fi
        systemctl enable fic_get_device_udev_info.service || true
        # Restore runtime state. \`systemctl start\` on an already-active
        # unit is idempotent. stop/restart are deliberately never used here:
        # the removal may have failed exactly because a live FIC writer
        # refuses to stop.
        if ! systemctl start fic.service; then
            echo "FIC: abort-remove could not restore fic.service runtime state" >&2
            exit 1
        fi
        if ! systemctl start fic-device.service; then
            echo "FIC: abort-remove could not restore fic-device.service runtime state" >&2
            exit 1
        fi
        if ! systemctl start fic-notify.service; then
            echo "FIC: abort-remove could not restore fic-notify.service runtime state" >&2
            exit 1
        fi
        # Critical FIC writers must be active again for the package to count
        # as restored; otherwise the recovery genuinely failed and dpkg must
        # keep the failure visible. Normal \`postinst configure\` treats
        # \`fic-notify.service\` as mandatory (\`systemctl enable --now\` under
        # \`set -e\`), so the abort-remove recovery uses the same strict model.
        if ! systemctl is-active --quiet fic.service; then
            echo "FIC: abort-remove recovery left fic.service inactive" >&2
            exit 1
        fi
        if ! systemctl is-active --quiet fic-device.service; then
            echo "FIC: abort-remove recovery left fic-device.service inactive" >&2
            exit 1
        fi
        if ! systemctl is-active --quiet fic-notify.service; then
            echo "FIC: abort-remove recovery left fic-notify.service inactive" >&2
            exit 1
        fi
    fi
    exit 0
fi

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
    mkdir -p /opt/fic/config /opt/fic/db /opt/fic/log /opt/fic/notify

    if [ ! -f /opt/fic/lockstatus ]; then
        printf '0\n' > /opt/fic/lockstatus
    fi

    if [ ! -f /opt/fic/db/commandhash.txt ]; then
        : > /opt/fic/db/commandhash.txt
    fi

    chown -R root:fic /opt/fic
    find /opt/fic -type d -exec chmod 2750 {} \;
    find /opt/fic -type f -exec chmod 0640 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;
    fi
fi

ln -sfn "$target_path" "/bin/$command_name"

unset FIC_SOCKET_PATH FIC_DEVICE_SOCKET_PATH
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for unit in fic.service fic-device.service fic-notify.service; do
        if systemctl is-active --quiet "\$unit"; then
            systemctl stop "\$unit"
        fi
    done
fi

/opt/fic/bin/fic --maintenance ensure-config
/opt/fic/bin/fic-dick --maintenance initialize-db
/opt/fic/bin/fic --maintenance check-config
/opt/fic/bin/fic-dick --maintenance check-db

chown -R root:fic /opt/fic
find /opt/fic -type d -exec chmod 2750 {} \;
find /opt/fic -type f -exec chmod 0640 {} \;
find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;

if [ -x /opt/fic/bin/fic ]; then
    /opt/fic/bin/fic --trust-sync-platform
fi

if [ "\${1:-}" = "configure" ]; then
    # Package-side pre-attach validation (read-only): preserved
    # /etc/pam.d/fic-faillock-* conffiles must be proven canonical-neutral or
    # journal-bound FIC-owned state BEFORE the permanent hooks may reach the
    # live PAM graph. On failure the package configuration aborts before any
    # pam-auth-update invocation and before the daemon is started.
    if ! /opt/fic/bin/fic --maintenance validate-pam-slots-before-attach; then
        echo "FIC: refusing to attach permanent PAM hooks: existing /etc/pam.d/fic-faillock-* state failed pre-attach validation" >&2
        exit 1
    fi
    pam-auth-update --package
    # These four profiles are permanent integration infrastructure. Policy
    # enable/disable never owns or deselects them; mutable ownership stays in
    # the /etc/pam.d/fic-faillock-* conffile slots.
    pam-auth-update --enable \
        fic-faillock-hook-preauth \
        fic-faillock-hook-authfail \
        fic-faillock-hook-authsucc \
        fic-faillock-hook-account
fi

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/fic.conf || true
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now fic.service
    systemctl enable --now fic-device.service
    systemctl enable --now fic_get_device_udev_info.service || true
    systemctl enable --now fic-notify.service
    systemctl is-active --quiet fic.service
    systemctl is-active --quiet fic-device.service
    /opt/fic/bin/fic --maintenance wait-daemon 10
    /opt/fic/bin/fic-dick wait-daemon 10
fi

if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules || true
fi

exit 0
EOF

    chmod 0755 "$package_root/DEBIAN/postinst"
}
# Shared generated-script snippet: read-only proof that the package-owned
# permanent FIC PAM hook profiles are attached, expressed purely in terms of
# the standard pam-auth-update state model:
#   - the selected-profile records under /var/lib/pam (auth, account,
#     password, session, session-noninteractive) contain a
#     "Module: <profile>" entry for every permanent hook profile;
#   - the generated /etc/pam.d/common-auth stack mentions the preauth,
#     authfail and authsucc hook targets and /etc/pam.d/common-account
#     mentions the account hook target.
# The proof never invokes pam-auth-update and never mutates PAM state,
# managed slots, the mutation journal or its witness. It is used by the
# generated prerm (detach-failure recovery proof) and by the generated
# postinst abort-remove recovery guard.
write_pam_hook_proof_function() {
    cat <<'EOF'
fic_prove_permanent_hooks_attached() {
    if [ ! -d /var/lib/pam ] || [ ! -f /etc/pam.d/common-auth ] ||
        [ ! -f /etc/pam.d/common-account ]; then
        return 1
    fi
    fic_selected=
    for fic_record in auth account password session session-noninteractive; do
        if [ -f "/var/lib/pam/$fic_record" ]; then
            fic_selected="$fic_selected$(cat "/var/lib/pam/$fic_record")"
        fi
    done
    for fic_hook in fic-faillock-hook-preauth fic-faillock-hook-authfail \
        fic-faillock-hook-authsucc fic-faillock-hook-account; do
        case "$fic_selected" in
            *"Module: $fic_hook"*) ;;
            *) return 1 ;;
        esac
    done
    grep -q 'fic-faillock-preauth' /etc/pam.d/common-auth || return 1
    grep -q 'fic-faillock-authfail' /etc/pam.d/common-auth || return 1
    grep -q 'fic-faillock-authsucc' /etc/pam.d/common-auth || return 1
    grep -q 'fic-faillock-account' /etc/pam.d/common-account || return 1
    return 0
}
EOF
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
    find /opt/fic -type d -exec chmod 2750 {} \;
    find /opt/fic -type f -exec chmod 0640 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;
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

    cat > "$package_root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

EOF
    write_pam_hook_proof_function >> "$package_root/DEBIAN/prerm"
    cat >> "$package_root/DEBIAN/prerm" <<EOF

if [ "\$1" = "remove" ]; then
    # Invariant: package removal first stops all FIC PAM writers and only
    # then detaches the permanent hooks. A live daemon could still perform
    # PAM mutations or re-activate the infrastructure concurrently with the
    # profile detach; after the services are stopped no new PAM mutation is
    # possible.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now fic-notify.service || true
        systemctl disable --now fic-device.service || true
        systemctl disable --now fic.service || true
        systemctl disable fic_get_device_udev_info.service || true
        systemctl daemon-reload || true
        for unit in fic.service fic-device.service fic-notify.service; do
            attempt=0
            while [ "\$attempt" -lt 10 ]; do
                systemctl is-active --quiet "\$unit" || break
                attempt=\$((attempt + 1))
                sleep 1
            done
            # Invariant: hook detach requires positive proof that every FIC
            # PAM writer is inactive. A stop timeout is a package-removal
            # failure, not permission to continue: the permanent hooks stay
            # attached and the removal aborts before any pam-auth-update.
            if systemctl is-active --quiet "\$unit"; then
                echo "FIC: unit \$unit is still active after the bounded stop wait; refusing to detach permanent PAM hooks" >&2
                exit 1
            fi
        done
    fi
    # Only now detach the permanent FIC PAM hook infrastructure. Every FIC
    # writer is proven inactive at this point, so this is the only safe
    # window in which a failed detach can be contained: the permanent hook
    # infrastructure is restored and proven right here while no FIC writer
    # can interfere, and dpkg's later abort-remove path never has to restart
    # a writer on top of a partially detached PAM graph.
    if ! pam-auth-update --package --remove \
        fic-faillock-notify \
        fic-faillock-authfail \
        fic-faillock-preauth-required \
        fic-faillock-authsucc \
        fic-faillock-hook-preauth \
        fic-faillock-hook-authfail \
        fic-faillock-hook-authsucc \
        fic-faillock-hook-account \
        fic-pwquality \
        fic-pwhistory; then
        echo "FIC: failed to detach permanent PAM hooks; restoring the package PAM hook infrastructure while all FIC writers remain stopped" >&2
        # Only the permanent hook infrastructure is restored here. The legacy
        # policy-owned selector profiles are deliberately NOT re-enabled:
        # policy state lives in the managed /etc/pam.d/fic-faillock-* slots,
        # and the installed package only guarantees the permanent hooks.
        # A single \`--enable\` is sufficient: it re-selects the four profiles
        # and regenerates the common-* stacks; a preceding \`--package\` call
        # would only regenerate from the post-failure selection state and
        # add nothing.
        if ! pam-auth-update --enable \
            fic-faillock-hook-preauth \
            fic-faillock-hook-authfail \
            fic-faillock-hook-authsucc \
            fic-faillock-hook-account; then
            if fic_prove_permanent_hooks_attached; then
                echo "FIC: PAM infrastructure recovery failed: pam-auth-update could not re-enable the permanent hook profiles, but the permanent hooks are proven still attached; the package removal failed" >&2
                exit 1
            fi
            echo "FIC: PAM infrastructure recovery failed: pam-auth-update could not re-enable the permanent hook profiles and the permanent hook state is NOT proven restored; no FIC writer may be restarted" >&2
            exit 1
        fi
        if ! fic_prove_permanent_hooks_attached; then
            echo "FIC: PAM infrastructure recovery failed: the re-enabled permanent hook profiles could not be proven attached; the permanent hook state is NOT proven restored and no FIC writer may be restarted" >&2
            exit 1
        fi
        echo "FIC: permanent PAM hook infrastructure restored and proven attached; the package removal failed" >&2
        exit 1
    fi
fi

if [ "\$1" = "remove" ] && [ -L "/bin/$command_name" ] && [ "\$(readlink -f "/bin/$command_name")" = "$target_path" ]; then
    rm -f "/bin/$command_name"
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
    find /opt/fic -type d -exec chmod 2750 {} \;
    find /opt/fic -type f -exec chmod 0640 {} \;

    if [ -d /opt/fic/bin ]; then
        find /opt/fic/bin -maxdepth 1 -type f -exec chmod 0750 {} \;
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
    local cmake_args=(
        -DCMAKE_BUILD_TYPE=Release
        "-DFIC_PRODUCT_VERSION=$FIC_PRODUCT_VERSION"
        "-DFIC_BUILD_COMMIT=$FIC_BUILD_COMMIT"
        "-DFIC_RELEASE_TAG=$FIC_RELEASE_TAG"
        "-DFIC_RELEASE_BUILD=$FIC_RELEASE_BUILD"
    )

    if [ "$source_dir" = "$FIC_SRC_DIR" ]; then
        cmake_args+=(
            "-DFIC_TARGET_PLATFORM=$FIC_PACKAGING_TARGET_PLATFORM"
        )
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

install_fic_pam_profiles() {
    local package_root="$1"
    local profile
    local profile_dir="$package_root/usr/share/pam-configs"

    mkdir -p "$profile_dir"
    for profile in fic-faillock-notify fic-faillock-authfail \
        fic-faillock-preauth-required fic-faillock-authsucc \
        fic-faillock-hook-preauth fic-faillock-hook-authfail \
        fic-faillock-hook-authsucc fic-faillock-hook-account \
        fic-pwquality fic-pwhistory; do
        install -m 0644 \
            "$ROOT_DIR/packaging/deb/pam-configs/$profile" \
            "$profile_dir/$profile"
    done
}

install_fic_pam_slots() {
    local package_root="$1"
    local slot
    local slot_dir="$package_root/etc/pam.d"

    mkdir -p "$slot_dir"
    for slot in fic-faillock-preauth fic-faillock-authfail \
        fic-faillock-authsucc fic-faillock-account; do
        install -m 0644 \
            "$ROOT_DIR/packaging/deb/pam-slots/$slot" \
            "$slot_dir/$slot"
    done
    cat > "$package_root/DEBIAN/conffiles" <<'EOF'
/etc/pam.d/fic-faillock-preauth
/etc/pam.d/fic-faillock-authfail
/etc/pam.d/fic-faillock-authsucc
/etc/pam.d/fic-faillock-account
EOF
}

build_fic_dick_package() {
    local package_name="fic-dick"
    local package_root
    local binary_depends
    local package_depends
    local output_deb

    package_root="$(init_package_root "$package_name")"
    output_deb=\
"$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    install_cmake_component "$FIC_DICK_BUILD_DIR" fic-dick "$package_root"

    binary_depends="$(detect_binary_depends "$package_root/opt/fic/bin/fic-dick")"
    package_depends="$(join_depends "$binary_depends" "udev")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$package_depends" \
        "Free Integrity Control device collector binary"

    write_fic_preinst "$package_root"
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
    chmod 0750 "$package_root/opt/fic/bin/fic-cli"
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
    chmod 0755 "$package_root/usr/libexec/fic"
    chmod 0755 "$package_root/usr/libexec/fic/fic-session-agent"
    chmod 0755 "$package_root/usr/libexec/fic/fic-xfconf-inspect"

    binary_depends="$(detect_binary_depends \
        "$package_root/usr/libexec/fic/fic-session-agent")"
    helper_depends="$(detect_binary_depends \
        "$package_root/usr/libexec/fic/fic-xfconf-inspect")"
    binary_depends="$(join_depends "$binary_depends" "$helper_depends")"

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
    install_fic_pam_profiles "$package_root"
    install_fic_pam_slots "$package_root"
    mkdir -p "$package_root/opt/fic/log"
    mkdir -p "$package_root/opt/fic/notify"

    binary_depends="$(detect_binary_depends "$package_root/opt/fic/bin/fic")"
    package_depends="$(join_depends "$binary_depends" "fic-dick (= ${PACKAGE_VERSION})" "libnotify-bin" "util-linux" "nftables" "libpam-runtime" "libpam-modules" "libpam-pwquality")"

    write_control_file \
        "$package_root" \
        "$package_name" \
        "$package_depends" \
        "Free Integrity Control daemon package with runtime data" \
        "fic-session-agent (= ${PACKAGE_VERSION})"

    write_fic_pam_preinst "$package_root"
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
    local qt_plugin_dir

    package_root="$(init_package_root "$package_name")"
    output_deb="$DIST_DIR/${package_name}_${PACKAGE_VERSION}_${PACKAGE_DISTRO_TAG}_${ARCH}.deb"

    mkdir -p "$package_root/opt/fic/bin"
    install_cmake_component "$FIC_GUI_BUILD_DIR" fic-gui "$package_root"
    mv "$package_root/opt/fic/bin/fic-gui" "$package_root/opt/fic/bin/fic-gui.real"
    qt_plugin_dir="$(find_qt_plugin_dir)" || {
        echo "Failed to locate Qt plugin directory for fic-gui bundling" >&2
        exit 1
    }
    fic_gui_create_launcher "$package_root" || return 1
    chmod 0750 "$package_root/opt/fic/bin/fic-gui"
    chmod 0750 "$package_root/opt/fic/bin/fic-gui.real"
    fic_gui_create_qt_conf "$package_root" || return 1
    fic_gui_bundle_qt_runtime "$package_root" deb "$qt_plugin_dir" || return 1
    fic_gui_verify_runtime_compliance "$package_root" || return 1

    binary_depends="$(detect_gui_depends "$package_root")" || return 1
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
    build_deb_package "$package_root" "$output_deb" || return 1
    cp "$package_root/usr/share/doc/fic-gui/third-party-components.json" \
        "$output_deb.third-party-components.json"

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
    require_command python3
    require_command readelf
    require_command readlink

    mkdir -p "$DIST_DIR"

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

    local dick_deb
    local fic_deb
    local session_agent_deb
    local cli_deb
    local gui_deb

    dick_deb="$(build_fic_dick_package)"
    fic_deb="$(build_fic_package)"
    session_agent_deb="$(build_fic_session_agent_package)"
    cli_deb="$(build_fic_cli_package)"
    gui_deb="$(build_fic_gui_package)" || exit 1

    verify_deb_metadata "$dick_deb" fic-dick
    verify_deb_metadata "$fic_deb" fic
    verify_deb_metadata "$session_agent_deb" fic-session-agent
    verify_deb_metadata "$cli_deb" fic-cli
    verify_deb_metadata "$gui_deb" fic-gui
    verify_deb_gui_compliance_metadata "$gui_deb"

    echo "Packages created:"
    echo "  $dick_deb"
    echo "  $fic_deb"
    echo "  $session_agent_deb"
    echo "  $cli_deb"
    echo "  $gui_deb"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
