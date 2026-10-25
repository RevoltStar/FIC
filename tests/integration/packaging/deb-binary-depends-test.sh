#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
test_root="$(mktemp -d /tmp/fic-deb-depends-test.XXXXXX)"
export STAGING_BASE="$test_root/staging" BUILD_ROOT="$test_root/build" DIST_DIR="$test_root/dist" BUILD_JOBS=1
mkdir -p "$STAGING_BASE"
source "$repo/packaging/deb/build-fic-debian12-deb.sh" 0.1.1
trap 'rm -rf "$test_root"' EXIT
fail() { echo "DEB dependency test failed: $*" >&2; exit 1; }
mkdir -p "$test_root/input with spaces"
touch "$test_root/input with spaces/daemon" "$test_root/helper"

# Exercise the actual detector without depending on the host's library set.
dpkg-shlibdeps() {
    [ -f debian/control ] || return 91
    [ "$1" = -O ] || return 92
    shift
    for binary in "$@"; do
        [[ "$binary" = /* && -f "$binary" ]] || return 93
    done
    printf '%s\n' "$@" >> "$test_root/analyzed"
    if [ "$analysis_case" = helper_failure ]; then
        for binary in "$@"; do
            case "$binary" in
                */fic-package-infrastructure|*/fic-xfconf-inspect) return 17 ;;
            esac
        done
    fi
    case "$analysis_case" in
        success|helper_failure) printf 'shlibs:Depends=libc6 (>= 2.34), libqt6core6t64 (>= 6.4)\n' ;;
        failure) echo 'native analysis failed' >&2; echo 'shlibs:Depends=libc6'; return 17 ;;
        empty) printf 'shlibs:Other=irrelevant\n' ;;
    esac
}
cd "$test_root"
analysis_case=success
deps="$(detect_binary_depends 'input with spaces/daemon' helper)" || fail 'valid analysis rejected'
[ "$deps" = 'libc6 (>= 2.34), libqt6core6t64 (>= 6.4)' ] || fail 'native dependencies lost'
[ "$(wc -l < "$test_root/analyzed")" = 2 ] || fail 'multi-ELF analysis lost an input'
mkdir -p "$test_root/prelogin/opt/fic/bin" "$test_root/prelogin/usr/libexec/fic"
touch "$test_root/prelogin/opt/fic/bin/fic-prelogin" \
    "$test_root/prelogin/opt/fic/bin/fic-prelogin-integration" \
    "$test_root/prelogin/usr/libexec/fic/fic-prelogin-frontend"
rm "$test_root/analyzed"
detect_prelogin_depends "$test_root/prelogin" >/dev/null || fail 'prelogin analysis rejected'
[ "$(wc -l < "$test_root/analyzed")" = 3 ] || fail 'prelogin lost an ELF input'
for analysis_case in failure empty; do
    if deps="$(detect_binary_depends helper 2>"$test_root/error")"; then
        fail "$analysis_case analysis accepted"
    fi
    [ -z "$deps" ] || fail 'failed analysis emitted fallback dependencies'
    [ -s "$test_root/error" ] || fail 'analysis diagnostic suppressed'
    if [ "$analysis_case" = failure ]; then
        grep -q 'native analysis failed' "$test_root/error" || fail 'native error suppressed'
    fi
done
if detect_binary_depends does-not-exist >/dev/null 2>&1; then fail 'missing ELF accepted'; fi
if detect_binary_depends >/dev/null 2>&1; then fail 'empty ELF list accepted'; fi
if compgen -G "$STAGING_BASE/binary-shlibdeps-*" >/dev/null; then fail 'analysis directories leaked'; fi

# Failure must reach package builders even in a conditional command
# substitution (where Bash errexit does not protect nested commands).
init_package_root() { mkdir -p "$test_root/package-$1/DEBIAN"; printf '%s' "$test_root/package-$1"; }
install_cmake_component() {
    local root="$3"
    mkdir -p "$root/opt/fic/bin" "$root/usr/libexec/fic" "$root/usr/share/bash-completion/completions"
    touch "$root/opt/fic/bin/fic" "$root/opt/fic/bin/fic-dick" "$root/opt/fic/bin/fic-cli" \
        "$root/usr/libexec/fic/fic-session-agent" "$root/usr/libexec/fic/fic-xfconf-inspect" \
        "$root/usr/share/bash-completion/completions/fic-cli"
}
install_fic_pam_profiles() { :; }
install_fic_pam_slots() { :; }
write_control_file() { printf '%s' "$3" > "$test_root/control-written"; }
build_deb_package() { touch "$test_root/published"; }
mkdir -p "$FIC_BUILD_DIR"
touch "$FIC_BUILD_DIR/fic-package-infrastructure"
analysis_case=failure
for builder in build_fic_package build_fic_dick_package build_fic_cli_package build_fic_session_agent_package; do
    rm -f "$test_root/analyzed"
    if result="$("$builder" 2>"$test_root/error")"; then fail "$builder ignored dependency failure"; fi
    [ -s "$test_root/analyzed" ] || fail "$builder failed before dependency analysis"
    [ ! -e "$test_root/control-written" ] && [ ! -e "$test_root/published" ] || fail "$builder staged invalid metadata"
done
analysis_case=helper_failure
for builder in build_fic_dick_package build_fic_session_agent_package; do
    if result="$("$builder" 2>"$test_root/error")"; then fail "$builder ignored helper analysis failure"; fi
    [ ! -e "$test_root/control-written" ] && [ ! -e "$test_root/published" ] || fail "$builder staged incomplete helper dependencies"
done
write_fic_pam_preinst() { :; }
write_platform_trust_triggers() { :; }
write_system_integration_symlink_postinst() { :; }
write_system_integration_symlink_prerm() { :; }
analysis_case=success
build_fic_package >/dev/null || fail 'valid package dependency metadata rejected'
for provider in sudo procps openssh-server; do
    grep -Eq "(^|, )$provider(,|$)" "$test_root/control-written" || fail "missing uninstall runtime provider: $provider"
done
echo 'DEB binary dependency tests passed'
