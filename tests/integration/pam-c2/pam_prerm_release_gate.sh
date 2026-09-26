#!/bin/bash
# C2 package-removal (prerm) REAL functional gate: installs the actually
# built FIC .deb in a DISPOSABLE container as root, establishes an
# FIC-owned password topology through the PRODUCTION coordinator API,
# removes the package with the REAL dpkg prerm and proves the C2 package
# release semantics against the REAL pam-auth-update + PAM stack.
#
# One scenario per container run (a package removal is terminal):
#
#   docker run --rm -v "$PWD":/src:ro debian:12 \
#       bash /src/tests/integration/pam-c2/pam_prerm_release_gate.sh history-initial
#
# Scenarios:
#   history-initial          FIC H ownership only -> release
#   quality-history          FIC Q+H ownership     -> release
#   foreign-quality-history  stock pwquality selected BEFORE FIC H ownership
#   foreign-added-during-fic stock pwquality added AFTER FIC Q+H ownership
#
# NOTE: this gate and the executor/wiring gates must NEVER run in the same
# container (pam-auth-update wrapper conflicts and shared evidence dirs).
set -u

SCENARIO="${1:-}"
case "$SCENARIO" in
    history-initial|quality-history|foreign-quality-history|foreign-added-during-fic)
        ;;
    *)
        echo "usage: $0 <history-initial|quality-history|foreign-quality-history|foreign-added-during-fic>" >&2
        exit 2
        ;;
esac

REPO="${GATE_REPO:-/src}"
GATE_DIR="$REPO/tests/integration/pam-c2"
EVID=/tmp/fic-prerm-gate-evidence
GATE_USER=ficgate
DRIVER=/tmp/fic-prerm-bin/fic-pam-c2-wiring-driver
PROBE=/tmp/fic-prerm-bin/fic-pam-probe
JOURNAL=/opt/fic/db/mutation-journal.json
# Production daemon journal (the installed maintenance binary reads THIS
# path; the driver writes the ownership provenance exactly there).
export FIC_PAM_C2_JOURNAL_PATH="$JOURNAL"
CURRENT_PW='Init!2026#GateXx'
FAILED=0

mkdir -p "$EVID"
verdict() { echo "$1" | tee -a "$EVID/verdicts.txt"; }
gate_pass() { verdict "PASS $SCENARIO $1"; }
gate_fail() { verdict "FAIL $SCENARIO $1"; FAILED=1; }
note() { echo "[prerm-gate:$SCENARIO] $*"; }
die_environment() {
    echo "ENVIRONMENT INVALID: $*" >&2
    exit 97
}

# ---------------------------------------------------------------- setup
DISTRO="$(. /etc/os-release && echo "$PRETTY_NAME")"
echo "$DISTRO" > "$EVID/distro.txt"
note "distro: $DISTRO"

DISTRO_TAG="$(case "$(. /etc/os-release && echo "$ID-$VERSION_ID")" in
    debian-12) echo debian12 ;;
    ubuntu-24.04) echo ubuntu2404 ;;
    *) die_environment "unsupported distro for the prerm gate" ;;
esac)"

export DEBIAN_FRONTEND=noninteractive
apt-get update > "$EVID/apt-update.log" 2>&1 || die_environment "apt-get update failed"
apt_ok=0
for attempt in 1 2 3 4 5; do
    if apt-get install -y --no-install-recommends \
        libpam-runtime libpam-modules libpam-pwquality \
        passwd cracklib-runtime wamerican gcc libc6-dev libpam0g-dev \
        libssl-dev nlohmann-json3-dev libsqlite3-dev pkg-config \
        libsystemd-dev libglib2.0-dev qtbase5-dev cmake g++ make \
        >> "$EVID/apt-install.log" 2>&1; then
        apt_ok=1
        break
    fi
    note "package install attempt $attempt failed; retrying"
    sleep 3
done
[ "$apt_ok" -eq 1 ] || die_environment "package install failed"

command -v pam-auth-update >/dev/null || die_environment "pam-auth-update missing"
command -v chpasswd >/dev/null || die_environment "chpasswd missing"

# ------------------------------------------------- install the built package
DEBS="$(find "$REPO/dist" -maxdepth 1 \
    \( -name "fic_*_${DISTRO_TAG}_amd64.deb" \
    -o -name "fic-dick_*_${DISTRO_TAG}_amd64.deb" \) | sort)"
echo "$DEBS" | grep -q "_${DISTRO_TAG}_amd64.deb" || \
    die_environment "no built fic .deb for $DISTRO_TAG in $REPO/dist"
note "installing: $(echo $DEBS | tr '\n' ' ')"
pkg_ok=0
for pkg_attempt in 1 2 3 4 5; do
    # shellcheck disable=SC2086
    if apt-get install -y --no-install-recommends $DEBS \
        >> "$EVID/dpkg-install.log" 2>&1; then
        pkg_ok=1
        break
    fi
    note "package installation attempt $pkg_attempt failed; retrying"
    sleep 3
done
[ "$pkg_ok" -eq 1 ] ||
    die_environment "fic package installation failed (see dpkg-install.log)"
dpkg -s fic >/dev/null 2>&1 || die_environment "fic package not installed"
[ -x /opt/fic/bin/fic ] || die_environment "/opt/fic/bin/fic missing"
[ -f /var/lib/dpkg/info/fic.prerm ] || die_environment "installed prerm missing"
command -v pam-auth-update >/dev/null || die_environment "package install broke pam-auth-update"

# ------------------------------------------------- build the gate drivers
GATE_PLATFORM="$(case "$(. /etc/os-release && echo "$ID-$VERSION_ID")" in
    debian-12) echo debian-12 ;;
    ubuntu-24.04) echo ubuntu-24.04 ;;
    *) die_environment "unsupported distro for the driver build" ;;
esac)"
cmake -S "$REPO" -B /tmp/fic-prerm-build \
    -DCMAKE_BUILD_TYPE=Release \
    -DFIC_TARGET_PLATFORM="$GATE_PLATFORM" \
    > "$EVID/cmake-configure.log" 2>&1 || die_environment "cmake configure failed"
cmake --build /tmp/fic-prerm-build --target fic-pam-c2-wiring-driver -j2 \
    > "$EVID/cmake-build.log" 2>&1 || die_environment "wiring driver build failed"
DRIVER_BIN="$(find /tmp/fic-prerm-build -name fic-pam-c2-wiring-driver -type f | head -1)"
[ -n "$DRIVER_BIN" ] || die_environment "wiring driver binary not found"
mkdir -p /tmp/fic-prerm-bin
cp "$DRIVER_BIN" "$DRIVER"
gcc -O2 -Wall -o "$PROBE" "$GATE_DIR/fic_pam_probe.c" -lpam || \
    die_environment "probe build failed"
chown root:root "$PROBE"
# setuid root: the probe performs pam_chauthtok in root mode (the current
# token is not required for target users); running it as the gate user
# would exercise the self-change conversation the probe does not model.
chmod 4755 "$PROBE"

# ------------------------------------------------- gate user
if ! id "$GATE_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/sh "$GATE_USER" || die_environment "gate user failed"
fi
echo "$GATE_USER:$CURRENT_PW" | chpasswd || die_environment "initial password failed"

# ------------------------------------------------- helpers
shadow_digest() {
    getent shadow "$GATE_USER" | cut -d: -f2 | sha256sum | cut -d' ' -f1
}

try_change() { # candidate -> rc; REAL pam_chauthtok through common-password
    su -s /bin/sh -c \
        "env FIC_GATE_PW='$1' FIC_GATE_CURRENT='$CURRENT_PW' $PROBE $GATE_USER" \
        "$GATE_USER" > "$EVID/last-probe.txt" 2>&1
}

change_ok() {
    local before after
    before="$(shadow_digest)"
    try_change "$1"
    after="$(shadow_digest)"
    grep -q '^RESULT ok' "$EVID/last-probe.txt" && [ "$before" != "$after" ]
}

change_rejected() {
    local before after
    before="$(shadow_digest)"
    try_change "$1"
    after="$(shadow_digest)"
    grep -q '^RESULT fail' "$EVID/last-probe.txt" && [ "$before" = "$after" ]
}

# Proven reliably rejected by the REAL pwquality+cracklib ('weakpass' with
# 8 lowercase chars PASSES Debian 12 defaults and must NOT be used).
WEAK_PW='password1'
STRONG_PW='Fg!Prerm2026#GateAa1'

bootstrap() {
    "$DRIVER" bootstrap || die_environment "managed slot bootstrap failed"
}

intent() { # quality history
    "$DRIVER" intent "$1" "$2" >> "$EVID/driver.log" 2>&1
}

apply_topology() {
    "$DRIVER" apply > "$EVID/last-apply.txt" 2>&1
}

expect_class() { # expected-class
    "$DRIVER" inspect > "$EVID/inspect.txt" 2>&1 || return 1
    grep -q "^topologyClass=$1\$" "$EVID/inspect.txt"
}

enable_foreign_pwquality() {
    pam-auth-update --enable pwquality >> "$EVID/foreign.log" 2>&1
}

snapshot() { # name
    local d="$EVID/$1"
    mkdir -p "$d"
    cp /etc/pam.d/common-password "$d/" 2>/dev/null
    cp /var/lib/pam/password "$d/" 2>/dev/null
    for slot in fic-password-quality fic-password-history \
                fic-password-history-initial; do
        cp "/etc/pam.d/$slot" "$d/" 2>/dev/null
    done
    cp "$JOURNAL" "$d/mutation-journal.json" 2>/dev/null
    "$DRIVER" inspect > "$d/inspect.txt" 2>&1
}

# ------------------------------------------------- establish ownership
# Distro containers may auto-select the stock pwquality profile when
# libpam-pwquality is installed; normalize the baseline so each scenario
# starts from a KNOWN selection state (foreign scenarios re-enable it
# explicitly at the right moment).
pam-auth-update --disable pwquality >> "$EVID/foreign.log" 2>&1 || true
note "establishing FIC-owned topology"
bootstrap

case "$SCENARIO" in
    history-initial)
        intent 0 1 || die_environment "intent failed"
        apply_topology || gate_fail "pre-removal apply failed: $(tr '\n' ' ' < "$EVID/last-apply.txt")"
        expect_class FicHistoryInitial || gate_fail "topology is not FicHistoryInitial"
        ;;
    quality-history)
        intent 1 1 || die_environment "intent failed"
        apply_topology || gate_fail "pre-removal apply failed: $(tr '\n' ' ' < "$EVID/last-apply.txt")"
        expect_class FicQualityPlusFicHistory || gate_fail "topology is not FicQualityPlusFicHistory"
        ;;
    foreign-quality-history)
        enable_foreign_pwquality || die_environment "foreign pwquality enable failed"
        intent 0 1 || die_environment "intent failed"
        apply_topology || gate_fail "pre-removal apply failed: $(tr '\n' ' ' < "$EVID/last-apply.txt")"
        expect_class ForeignQualityPlusFicHistory || gate_fail "topology is not ForeignQualityPlusFicHistory"
        ;;
    foreign-added-during-fic)
        intent 1 1 || die_environment "intent failed"
        apply_topology || gate_fail "pre-removal apply failed: $(tr '\n' ' ' < "$EVID/last-apply.txt")"
        expect_class FicQualityPlusFicHistory || gate_fail "topology is not FicQualityPlusFicHistory"
        enable_foreign_pwquality || die_environment "foreign pwquality enable failed"
        ;;
esac

if [ "$FAILED" -eq 1 ]; then
    snapshot "pre-removal-failed"
    verdict "FAIL $SCENARIO aborted before package removal"
    exit 1
fi
snapshot "pre-removal"

# ------------------------------------------------- REAL package removal
note "running the REAL prerm (dpkg -r fic)"
if dpkg -r fic > "$EVID/dpkg-remove.log" 2>&1; then
    gate_pass "dpkg -r fic exit 0"
else
    gate_fail "dpkg -r fic failed: $(tr '\n' ' ' < "$EVID/dpkg-remove.log")"
fi
snapshot "post-removal"

# ------------------------------------------------- release proofs
state_file=/var/lib/pam/password
if [ -f "$state_file" ] && grep -q "Module: fic-password" "$state_file"; then
    gate_fail "a FIC password identity is still selected after removal"
else
    gate_pass "no FIC password identity selected"
fi

if grep -q "fic-password" /etc/pam.d/common-password 2>/dev/null; then
    gate_fail "common-password still references a FIC password identity"
else
    gate_pass "no FIC password include in common-password"
fi

slots_clean=1
for slot in fic-password-quality fic-password-history \
            fic-password-history-initial; do
    if [ -f "/etc/pam.d/$slot" ] &&
       ! grep -q "state=neutral" "/etc/pam.d/$slot"; then
        note "slot $slot is not neutral after removal"
        slots_clean=0
    fi
done
if [ "$slots_clean" -eq 1 ]; then
    gate_pass "managed password slots released (absent or neutral)"
else
    gate_fail "a managed password slot is not neutral after removal"
fi

foreign_expected=0
case "$SCENARIO" in
    foreign-quality-history|foreign-added-during-fic) foreign_expected=1 ;;
esac

if [ "$foreign_expected" -eq 1 ]; then
    if grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
        gate_pass "the foreign stock pwquality producer is preserved"
    else
        gate_fail "the foreign stock pwquality producer was destroyed"
    fi
    if change_rejected "$WEAK_PW"; then
        gate_pass "weak password still rejected by the foreign pwquality"
    else
        gate_fail "weak password was NOT rejected after the release"
    fi
fi

if change_ok "$STRONG_PW"; then
    gate_pass "pam_chauthtok works through the released common-password"
else
    gate_fail "pam_chauthtok is broken after the release: $(tr '\n' ' ' < "$EVID/last-probe.txt")"
fi

if [ "$FAILED" -eq 0 ]; then
    verdict "PASS $SCENARIO gate"
    exit 0
fi
exit 1
