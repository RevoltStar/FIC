#!/bin/bash
# C2 production WIRING functional gate: exercises the full production wiring
# path (IDENTITY_ACCESS configuration intent -> PamPasswordTopologyCoordinator
# -> C2 transition executor -> daemon mutation journal -> PAM rollback
# backend) against the REAL pam-auth-update + PAM stack inside a DISPOSABLE
# container as root.
#
# Run (never on a host):
#   docker run --rm -v "$PWD":/src:ro debian:12 \
#       bash /src/tests/integration/pam-c2/pam_c2_wiring_gate.sh
#   docker run --rm -v "$PWD":/src:ro ubuntu:24.04 \
#       bash /src/tests/integration/pam-c2/pam_c2_wiring_gate.sh
#
# Unlike pam_c2_gate.sh (executor-level), every topology mutation here goes
# through the production coordinator API the daemon uses after the wiring
# stage — the executor is never driven directly.
set -u

REPO="${GATE_REPO:-/src}"
GATE_DIR="$REPO/tests/integration/pam-c2"
EVID=/tmp/fic-wiring-gate-evidence
GATE_USER=ficgate
DRIVER=/tmp/fic-wiring-bin/fic-pam-c2-wiring-driver
PROBE=/tmp/fic-wiring-bin/fic-pam-probe
FAILED=0
# NOTE: passwords must NOT contain the gate user's login name (ficgate):
# pwquality usercheck rejects passwords containing it.
CURRENT_PW='Init!2026#GateXx'
PREV_PW='Init!2026#GateXx'

mkdir -p "$EVID"

verdict() { echo "$1" | tee -a "$EVID/verdicts.txt"; }
gate_pass() { verdict "PASS $1"; }
gate_fail() { verdict "FAIL $1"; FAILED=1; }
note() { echo "[wiring-gate] $*"; }

die_environment() {
    echo "ENVIRONMENT INVALID: $*" >&2
    exit 97
}

# ---------------------------------------------------------------- setup
DISTRO="$(. /etc/os-release && echo "$PRETTY_NAME")"
echo "$DISTRO" > "$EVID/distro.txt"
note "distro: $DISTRO"

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

# Install the EXACT current FIC payload pam-configs (production files).
cp "$REPO"/packaging/deb/pam-configs/fic-password-quality-hook \
   "$REPO"/packaging/deb/pam-configs/fic-password-history-hook \
   "$REPO"/packaging/deb/pam-configs/fic-password-history-initial-hook \
   /usr/share/pam-configs/ || die_environment "FIC pam-configs install failed"
command -v chpasswd >/dev/null || die_environment "chpasswd missing"

have_pam_module() {
    for d in /lib/x86_64-linux-gnu/security \
             /usr/lib/x86_64-linux-gnu/security /lib/security; do
        if [ -f "$d/$1" ]; then
            echo "$d/$1"
            return 0
        fi
    done
    return 1
}

have_pam_module pam_unix.so >/dev/null || die_environment "pam_unix.so missing"
have_pam_module pam_pwquality.so >/dev/null || \
    die_environment "pam_pwquality.so missing"
have_pam_module pam_pwhistory.so >/dev/null || \
    die_environment "pam_pwhistory.so missing"

if [ ! -f /var/cache/cracklib/cracklib_dict.pwd ]; then
    create-cracklib-dict /usr/share/dict/words > /dev/null 2>&1 || \
        die_environment "cracklib dictionary cannot be created"
fi
[ -f /var/cache/cracklib/cracklib_dict.pwd ] || \
    die_environment "cracklib dictionary missing"

if [ -f /etc/security/pwquality.conf ] && \
   ! grep -q '^enforce_for_root' /etc/security/pwquality.conf; then
    echo 'enforce_for_root' >> /etc/security/pwquality.conf
fi

mkdir -p /tmp/fic-wiring-bin
gcc -O2 -Wall -o "$PROBE" "$GATE_DIR/fic_pam_probe.c" -lpam || \
    die_environment "probe build failed"
chown root:root "$PROBE"
chmod 4755 "$PROBE"

GATE_PLATFORM="$(
    case "$(. /etc/os-release && echo "$ID-$VERSION_ID")" in
        debian-12) echo debian-12 ;;
        debian-13) echo debian-13 ;;
        ubuntu-24.04) echo ubuntu-24.04 ;;
        ubuntu-26.04) echo ubuntu-26.04 ;;
        *) die_environment "unsupported distro for the wiring gate" ;;
    esac
)"
cmake -S "$REPO" -B /tmp/fic-wiring-build \
    -DCMAKE_BUILD_TYPE=Release \
    -DFIC_TARGET_PLATFORM="$GATE_PLATFORM" \
    > "$EVID/cmake-configure.log" 2>&1 || die_environment "cmake configure failed"
cmake --build /tmp/fic-wiring-build --target fic-pam-c2-wiring-driver -j2 \
    > "$EVID/cmake-build.log" 2>&1 || die_environment "wiring driver build failed"
DRIVER_BIN="$(find /tmp/fic-wiring-build -name fic-pam-c2-wiring-driver -type f | head -1)"
[ -n "$DRIVER_BIN" ] || die_environment "wiring driver binary not found"
cp "$DRIVER_BIN" "$DRIVER"

# pam-auth-update wrapper: traces every invocation (one profile per
# invocation assertion) and optionally injects ONE native failure.
PAU=/usr/sbin/pam-auth-update
if [ ! -f "$PAU.real" ]; then
    mv "$PAU" "$PAU.real"
    cat > "$PAU" <<'WRAPPER'
#!/bin/sh
echo "$*" >> /tmp/fic-wiring-gate-evidence/pam-auth-update.log
if [ "$#" -ne 2 ]; then
    echo "GATE-WRAPPER: expected exactly one profile per invocation, got: $*" >&2
    exit 43
fi
if [ -f /tmp/fic-wiring-gate-evidence/inject-native-failure ]; then
    rm -f /tmp/fic-wiring-gate-evidence/inject-native-failure
    echo "GATE-WRAPPER: injected native failure" >&2
    exit 42
fi
exec /usr/sbin/pam-auth-update.real "$@"
WRAPPER
    chmod 0755 "$PAU"
fi
: > "$EVID/pam-auth-update.log"

# ---------------------------------------------------------------- helpers
bootstrap() {
    "$DRIVER" bootstrap || die_environment "managed slot bootstrap failed"
}

intent() { # quality history
    "$DRIVER" intent "$1" "$2" >> "$EVID/driver.log" 2>&1
}

apply_topology() { # -> writes last-apply.txt
    "$DRIVER" apply > "$EVID/last-apply.txt" 2>&1
}

rollback_policy() { # policy -> writes last-rollback.txt
    "$DRIVER" rollback "$1" > "$EVID/last-rollback.txt" 2>&1
}

apply_ok() { # gate-name
    apply_topology || { gate_fail "$1: apply failed: $(cat "$EVID/last-apply.txt" | tr '\n' ' ')"; return 1; }
    return 0
}

inspect() {
    "$DRIVER" inspect > "$EVID/inspect.txt" 2>&1
}

require_field() { # key expected gate
    local actual
    actual="$(grep -E "^$1=" "$EVID/last-apply.txt" 2>/dev/null | head -1 | cut -d= -f2-)"
    [ "$actual" = "$2" ] || gate_fail "$3: $1 expected '$2', got '$actual'"
}

require_inspect() { # key expected gate
    inspect
    local actual
    actual="$(grep -E "^$1=" "$EVID/inspect.txt" | head -1 | cut -d= -f2-)"
    [ "$actual" = "$2" ] || gate_fail "$3: inspect $1 expected '$2', got '$actual'"
}

require_inspect_contains() { # key substring gate
    inspect
    grep -E "^$1=" "$EVID/inspect.txt" | grep -q "$2" || \
        gate_fail "$3: inspect $1 does not contain '$2'"
}

native_calls() { wc -l < "$EVID/pam-auth-update.log" | tr -d ' '; }

snapshot_artifacts() { # gate-name
    local d="$EVID/$1"
    mkdir -p "$d"
    cp /etc/pam.d/common-password "$d/" 2>/dev/null
    cp /var/lib/pam/password "$d/" 2>/dev/null
    for slot in fic-password-quality fic-password-history \
                fic-password-history-initial; do
        cp "/etc/pam.d/$slot" "$d/" 2>/dev/null
    done
    cp /var/lib/fic/pam-c2-gate/mutation-journal.json "$d/" 2>/dev/null
    inspect > "$d/inspect.txt" 2>&1
    cp "$EVID/pam-auth-update.log" "$d/" 2>/dev/null
    cp "$EVID/last-apply.txt" "$d/" 2>/dev/null
    cp "$EVID/last-rollback.txt" "$d/" 2>/dev/null
}

shadow_digest() {
    getent shadow "$GATE_USER" | cut -d: -f2 | sha256sum | cut -d' ' -f1
}

strong_password() {
    # Random mixed-case+digits+special shape; verified 6/6 against the REAL
    # stock pwquality+cracklib (the previous hex-suffix shape was flaky:
    # cracklib rejects some hex runs).
    echo "Fg!$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 10)Aa1!"
}

try_change() { # candidate -> rc; REAL self-change via pam_chauthtok
    su -s /bin/sh -c \
        "env FIC_GATE_PW='$1' FIC_GATE_CURRENT='$CURRENT_PW' $PROBE $GATE_USER" \
        "$GATE_USER" > "$EVID/last-probe.txt" 2>&1
}

change_ok() {
    local before after
    before="$(shadow_digest)"
    try_change "$1"
    after="$(shadow_digest)"
    if grep -q '^RESULT ok' "$EVID/last-probe.txt" && \
       [ "$before" != "$after" ]; then
        PREV_PW="$CURRENT_PW"
        CURRENT_PW="$1"
        return 0
    fi
    return 1
}

change_rejected() {
    local before after
    before="$(shadow_digest)"
    try_change "$1"
    after="$(shadow_digest)"
    if grep -q '^RESULT fail' "$EVID/last-probe.txt" && \
       [ "$before" = "$after" ]; then
        return 0
    fi
    return 1
}

weak_password() {
    # PROVEN reliably rejected by the REAL pwquality (cracklib dictionary
    # + class checks), same shape as the executor gate G2-G11. NOTE:
    # 'weakpass' (8 lowercase chars) PASSES Debian 12 pwquality defaults
    # (minlen=8) and would corrupt the password-state chain.
    echo "password1"
}
reused_password() { echo "$PREV_PW"; }

if ! id "$GATE_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/sh "$GATE_USER" || die_environment "gate user failed"
    echo "$GATE_USER:$CURRENT_PW" | chpasswd || \
        die_environment "gate user password failed"
fi
# Production runtime dirs for the daemon journal + configuration intent.
# The packaged default config normally exists; the gate pre-creates an
# empty IDENTITY_ACCESS.conf exactly like a fresh install before the first
# `fic policy enable` (ModuleConfigFileHandler loadConfig requires the
# file).
mkdir -p /opt/fic/config /opt/fic/db /var/lib/fic/pam-c2-gate || \
    die_environment "runtime dirs failed"
[ -f /opt/fic/config/IDENTITY_ACCESS.conf ] || \
    : > /opt/fic/config/IDENTITY_ACCESS.conf

# ------------------------------------------------------------------ gates
# W1: config intent Q -> production coordinator apply -> FicQuality,
# strong accepted, weak rejected.
w1() {
    bootstrap || return
    # Normalize the baseline: the distro container may auto-select the
    # stock pwquality profile on package install; the gate starts from a
    # proven None baseline and re-adds stock deliberately in W8/W9.
    /usr/sbin/pam-auth-update.real --disable pwquality || true
    intent 1 0 || { gate_fail "W1: intent failed"; return; }
    if ! apply_ok "W1"; then return; fi
    require_field success 1 "W1"
    require_inspect topologyClass FicQuality "W1"
    require_inspect ficQualityOwned 1 "W1"
    local pw; pw="$(strong_password)"
    change_ok "$pw" || { gate_fail "W1: strong password rejected"; return; }
    change_rejected "$(weak_password)" || \
        { gate_fail "W1: weak password accepted"; return; }
    snapshot_artifacts W1
    gate_pass "W1"
}

# W2: config intent H -> FicHistoryInitial; a successful change stores the
# previous password in the pwhistory state (the pre-FIC initial password is
# NOT in the history), then the reuse rejection is proven.
w2() {
    intent 0 1 || { gate_fail "W2: intent failed"; return; }
    if ! apply_ok "W2"; then return; fi
    require_inspect topologyClass FicHistoryInitial "W2"
    require_inspect ficHistoryInitialOwned 1 "W2"
    local pw; pw="$(strong_password)"
    change_ok "$pw" || { gate_fail "W2: strong password rejected"; return; }
    change_rejected "$(reused_password)" || \
        { gate_fail "W2: reused password accepted"; return; }
    snapshot_artifacts W2
    gate_pass "W2"
}

# W3: config intent Q+H -> ONE joint transition to Q+H; weak+reuse
# rejected, strong accepted.
w3() {
    intent 1 1 || { gate_fail "W3: intent failed"; return; }
    if ! apply_ok "W3"; then return; fi
    require_inspect topologyClass FicQualityPlusFicHistory "W3"
    require_inspect ficQualityOwned 1 "W3"
    require_inspect ficHistoryOwned 1 "W3"
    change_rejected "$(weak_password)" || \
        { gate_fail "W3: weak password accepted"; return; }
    change_rejected "$(reused_password)" || \
        { gate_fail "W3: reused password accepted"; return; }
    local pw; pw="$(strong_password)"
    change_ok "$pw" || { gate_fail "W3: strong password rejected"; return; }
    change_rejected "$(reused_password)" || \
        { gate_fail "W3: reuse after change accepted"; return; }
    snapshot_artifacts W3
    gate_pass "W3"
}

# W4: idempotent reapply (a fresh driver process = daemon restart
# semantics): proven state -> success, NO native mutation, no new Applied
# ownership.
w4() {
    local before after
    before="$(native_calls)"
    if ! apply_ok "W4"; then return; fi
    after="$(native_calls)"
    require_field changedSystemState 0 "W4"
    [ "$before" = "$after" ] || \
        gate_fail "W4: idempotent reapply invoked pam-auth-update"
    require_inspect topologyClass FicQualityPlusFicHistory "W4"
    snapshot_artifacts W4
    gate_pass "W4"
}

# W5: rollback of the quality domain while history stays requested:
# variant switch through the planner (H-only survives, FIC quality
# released, journal provenance RolledBack).
w5() {
    rollback_policy enable_password_quality || {
        gate_fail "W5: rollback failed: $(cat "$EVID/last-rollback.txt" | tr '\n' ' ')"
        return
    }
    grep -q "state=Released" "$EVID/last-rollback.txt" || \
        { gate_fail "W5: quality record not Released"; return; }
    require_inspect topologyClass FicHistoryInitial "W5"
    require_inspect ficQualityOwned 0 "W5"
    require_inspect ficHistoryInitialOwned 1 "W5"
    change_rejected "$(reused_password)" || \
        { gate_fail "W5: history lost after the quality release"; return; }
    snapshot_artifacts W5
    gate_pass "W5"
}

# W6: release the surviving history domain -> None, all slots Neutral.
w6() {
    intent 0 0 || { gate_fail "W6: intent failed"; return; }
    rollback_policy enable_password_history || \
        { gate_fail "W6: rollback failed"; return; }
    grep -q "state=Released" "$EVID/last-rollback.txt" || \
        { gate_fail "W6: history record not Released"; return; }
    require_inspect topologyClass None "W6"
    require_inspect qualitySlotState Neutral "W6"
    require_inspect historySlotState Neutral "W6"
    require_inspect historyInitialSlotState Neutral "W6"
    local pw; pw="$(strong_password)"
    change_ok "$pw" || { gate_fail "W6: password change broken at None"; return; }
    snapshot_artifacts W6
    gate_pass "W6"
}

# W7: re-request Q+H -> the planner performs the variant switch
# DetachInitial -> AttachQuality -> AttachConsumer.
w7() {
    intent 1 1 || { gate_fail "W7: intent failed"; return; }
    if ! apply_ok "W7"; then return; fi
    require_inspect topologyClass FicQualityPlusFicHistory "W7"
    require_inspect ficQualityOwned 1 "W7"
    require_inspect ficHistoryOwned 1 "W7"
    change_rejected "$(weak_password)" || \
        { gate_fail "W7: weak password accepted"; return; }
    snapshot_artifacts W7
    gate_pass "W7"
}

# W8: foreign stock pwquality pre-existing satisfies the quality
# capability: no FIC quality attach, no FIC ownership, stock semantics
# enforced. The rollback backend has nothing FIC-owned to release.
w8() {
    intent 0 0 || { gate_fail "W8: intent failed"; return; }
    apply_topology || true
    /usr/sbin/pam-auth-update.real --enable pwquality || \
        die_environment "stock pwquality enable failed"
    intent 1 0 || { gate_fail "W8: intent failed"; return; }
    if ! apply_ok "W8"; then return; fi
    require_inspect topologyClass ForeignQuality "W8"
    require_inspect ficQualityOwned 0 "W8"
    change_rejected "$(weak_password)" || \
        { gate_fail "W8: stock pwquality not enforcing"; return; }
    local pw; pw="$(strong_password)"
    change_ok "$pw" || { gate_fail "W8: strong password rejected"; return; }
    rollback_policy enable_password_quality > "$EVID/last-rollback.txt" 2>&1
    grep -qE "NothingToDo|AlreadyReleased" "$EVID/last-rollback.txt" || \
        gate_fail "W8: rollback touched the foreign producer"
    snapshot_artifacts W8
    gate_pass "W8"
}

# W9: foreign stock pwquality added DURING FIC activity: the quality
# rollback removes ONLY the FIC-owned attach; the stock producer remains
# and keeps enforcing (final semantic topology = ForeignQuality).
w9() {
    /usr/sbin/pam-auth-update.real --disable pwquality || \
        die_environment "stock pwquality disable failed"
    intent 1 0 || { gate_fail "W9: intent failed"; return; }
    if ! apply_ok "W9"; then return; fi
    require_inspect topologyClass FicQuality "W9"
    require_inspect ficQualityOwned 1 "W9"
    /usr/sbin/pam-auth-update.real --enable pwquality || \
        die_environment "stock pwquality enable failed"
    rollback_policy enable_password_quality > "$EVID/last-rollback.txt" 2>&1 \
        || { gate_fail "W9: rollback failed"; return; }
    grep -q "state=Released" "$EVID/last-rollback.txt" || \
        { gate_fail "W9: FIC quality not released"; return; }
    require_inspect topologyClass ForeignQuality "W9"
    require_inspect ficQualityOwned 0 "W9"
    change_rejected "$(weak_password)" || \
        { gate_fail "W9: stock pwquality lost after the FIC release"; return; }
    snapshot_artifacts W9
    gate_pass "W9"
}

w1
w2
w3
w4
w5
w6
w7
w8
w9

if [ "$FAILED" -eq 0 ]; then
    verdict "C2 PRODUCTION WIRING GATE: PASS"
else
    verdict "C2 PRODUCTION WIRING GATE: FAIL"
fi
exit "$FAILED"



