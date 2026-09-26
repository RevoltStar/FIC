#!/bin/bash
# C2 REAL functional gate (G1-G11): exercises the production C2 password
# topology executor against the REAL pam-auth-update + PAM stack inside a
# DISPOSABLE container as root.
#
# Run (never on a host):
#   docker run --rm -v "$PWD":/src:ro debian:12 \
#       bash /src/tests/integration/pam-c2/pam_c2_gate.sh
#   docker run --rm -v "$PWD":/src:ro ubuntu:24.04 \
#       bash /src/tests/integration/pam-c2/pam_c2_gate.sh
#
# Evidence: /tmp/fic-gate-evidence/ (pam state, generated stack, slots,
# journal, pam-auth-update invocation log, functional probe results,
# shadow hash digests). Real passwords are never stored.
set -u

REPO="${GATE_REPO:-/src}"
GATE_DIR="$REPO/tests/integration/pam-c2"
EVID=/tmp/fic-gate-evidence
GATE_USER=ficgate
DRIVER=/tmp/fic-gate-bin/fic-pam-c2-gate-driver
PROBE=/tmp/fic-gate-bin/fic-pam-probe
FAILED=0
# NOTE: passwords must NOT contain the gate user's login name (ficgate):
# pwquality usercheck rejects passwords containing it.
CURRENT_PW='Init!2026#GateXx'
PREV_PW='Init!2026#GateXx'

mkdir -p "$EVID"

verdict() { echo "$1" | tee -a "$EVID/verdicts.txt"; }
gate_pass() { verdict "PASS $1"; }
gate_fail() { verdict "FAIL $1"; FAILED=1; }
note() { echo "[gate] $*"; }

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
# The gate network path may be flaky (proxied): retry the install; apt
# keeps already-downloaded .debs, so retries make forward progress.
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

# Install the EXACT current FIC payload pam-configs (production files, no
# synthetic profiles) into the container profile database.
cp "$REPO"/packaging/deb/pam-configs/fic-password-quality-hook \
   "$REPO"/packaging/deb/pam-configs/fic-password-history-hook \
   "$REPO"/packaging/deb/pam-configs/fic-password-history-initial-hook \
   /usr/share/pam-configs/ || die_environment "FIC pam-configs install failed"
command -v chpasswd >/dev/null || die_environment "chpasswd missing"

have_pam_module() { # module.so -> echoes found path
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

# cracklib runtime dictionary (v6 harness lesson: without it even the
# stock pwquality oracle is invalid).
if [ ! -f /var/cache/cracklib/cracklib_dict.pwd ]; then
    create-cracklib-dict /usr/share/dict/words > /dev/null 2>&1 || \
        die_environment "cracklib dictionary cannot be created"
fi
[ -f /var/cache/cracklib/cracklib_dict.pwd ] || \
    die_environment "cracklib dictionary missing"

# The functional probe runs as root: stock pwquality ignores quality for
# root unless enforce_for_root is set (distro default: off). Without it
# even the stock pwquality oracle would be invalid.
if [ -f /etc/security/pwquality.conf ] && \
   ! grep -q '^enforce_for_root' /etc/security/pwquality.conf; then
    echo 'enforce_for_root' >> /etc/security/pwquality.conf
fi

# Build the gate driver + probe from the EXACT repo sources.
mkdir -p /tmp/fic-gate-bin
gcc -O2 -Wall -o "$PROBE" "$GATE_DIR/fic_pam_probe.c" -lpam || \
    die_environment "probe build failed"
# The probe is executed AS the gate user (setuid root, the same model as
# passwd(1)): real uid != 0 makes pam_pwhistory and pam_pwquality enforce
# for the change, while euid 0 lets the stack access shadow/opasswd.
chown root:root "$PROBE"
chmod 4755 "$PROBE"
GATE_PLATFORM="$(
    case "$(. /etc/os-release && echo "$ID-$VERSION_ID")" in
        debian-12)    echo debian-12 ;;
        debian-13)    echo debian-13 ;;
        ubuntu-24.04) echo ubuntu-24.04 ;;
        ubuntu-26.04) echo ubuntu-26.04 ;;
        *) die_environment "unsupported distro for the C2 gate" ;;
    esac
)"
cmake -S "$REPO" -B /tmp/fic-gate-build \
    -DCMAKE_BUILD_TYPE=Release \
    -DFIC_TARGET_PLATFORM="$GATE_PLATFORM" \
    > "$EVID/cmake-configure.log" 2>&1 || \
    die_environment "cmake configure failed"
cmake --build /tmp/fic-gate-build --target fic-pam-c2-gate-driver -j2 \
    > "$EVID/cmake-build.log" 2>&1 || die_environment "driver build failed"
DRIVER_BIN="$(find /tmp/fic-gate-build -name fic-pam-c2-gate-driver -type f | head -1)"
[ -n "$DRIVER_BIN" ] || die_environment "driver binary not found"
cp "$DRIVER_BIN" /tmp/fic-gate-bin/fic-pam-c2-gate-driver

# Stock-only oracle reference topology (for the G8 structural match).
cp /etc/pam.d/common-password "$EVID/stock-baseline-common-password"

# pam-auth-update wrapper: traces every invocation (one profile per
# invocation assertion) and optionally injects ONE native failure.
PAU=/usr/sbin/pam-auth-update
if [ ! -f "$PAU.real" ]; then
    mv "$PAU" "$PAU.real"
    cat > "$PAU" <<'WRAPPER'
#!/bin/sh
echo "$*" >> /tmp/fic-gate-evidence/pam-auth-update.log
if [ "$#" -ne 2 ]; then
    echo "GATE-WRAPPER: expected exactly one profile per invocation, got: $*" >&2
    exit 43
fi
if [ -f /tmp/fic-gate-evidence/inject-native-failure ]; then
    rm -f /tmp/fic-gate-evidence/inject-native-failure
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

inspect() {
    "$DRIVER" inspect
}

transition() { # quality history
    "$DRIVER" transition "$1" "$2" > "$EVID/last-transition.txt" 2>&1
}

require_field() { # file key expected_value gate
    local actual
    actual="$(grep -E "^$2=" "$1" | head -1 | cut -d= -f2-)"
    if [ "$actual" = "$3" ]; then
        return 0
    fi
    gate_fail "$4: $2 expected '$3', got '$actual'"
    return 1
}

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
}

shadow_digest() {
    getent shadow "$GATE_USER" | cut -d: -f2 | sha256sum | cut -d' ' -f1
}

strong_password() { # unique per phase
    echo "Fg!$(date +%s%N | sha256sum | head -c 12)qW7z"
}

try_change() { # candidate -> rc; REAL self-change via pam_chauthtok
    # Executed AS the gate user (setuid probe): getuid != 0 makes
    # pam_pwhistory/pam_pwquality enforce the checks.
    su -s /bin/sh -c \
        "env FIC_GATE_PW='$1' FIC_GATE_CURRENT='$CURRENT_PW' $PROBE $GATE_USER" \
        "$GATE_USER" > "$EVID/last-probe.txt" 2>&1
}

change_ok() { # proves the shadow hash actually changes
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

change_rejected() { # proves the shadow hash does NOT change
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

# ------------------------------------------------------------------ gates
# G1: None baseline — no FIC profiles, all slots Neutral, password change
# works through the untouched stack.
g1() {
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then
        CURRENT_PW="$pw"
    else
        gate_fail "G1: baseline password change failed"
        return
    fi
    snapshot_artifacts G1
    gate_pass "G1"
}

# G2: None -> Quality: physical proof + strong/weak semantics + disable
# back to None.
g2() {
    transition 1 0 || { gate_fail "G2: transition to Quality failed: $(cat "$EVID/last-transition.txt")"; return; }
    local s; s="$EVID/last-transition.txt"
    require_field "$s" success 1 G2 || true
    local i; i="$(inspect)"
    echo "$i" > "$EVID/g2-inspect.txt"
    require_field "$EVID/g2-inspect.txt" ficQualitySelected 1 G2 || true
    require_field "$EVID/g2-inspect.txt" qualitySlotState Active G2 || true
    require_field "$EVID/g2-inspect.txt" historySlotState Neutral G2 || true
    require_field "$EVID/g2-inspect.txt" historyInitialSlotState Neutral G2 || true
    require_field "$EVID/g2-inspect.txt" ficQualityOwned 1 G2 || true
    grep -qE '^password[[:space:]]+include[[:space:]]+fic-password-quality[[:space:]]*$' \
        /etc/pam.d/common-password || \
        gate_fail "G2: quality include line missing (exact grammar)"
    local qline uline
    qline="$(grep -nE 'include[[:space:]]+fic-password-quality' /etc/pam.d/common-password | cut -d: -f1)"
    uline="$(grep -n 'pam_unix.so' /etc/pam.d/common-password | cut -d: -f1)"
    [ -n "$qline" ] && [ -n "$uline" ] && [ "$qline" -lt "$uline" ] || \
        gate_fail "G2: quality include is not before pam_unix"
    grep 'pam_unix.so' /etc/pam.d/common-password | grep -q 'use_authtok' || \
        gate_fail "G2: pam_unix is not in consumer form"
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then CURRENT_PW="$pw"; else
        gate_fail "G2: strong password change failed"; fi
    if change_rejected 'password1'; then :; else
        gate_fail "G2: weak password was NOT rejected"; fi
    snapshot_artifacts G2
    transition 0 0 || { gate_fail "G2: disable back to None failed: $(cat "$EVID/last-transition.txt")"; return; }
    i="$(inspect)"; echo "$i" > "$EVID/g2b-inspect.txt"
    require_field "$EVID/g2b-inspect.txt" ficQualitySelected 0 G2 || true
    require_field "$EVID/g2b-inspect.txt" qualitySlotState Neutral G2 || true
    require_field "$EVID/g2b-inspect.txt" topologyClass None G2 || true
    pw="$(strong_password)"
    if change_ok "$pw"; then CURRENT_PW="$pw"; else
        gate_fail "G2: baseline functional path broken after disable"; fi
    snapshot_artifacts G2-disabled
    gate_pass "G2"
}

# G3: None -> History-only: initial producer slot + reuse rejection.
g3() {
    transition 0 1 || { gate_fail "G3: transition to History-only failed: $(cat "$EVID/last-transition.txt")"; return; }
    local i; i="$(inspect)"; echo "$i" > "$EVID/g3-inspect.txt"
    require_field "$EVID/g3-inspect.txt" ficHistoryInitialSelected 1 G3 || true
    require_field "$EVID/g3-inspect.txt" historyInitialSlotState Active G3 || true
    require_field "$EVID/g3-inspect.txt" ficHistorySelected 0 G3 || true
    grep -qE 'include[[:space:]]+fic-password-history-initial' \
        /etc/pam.d/common-password || \
        gate_fail "G3: history-initial include missing"
    grep 'pam_unix.so' /etc/pam.d/common-password | grep -q 'use_authtok' || \
        gate_fail "G3: pam_unix is not in consumer form"
    local hline uline
    hline="$(grep -nE 'include[[:space:]]+fic-password-history-initial' /etc/pam.d/common-password | cut -d: -f1)"
    uline="$(grep -n 'pam_unix.so' /etc/pam.d/common-password | cut -d: -f1)"
    [ "$hline" -lt "$uline" ] || \
        gate_fail "G3: history-initial is not before pam_unix"
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then :; else
        gate_fail "G3: normal password change failed under history-only"; fi
    # Reuse of the PREVIOUS password must be rejected (remember=3).
    if change_rejected "$PREV_PW"; then :; else
        gate_fail "G3: password reuse was NOT rejected"; fi
    snapshot_artifacts G3
    transition 0 0 || { gate_fail "G3: disable to None failed"; return; }
    i="$(inspect)"; echo "$i" > "$EVID/g3b-inspect.txt"
    require_field "$EVID/g3b-inspect.txt" topologyClass None G3 || true
    require_field "$EVID/g3b-inspect.txt" historyInitialSlotState Neutral G3 || true
    pw="$(strong_password)"
    if change_ok "$pw"; then CURRENT_PW="$pw"; else
        gate_fail "G3: baseline broken after disable"; fi
    snapshot_artifacts G3-disabled
    gate_pass "G3"
}

# G4: None -> Quality+History: strong accepted, weak rejected, reuse
# rejected.
g4() {
    transition 1 1 || { gate_fail "G4: transition to Q+H failed: $(cat "$EVID/last-transition.txt")"; return; }
    local i; i="$(inspect)"; echo "$i" > "$EVID/g4-inspect.txt"
    require_field "$EVID/g4-inspect.txt" topologyClass FicQualityPlusFicHistory G4 || true
    local qline hline uline
    qline="$(grep -nE 'include[[:space:]]+fic-password-quality' /etc/pam.d/common-password | cut -d: -f1)"
    hline="$(grep -nE 'include[[:space:]]+fic-password-history[[:space:]]' /etc/pam.d/common-password | cut -d: -f1)"
    uline="$(grep -nE 'pam_unix\.so[[:space:]].*use_authtok' /etc/pam.d/common-password | cut -d: -f1)"
    [ -n "$qline" ] && [ -n "$hline" ] && [ "$qline" -lt "$hline" ] && \
        [ "$hline" -lt "$uline" ] || \
        gate_fail "G4: ordering quality < history < pam_unix violated"
    grep -qE 'include[[:space:]]+fic-password-history-initial' \
        /etc/pam.d/common-password && \
        gate_fail "G4: history-initial must be absent in Q+H"
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then :; else
        gate_fail "G4: strong change failed under Q+H"; fi
    change_rejected 'password1' || gate_fail "G4: weak NOT rejected"
    if change_rejected "$PREV_PW"; then :; else
        gate_fail "G4: reuse NOT rejected"; fi
    snapshot_artifacts G4
    gate_pass "G4"
}

# G5: Q+H -> H-only: consumer detach, quality detach, initial attach.
g5() {
    transition 0 1 || { gate_fail "G5: Q+H -> H-only failed: $(cat "$EVID/last-transition.txt")"; return; }
    local s; s="$EVID/last-transition.txt"
    local actions
    actions="$(grep '^executedActions=' "$s" | cut -d= -f2-)"
    echo "$actions" | grep -q 'fic-password-history-hook,' || \
        gate_fail "G5: consumer detach action missing"
    echo "$actions" | grep -q 'fic-password-quality-hook,' || \
        gate_fail "G5: quality detach action missing"
    echo "$actions" | grep -q 'fic-password-history-initial-hook,' || \
        gate_fail "G5: initial attach action missing"
    local i; i="$(inspect)"; echo "$i" > "$EVID/g5-inspect.txt"
    require_field "$EVID/g5-inspect.txt" topologyClass FicHistoryInitial G5 || true
    # History enforcement must survive the switch: the previous password
    # is still remembered.
    if change_rejected "$PREV_PW"; then :; else
        gate_fail "G5: history enforcement lost after switch"; fi
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then :; else
        gate_fail "G5: normal change failed under H-only"; fi
    snapshot_artifacts G5
    gate_pass "G5"
}

# G6: H-only -> Q+H: initial detach, quality attach, consumer attach.
g6() {
    transition 1 1 || { gate_fail "G6: H-only -> Q+H failed: $(cat "$EVID/last-transition.txt")"; return; }
    local i; i="$(inspect)"; echo "$i" > "$EVID/g6-inspect.txt"
    require_field "$EVID/g6-inspect.txt" topologyClass FicQualityPlusFicHistory G6 || true
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then :; else
        gate_fail "G6: strong change failed"; fi
    change_rejected 'password1' || gate_fail "G6: weak NOT rejected"
    if change_rejected "$PREV_PW"; then :; else
        gate_fail "G6: reuse NOT rejected"; fi
    snapshot_artifacts G6
    gate_pass "G6"
}

# Stock pwquality oracle (§12): the environment is only valid for
# functional verdicts if stock pwquality itself accepts strong and
# rejects weak passwords.
stock_pwquality_oracle() {
    ls /usr/share/pam-configs/pwquality >/dev/null 2>&1 || \
        die_environment "stock pwquality profile missing"
    pam-auth-update --enable pwquality || \
        die_environment "stock pwquality profile cannot be selected"
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then CURRENT_PW="$pw"; else
        die_environment "stock pwquality oracle: strong change FAILED"
    fi
    if change_rejected 'password1'; then :; else
        die_environment "stock pwquality oracle: weak NOT rejected"
    fi
    # Reference topology for the G8 structural match.
    cp /etc/pam.d/common-password \
        "$EVID/stock-only-with-pwquality-common-password"
    note "stock pwquality oracle: PASS (strong ok, weak rejected)"
}

# G7: foreign stock pwquality pre-existing.
g7() {
    transition 0 0 || die_environment "cannot return to None before G7"
    stock_pwquality_oracle
    transition 1 0 || { gate_fail "G7: transition (Q=true) failed: $(cat "$EVID/last-transition.txt")"; return; }
    local i; i="$(inspect)"; echo "$i" > "$EVID/g7a-inspect.txt"
    require_field "$EVID/g7a-inspect.txt" topologyClass ForeignQuality G7 || true
    require_field "$EVID/g7a-inspect.txt" ficQualitySelected 0 G7 || true
    require_field "$EVID/g7a-inspect.txt" ficQualityOwned 0 G7 || true
    require_field "$EVID/g7a-inspect.txt" qualitySlotState Neutral G7 || true
    require_field "$EVID/g7a-inspect.txt" foreignQualityProducer 1 G7 || true
    grep -q 'include fic-password-quality' /etc/pam.d/common-password && \
        gate_fail "G7: FIC quality hook must NOT be selected"
    grep -q 'pam_pwquality.so' /etc/pam.d/common-password || \
        gate_fail "G7: stock pwquality rule vanished"
    change_rejected 'password1' || gate_fail "G7: weak NOT rejected under foreign"
    transition 1 1 || { gate_fail "G7: transition (Q+H) failed: $(cat "$EVID/last-transition.txt")"; return; }
    i="$(inspect)"; echo "$i" > "$EVID/g7b-inspect.txt"
    require_field "$EVID/g7b-inspect.txt" topologyClass ForeignQualityPlusFicHistory G7 || true
    require_field "$EVID/g7b-inspect.txt" foreignQualityProducer 1 G7 || true
    grep -qE 'include[[:space:]]+fic-password-history[[:space:]]' /etc/pam.d/common-password || \
        gate_fail "G7: FIC history consumer missing"
    if change_rejected "$PREV_PW"; then :; else
        gate_fail "G7: reuse NOT rejected under foreign+history"; fi
    change_rejected 'password1' || gate_fail "G7: weak NOT rejected"
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then :; else
        gate_fail "G7: strong change failed under foreign+history"; fi
    transition 1 0 || { gate_fail "G7: FIC history disable failed"; return; }
    i="$(inspect)"; echo "$i" > "$EVID/g7c-inspect.txt"
    require_field "$EVID/g7c-inspect.txt" topologyClass ForeignQuality G7 || true
    grep -q 'pam_pwquality.so' /etc/pam.d/common-password || \
        gate_fail "G7: stock pwquality lost after FIC disable"
    grep -qE 'include[[:space:]]+fic-password-history[[:space:]]' /etc/pam.d/common-password && \
        gate_fail "G7: FIC history include still present"
    snapshot_artifacts G7
    gate_pass "G7"
}

# G8: foreign stock pwquality appears WHILE FIC quality is active; the
# FIC disable removes ONLY the FIC-owned selection.
g8() {
    transition 0 0 || die_environment "cannot return to None before G8"
    pam-auth-update --disable pwquality || \
        die_environment "stock pwquality cannot be deselected"
    transition 1 0 || die_environment "cannot activate FIC quality before G8"
    pam-auth-update --enable pwquality || \
        die_environment "external stock pwquality enable failed"
    transition 0 0 || { gate_fail "G8: FIC disable with foreign failed: $(cat "$EVID/last-transition.txt")"; return; }
    local i; i="$(inspect)"; echo "$i" > "$EVID/g8-inspect.txt"
    require_field "$EVID/g8-inspect.txt" ficQualitySelected 0 G8 || true
    require_field "$EVID/g8-inspect.txt" qualitySlotState Neutral G8 || true
    require_field "$EVID/g8-inspect.txt" foreignQualityProducer 1 G8 || true
    require_field "$EVID/g8-inspect.txt" ficQualityOwned 0 G8 || true
    grep -q 'include fic-password-quality' /etc/pam.d/common-password && \
        gate_fail "G8: FIC quality include still present"
    grep -q 'pam_pwquality.so' /etc/pam.d/common-password || \
        gate_fail "G8: stock pwquality rule not preserved"
    change_rejected 'password1' || gate_fail "G8: weak NOT rejected (stock must enforce)"
    grep -E '^password ' "$EVID/stock-only-with-pwquality-common-password" | \
        sed 's/ $//' | sort > /tmp/g8-expected
    grep -E '^password ' /etc/pam.d/common-password | \
        sed 's/ $//' | sort > /tmp/g8-actual
    if diff -q /tmp/g8-expected /tmp/g8-actual > /dev/null; then :; else
        gate_fail "G8: final topology differs from the stock-only oracle"
        diff /tmp/g8-expected /tmp/g8-actual \
            > "$EVID/g8-structural-diff.txt" 2>&1
    fi
    snapshot_artifacts G8
    gate_pass "G8"
}

# G9: trailing whitespace proof — the REAL pam-auth-update generates
# include lines with a trailing space (captured at G4 in the Q+H state)
# and the C++ resulting-state proofs accepted them (every transition
# above proved this exact grammar).
g9() {
    local f="$EVID/G4/common-password"
    if [ ! -f "$f" ]; then
        gate_fail "G9: no Q+H stack artifact captured"
        return
    fi
    cat -A "$f" > "$EVID/g9-common-password-cat-A.txt"
    grep -E 'include[[:space:]]+fic-password-quality' "$f" | \
        grep -q ' $' || \
        gate_fail "G9: quality include line lacks the trailing space"
    grep -E 'include[[:space:]]+fic-password-history[[:space:]]' "$f" | \
        grep -q ' $' || \
        gate_fail "G9: history include line lacks the trailing space"
    note "G9: real grammar proof: trailing-space include lines accepted"
    snapshot_artifacts G9
    gate_pass "G9"
}

# G10: one-profile-per-invocation.
g10() {
    mkdir -p "$EVID/G10"
    if awk 'NF != 2 { bad = 1 } END { exit bad ? 1 : 0 }' \
        "$EVID/pam-auth-update.log"; then
        :
    else
        gate_fail "G10: multi-profile pam-auth-update invocation detected"
    fi
    cp "$EVID/pam-auth-update.log" "$EVID/G10/"
    gate_pass "G10"
}

# G11: real native failure probe.
g11() {
    transition 0 0 || die_environment "cannot return to None before G11"
    # The failure probe needs a clean FIC attach: drop the foreign stock
    # producer left by G8, otherwise requesting quality is a proven no-op.
    pam-auth-update --disable pwquality || \
        die_environment "cannot drop the foreign producer before G11"
    touch "$EVID/inject-native-failure"
    if transition 1 0; then
        gate_fail "G11: transition unexpectedly succeeded despite the native failure"
    fi
    local s; s="$EVID/last-transition.txt"
    require_field "$s" compensated 1 G11 || true
    require_field "$s" compensatedStateProven 1 G11 || true
    grep -q 'NOT proven restored' "$s" && \
        gate_fail "G11: compensation should have proven the restoration"
    local i; i="$(inspect)"; echo "$i" > "$EVID/g11-inspect.txt"
    require_field "$EVID/g11-inspect.txt" qualitySlotState Neutral G11 || true
    require_field "$EVID/g11-inspect.txt" ficQualitySelected 0 G11 || true
    local pw; pw="$(strong_password)"
    if change_ok "$pw"; then CURRENT_PW="$pw"; else
        gate_fail "G11: PAM password path broken after compensation"; fi
    transition 1 0 || { gate_fail "G11: recovery transition failed"; return; }
    i="$(inspect)"; echo "$i" > "$EVID/g11b-inspect.txt"
    require_field "$EVID/g11b-inspect.txt" topologyClass FicQuality G11 || true
    pw="$(strong_password)"
    if change_ok "$pw"; then CURRENT_PW="$pw"; else
        gate_fail "G11: strong change failed after recovery"; fi
    change_rejected 'password1' || gate_fail "G11: weak NOT rejected after recovery"
    snapshot_artifacts G11
    gate_pass "G11"
}

# ------------------------------------------------------------------ main
if id "$GATE_USER" >/dev/null 2>&1; then
    die_environment "user $GATE_USER already exists"
fi
useradd -m -s /bin/sh "$GATE_USER" || die_environment "useradd failed"
bootstrap
note "managed slots bootstrapped"

# Provision the initial password as root (the user has no password yet;
# every later change runs as the user through the full PAM stack).
FIC_GATE_PW="$CURRENT_PW" "$PROBE" "$GATE_USER" \
    > "$EVID/initial-probe.txt" 2>&1 || \
    die_environment "initial password provisioning failed: $(cat "$EVID/initial-probe.txt")"

g1
stock_pwquality_oracle
pam-auth-update --disable pwquality || \
    die_environment "oracle cleanup failed"
g2
g3
g4
g5
g6
g7
g8
g9
g10
g11

if [ "$FAILED" -eq 0 ]; then
    verdict "C2 REAL FUNCTIONAL GATE: PASS ($DISTRO)"
else
    verdict "C2 REAL FUNCTIONAL GATE: FAIL ($DISTRO)"
fi
cat "$EVID/verdicts.txt"
exit "$FAILED"
