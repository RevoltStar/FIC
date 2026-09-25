#!/bin/sh
# FIC Step 5C architecture gate: disposable-environment proof that selecting
# the permanent FIC password hook profiles (Password-Type: Primary) on top of
# NEUTRAL managed slots does not change the password stack in a way that
# breaks the normal password-changing PAM path, and that the exact
# pam-auth-update grammar assumed by the resulting-state proofs is real.
#
# STATUS (Step 5C architecture gate, Debian 12 + Ubuntu 24.04, 2026-09):
# FAILED for the shipped payload (comment-only neutral slots, priorities
# 1024/1023). With either hook selected, pam-auth-update pushes pam_unix out
# of Primary modpos 0, so unix switches from its token-producing
# Password-Initial variant ("obscure yescrypt") to the consuming
# Password variant ("use_authtok try_first_pass"); a comment-only include
# target provides no token producer and the real PAM password change
# (chpasswd) fails with "Authentication token manipulation error" until the
# hooks are detached. A low-priority payload variant fails differently:
# comment-only includes expand to zero PAM handlers while the generated
# [success=N] jump counts them, overshooting past pam_permit. See
# docs/HANDOFF.md. Do not implement the Step 5C production attach until the
# payload topology decision is made.
#
# Run INSIDE a disposable Debian 12 / Ubuntu 24.04 container as root:
#
#   podman run --rm -v "$PWD":/src:ro debian:12 \
#       sh /src/tests/integration/packaging/PamArchitectureGate.sh
#
# The gate never touches the host: everything happens in the container
# (test user, /var/lib/pam, /etc/pam.d). Every phase leaves evidence files
# in /tmp/fic-gate-evidence.
set -u

REPO="${GATE_REPO:-/src}"
EVID=/tmp/fic-gate-evidence
TEST_USER=ficgate
TEST_PASSWORD_BASE='FicGate!2026'
FAILED=0

pass() { echo "[gate][PASS] $*"; }
fail() { echo "[gate][FAIL] $*" >&2; FAILED=1; }
note() { echo "[gate] $*"; }

if [ "$(id -u)" != "0" ]; then
    echo "[gate] must run as root inside a disposable container" >&2
    exit 2
fi
for tool in pam-auth-update passwd useradd script userdel; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[gate] missing required tool: $tool" >&2
        exit 2
    }
done
for payload in \
    "$REPO/packaging/deb/pam-configs/fic-password-quality-hook" \
    "$REPO/packaging/deb/pam-configs/fic-password-history-hook" \
    "$REPO/packaging/deb/pam-slots/fic-password-quality" \
    "$REPO/packaging/deb/pam-slots/fic-password-history" \
    "$REPO/packaging/deb/pam-slots/fic-password-history-initial"; do
    [ -f "$payload" ] || {
        echo "[gate] missing package payload: $payload" >&2
        exit 2
    }
done

export DEBIAN_FRONTEND=noninteractive
mkdir -p "$EVID"

shadow_hash() {
    grep "^$1:" /etc/shadow | cut -d: -f2
}

CHANGE_SEQUENCE=0
change_password() {
    # Real PAM password-changing path: the PAM service "chpasswd"
    # (@include common-password) driven non-interactively. Every phase uses
    # a UNIQUE password: re-setting the identical password makes pam_unix
    # refuse the change ("Password unchanged") independently of the hook
    # topology, which would mask the gate signal.
    CHANGE_SEQUENCE=$((CHANGE_SEQUENCE + 1))
    candidate="${TEST_PASSWORD_BASE}${CHANGE_SEQUENCE}x"
    printf '%s:%s\n' "$TEST_USER" "$candidate" | chpasswd
}

prove_password_change() {
    phase="$1"
    before=$(shadow_hash "$TEST_USER")
    if ! change_password; then
        fail "$phase: PAM password change (chpasswd) failed"
        return 1
    fi
    after=$(shadow_hash "$TEST_USER")
    if [ -z "$after" ] || [ "$after" = "$before" ]; then
        fail "$phase: PAM password change did not update the authentication token"
        return 1
    fi
    pass "$phase: PAM password change works and updates the token"
    return 0
}

# Control experiment: prove the probe is actually sensitive to the PAM
# password topology (a dangling include target must fail the change), so a
# PASS below can never be a false negative caused by a PAM-blind probe.
# The gate runs inside a disposable container, so editing the generated
# stack here is a diagnostic, not a production mechanism.
prove_probe_sensitivity() {
    stack=/etc/pam.d/common-password
    cp "$stack" "$EVID/probe-control.common-password"
    printf 'password include fic-gate-probe-missing-target\n' >> "$stack"
    if change_password >/dev/null 2>&1; then
        fail "probe control: password change unexpectedly succeeded with a dangling include target (the probe is PAM-blind; gate invalid)"
    else
        pass "probe control: dangling include target fails the password change (probe is topology-sensitive)"
    fi
    cp "$EVID/probe-control.common-password" "$stack"
}

snapshot_state() {
    cp /var/lib/pam/password "$EVID/$1.var-lib-pam-password" 2>/dev/null
    cp /etc/pam.d/common-password "$EVID/$1.common-password" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
note "platform: $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release)"
snapshot_state baseline
note "baseline password state:"
sed 's/^/[gate]   /' "$EVID/baseline.var-lib-pam-password" 2>/dev/null
note "baseline generated common-password:"
sed 's/^/[gate]   /' "$EVID/baseline.common-password"

userdel -r "$TEST_USER" >/dev/null 2>&1 || true
if ! useradd -m "$TEST_USER"; then
    echo "[gate] cannot create the disposable test user" >&2
    exit 2
fi
prove_password_change "baseline" || true
prove_probe_sensitivity

# All hook payloads are installed package-like upfront; the phases then
# exercise the exact single-profile enable sequences and capture the REAL
# generated grammar for every selection state.
cp "$REPO/packaging/deb/pam-configs/fic-password-quality-hook" \
    /usr/share/pam-configs/fic-password-quality-hook
cp "$REPO/packaging/deb/pam-configs/fic-password-history-hook" \
    /usr/share/pam-configs/fic-password-history-hook
cp "$REPO/packaging/deb/pam-slots/fic-password-quality" \
    /etc/pam.d/fic-password-quality
cp "$REPO/packaging/deb/pam-slots/fic-password-history" \
    /etc/pam.d/fic-password-history
cp "$REPO/packaging/deb/pam-slots/fic-password-history-initial" \
    /etc/pam.d/fic-password-history-initial

# Phase 1: history hook selected ALONE (Q0=0/H0=1 pre-existing state).
# Confirmed real grammar (Debian 12 + Ubuntu 24.04): the stack is split,
# the state file records the profile with the INITIAL include, and the
# generated stack carries ONLY the initial include of the history hook.
if pam-auth-update --enable fic-password-history-hook; then
    pass "history-alone: single-profile pam-auth-update --enable rc=0"
else
    fail "history-alone: pam-auth-update --enable rc!=0"
fi
snapshot_state history-alone
note "password state (history alone):"
sed 's/^/[gate]   /' "$EVID/history-alone.var-lib-pam-password"
note "generated common-password (history alone):"
sed 's/^/[gate]   /' "$EVID/history-alone.common-password"
grep -q "^Module: fic-password-history-hook$" /var/lib/pam/password &&
    pass "history-alone: exact selection record" ||
    fail "history-alone: exact selection record missing"
grep -Eq "^password[[:space:]]+include[[:space:]]+fic-password-history-initial[[:space:]]*$" \
    /etc/pam.d/common-password &&
    pass "history-alone: split-stack initial include generated" ||
    fail "history-alone: split-stack initial include missing"
prove_password_change "history-alone"

# Phase 2: quality hook enabled on top (Step 5C attach order, Q0=1/H0=1).
# Confirmed real grammar: the split collapses; BOTH hooks prove attached
# through the exact Module record plus the exact NORMAL include, and the
# initial include is NOT generated anymore.
if pam-auth-update --enable fic-password-quality-hook; then
    pass "quality: single-profile pam-auth-update --enable rc=0"
else
    fail "quality: pam-auth-update --enable fic-password-quality-hook rc!=0"
fi
snapshot_state both-selected
note "password state (both selected):"
sed 's/^/[gate]   /' "$EVID/both-selected.var-lib-pam-password"
note "generated common-password (both selected):"
sed 's/^/[gate]   /' "$EVID/both-selected.common-password"

grep -q "^Module: fic-password-quality-hook$" /var/lib/pam/password &&
    pass "quality: exact 'Module: fic-password-quality-hook' selection record" ||
    fail "quality: exact selection record missing in /var/lib/pam/password"
grep -Eq "^password[[:space:]]+include[[:space:]]+fic-password-quality[[:space:]]*$" \
    /etc/pam.d/common-password &&
    pass "quality: exact active 'password include fic-password-quality' include" ||
    fail "quality: exact active quality include missing in generated stack"
grep -q "^Module: fic-password-history-hook$" /var/lib/pam/password &&
    pass "history: exact 'Module: fic-password-history-hook' selection record" ||
    fail "history: exact selection record missing"
grep -Eq "^password[[:space:]]+include[[:space:]]+fic-password-history[[:space:]]*$" \
    /etc/pam.d/common-password &&
    pass "history: exact normal include present" ||
    fail "history: exact normal include missing"
grep -Eq "^password[[:space:]]+include[[:space:]]+fic-password-history-initial[[:space:]]*$" \
    /etc/pam.d/common-password &&
    fail "history: initial include unexpectedly present in the both-selected state (grammar regressed)" ||
    pass "history: initial include absent in the both-selected state (confirmed grammar)"
prove_password_change "both-selected"

# ---------------------------------------------------------------------------
# Detach / restore (supported pam-auth-update operations only)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Detach / restore (supported pam-auth-update operations only)
# ---------------------------------------------------------------------------
pam-auth-update --remove fic-password-history-hook || \
    fail "detach: pam-auth-update --remove fic-password-history-hook rc!=0"
pam-auth-update --remove fic-password-quality-hook || \
    fail "detach: pam-auth-update --remove fic-password-quality-hook rc!=0"
snapshot_state detached
if diff -u "$EVID/baseline.var-lib-pam-password" \
        "$EVID/detached.var-lib-pam-password" >/dev/null 2>&1 &&
    diff -u "$EVID/baseline.common-password" \
        "$EVID/detached.common-password" >/dev/null 2>&1; then
    pass "detach: per-profile --remove restored the exact baseline topology"
else
    fail "detach: per-profile --remove did not restore the baseline topology"
    diff -u "$EVID/baseline.common-password" \
        "$EVID/detached.common-password" 2>/dev/null | sed 's/^/[gate]   /'
fi
prove_password_change "detached"

# Idempotence of a single-profile --remove on an already-unselected profile
# (the compensation path relies on remove being a safe no-op there).
remove_rc=0
pam-auth-update --remove fic-password-quality-hook || remove_rc=$?
[ "$remove_rc" = "0" ] &&
    pass "idempotence: --remove of an unselected profile returns rc=0" ||
    fail "idempotence: --remove of an unselected profile returned rc=$remove_rc"
snapshot_state idempotent-remove
diff -u "$EVID/detached.var-lib-pam-password" \
        "$EVID/idempotent-remove.var-lib-pam-password" >/dev/null 2>&1 &&
    diff -u "$EVID/detached.common-password" \
        "$EVID/idempotent-remove.common-password" >/dev/null 2>&1 &&
    pass "idempotence: repeated --remove changed nothing" ||
    fail "idempotence: repeated --remove changed the state"

userdel -r "$TEST_USER" >/dev/null 2>&1 || true

if [ "$FAILED" = "0" ]; then
    echo "[gate] ARCHITECTURE GATE PASSED"
    exit 0
fi
echo "[gate] ARCHITECTURE GATE FAILED" >&2
exit 1
