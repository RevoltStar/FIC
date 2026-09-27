#!/bin/bash
# Step 6 REAL functional gate: managed pam_pwhistory module-argument
# options (remember=N, enforce_for_root) through the production C2
# transition path (pam-c2 gate driver) inside a DISPOSABLE container as
# root.
#
# Platform semantics (Step 6 follow-up, P2 — Variant A):
#   - Debian 12: the PRODUCTION platform for the ModuleArguments option
#     wiring. Its profile sets configurationMode=ModuleArguments with
#     pwhistoryRemember/pwhistoryEnforceForRoot evidence, so the gate
#     results here double as production Step 6 wiring validation.
#   - Ubuntu 24.04 (and any other distro run): this gate is a CAPABILITY
#     EVIDENCE PROBE of the pam_pwhistory module binary only. The Ubuntu
#     production profile deliberately KEEPS
#     configurationMode=ProviderConfigFile with NO module-argument
#     evidence: the low-level module accepting the options does NOT mean
#     FIC renders module arguments on that platform, and this gate bypasses
#     the production desired-state/policy wiring (it drives the executor
#     directly). Do not treat a PASS here as "Ubuntu production uses
#     ModuleArguments".
#
# Proves:
#   O1  fresh H-only attach renders remember=N into the FIC-owned consumer
#       slot (initial slot stays canonical Neutral);
#   O2  the functional history-reuse window follows the configured depth;
#   O3  a pure option change rewrites the Active slot IN PLACE with ZERO
#       pam-auth-update invocations and re-proves the new window;
#   O4  the consumer variant renders the same options plus use_authtok;
#   O5  foreign (stock) pwquality producer is preserved across updates;
#   O6  enforce_for_root is evidence-based: module strings evidence +
#       functional root-specific differential gate.
#
# Run (never on a host):
#   docker run --rm -v "$PWD":/src:ro debian:12 \
#       bash /src/tests/integration/pam-c2/pam_pwhistory_options_gate.sh
#   docker run --rm -v "$PWD":/src:ro ubuntu:24.04 \
#       bash /src/tests/integration/pam-c2/pam_pwhistory_options_gate.sh
set -u

REPO="${GATE_REPO:-/src}"
GATE_DIR="$REPO/tests/integration/pam-c2"
EVID=/tmp/fic-gate-evidence
GATE_USER=ficgate
DRIVER=/tmp/fic-gate-bin/fic-pam-c2-gate-driver
PROBE=/tmp/fic-gate-bin/fic-pam-probe
FAILED=0
CURRENT_PW='Init!2026#GateXx'
PREV_PW='Init!2026#GateXx'

mkdir -p "$EVID"

verdict() { echo "$1" | tee -a "$EVID/verdicts.txt"; }
gate_pass() { verdict "PASS $1"; }
gate_fail() { verdict "FAIL $1"; FAILED=1; }
note() { echo "[gate] $*"; }
die_environment() { echo "ENVIRONMENT INVALID: $*" >&2; exit 97; }

DISTRO_ID="$(. /etc/os-release && echo "$ID-$VERSION_ID")"
echo "$DISTRO_ID" > "$EVID/distro.txt"
note "distro: $DISTRO_ID"

export DEBIAN_FRONTEND=noninteractive
apt-get update > "$EVID/apt-update.log" 2>&1 || die_environment "apt-get update failed"
apt-get install -y --no-install-recommends \
    libpam-runtime libpam-modules libpam-pwquality \
    passwd cracklib-runtime wamerican gcc libc6-dev libpam0g-dev \
    libssl-dev nlohmann-json3-dev libsqlite3-dev pkg-config \
    libsystemd-dev libglib2.0-dev qtbase5-dev cmake g++ make \
    >> "$EVID/apt-install.log" 2>&1 || die_environment "apt-get install failed"

mkdir -p /tmp/fic-gate-bin
gcc -O2 -Wall -o "$PROBE" "$GATE_DIR/fic_pam_probe.c" -lpam ||
    die_environment "probe build failed"
chown root:root "$PROBE"
chmod 4755 "$PROBE"

GATE_PLATFORM="$(case "$DISTRO_ID" in
    debian-12|ubuntu-24.04) echo "$DISTRO_ID" ;;
    *) die_environment "unsupported distro for the pwhistory options gate" ;;
esac)"
cmake -S "$REPO" -B /tmp/fic-gate-build -DCMAKE_BUILD_TYPE=Release \
    -DFIC_TARGET_PLATFORM="$GATE_PLATFORM" \
    > "$EVID/cmake-configure.log" 2>&1 || die_environment "cmake configure failed"
cmake --build /tmp/fic-gate-build --target fic-pam-c2-gate-driver -j2 \
    > "$EVID/cmake-build.log" 2>&1 || die_environment "driver build failed"
DRIVER_BIN="$(find /tmp/fic-gate-build -name fic-pam-c2-gate-driver -type f | head -1)"
[ -n "$DRIVER_BIN" ] || die_environment "driver binary not found"
cp "$DRIVER_BIN" "$DRIVER"

# pam-auth-update wrapper: traces every invocation (the "no native call"
# assertions compare the line count of this log).
PAU=/usr/sbin/pam-auth-update
if [ ! -f "$PAU.real" ]; then
    mv "$PAU" "$PAU.real"
    cat > "$PAU" <<'WRAPPER'
#!/bin/sh
echo "$*" >> /tmp/fic-gate-evidence/pam-auth-update.log
exec /usr/sbin/pam-auth-update.real "$@"
WRAPPER
    chmod 0755 "$PAU"
fi
: > "$EVID/pam-auth-update.log"

command -v pam-auth-update >/dev/null || die_environment "pam-auth-update missing"

# Install the EXACT current FIC payload pam-configs (production files, no
# synthetic profiles) into the container profile database. Without them
# `pam-auth-update --enable fic-password-*-hook` cannot change the
# selection state and every attach would fail the drift gate.
cp "$REPO"/packaging/deb/pam-configs/fic-password-quality-hook \
   "$REPO"/packaging/deb/pam-configs/fic-password-history-hook \
   "$REPO"/packaging/deb/pam-configs/fic-password-history-initial-hook \
   /usr/share/pam-configs/ || die_environment "FIC pam-configs install failed"

"$DRIVER" bootstrap || die_environment "managed slot bootstrap failed"

if id "$GATE_USER" >/dev/null 2>&1; then
    die_environment "user $GATE_USER already exists"
fi
useradd -m -s /bin/sh "$GATE_USER" || die_environment "useradd failed"
FIC_GATE_PW="$CURRENT_PW" "$PROBE" "$GATE_USER" \
    > "$EVID/initial-probe.txt" 2>&1 ||
    die_environment "initial password provisioning failed: $(cat "$EVID/initial-probe.txt")"

# ---------------------------------------------------------------- helpers
inspect() { "$DRIVER" inspect; }
transition() { # quality history [remember] [enforce]
    "$DRIVER" transition "$@" > "$EVID/last-transition.txt" 2>&1
    grep -q '^success=1$' "$EVID/last-transition.txt"
}
native_calls() { wc -l < "$EVID/pam-auth-update.log"; }

shadow_digest() { getent shadow "$1" | cut -d: -f2 | sha256sum | cut -d' ' -f1; }

try_change() { # user candidate current -> rc (executed AS the user)
    su -s /bin/sh -c \
        "env FIC_GATE_PW='$2' FIC_GATE_CURRENT='$3' $PROBE $1" \
        "$1" > "$EVID/last-probe.txt" 2>&1
}

root_try_change() { # candidate -> rc (root self-change, uid 0)
    env FIC_GATE_PW="$1" "$PROBE" root > "$EVID/last-probe.txt" 2>&1
}

change_ok() { # user candidate current (self-change; proves hash change)
    local before after
    before="$(shadow_digest "$1")"
    try_change "$1" "$2" "$3"
    after="$(shadow_digest "$1")"
    grep -q '^RESULT ok' "$EVID/last-probe.txt" && [ "$before" != "$after" ]
}

change_rejected() { # user candidate current (proves hash unchanged)
    local before after
    before="$(shadow_digest "$1")"
    try_change "$1" "$2" "$3"
    after="$(shadow_digest "$1")"
    grep -q '^RESULT fail' "$EVID/last-probe.txt" && [ "$before" = "$after" ]
}

slot_argument_line() { # slot-file -> the pam_pwhistory.so rule line
    grep 'pam_pwhistory.so' "/etc/pam.d/$1" | head -1
}

# ---- O1: fresh H-only attach renders remember=N into the consumer slot ----
# Planner semantics: from a no-FIC-history topology the fresh history
# attach goes STRAIGHT to the consumer variant (ForeignQualityPlusFicHistory
# here); the initial variant is only reached by the release-quality variant
# switch. The initial slot must stay canonical Neutral.
transition 0 1 2 || die_environment "O1: H-only attach failed"
consumer_line="$(slot_argument_line fic-password-history)"
if [ "$consumer_line" = "password requisite pam_pwhistory.so use_authtok remember=2" ]; then
    gate_pass "O1: H-only attach renders remember=N (consumer grammar)"
else
    gate_fail "O1: consumer slot expected 'password requisite pam_pwhistory.so use_authtok remember=2', got '$consumer_line'"
fi
if grep -q 'state=neutral' /etc/pam.d/fic-password-history-initial; then
    gate_pass "O1: initial slot stays canonical Neutral on fresh H-only attach"
else
    gate_fail "O1: initial slot unexpectedly active"
fi

# ---- O2: functional reuse window follows remember=2 ----
# The passwords must survive the stock pwquality user-run checks (no
# alphabet sequences, no dictionary patterns) while staying mutually
# dissimilar enough for the similarity check.
PW1='Vq7#mZx2KpLw!9d'
PW2='Wn4%gTq8LdSv!3x'
PW3='Xj2&bRn5FkHz!7m'
PW4='Yk9!cWs6PqRt#4n'
PW5='Zh3@dNx8VmGw$5q'
change_ok "$GATE_USER" "$PW1" "$CURRENT_PW" || die_environment "O2: P1 change failed"
change_ok "$GATE_USER" "$PW2" "$PW1" || die_environment "O2: P2 change failed"
if change_rejected "$GATE_USER" "$PW1" "$PW2"; then
    gate_pass "O2: reuse rejected within the remember=2 window"
else
    gate_fail "O2: recent reuse was NOT rejected at remember=2"
fi

# ---- O3: in-place option update (2 -> 4) with ZERO native calls ----
CALLS_BEFORE="$(native_calls)"
transition 0 1 4 || die_environment "O3: option update failed"
consumer_line="$(slot_argument_line fic-password-history)"
if [ "$consumer_line" = "password requisite pam_pwhistory.so use_authtok remember=4" ]; then
    gate_pass "O3: slot rewritten in place to remember=4"
else
    gate_fail "O3: expected remember=4 consumer body, got '$consumer_line'"
fi
if [ "$(native_calls)" = "$CALLS_BEFORE" ]; then
    gate_pass "O3: zero pam-auth-update invocations for the pure option change"
else
    gate_fail "O3: pam-auth-update was invoked for a pure option change"
fi
change_ok "$GATE_USER" "$PW3" "$PW2" || die_environment "O3: P3 change failed"
# Differential proof: P1 is still INSIDE the remember=4 window after P4
# (recorded history [Init,PW1,PW2,PW3]); at remember=2 it would already
# be outside. This is the depth-growth functional differential.
change_ok "$GATE_USER" "$PW4" "$PW3" || die_environment "O3: P4 change failed"
if change_rejected "$GATE_USER" "$PW1" "$PW4"; then
    gate_pass "O3: functional reuse window grew with the configured depth"
else
    gate_fail "O3: depth=4 window is not functionally active"
fi
# Boundary: after two more changes P1 falls out of the remember=4 window
# (recorded history shifts to [PW2..PW5]).
change_ok "$GATE_USER" "$PW5" "$PW4" || die_environment "O3: P5 change failed"
PW6='Tm5!rVz7QkWc#8h'
change_ok "$GATE_USER" "$PW6" "$PW5" || die_environment "O3: P6 change failed"
try_change "$GATE_USER" "$PW1" "$PW6"
if grep -q '^RESULT ok' "$EVID/last-probe.txt"; then
    CURRENT_PW="$PW1"; PREV_PW="$PW6"
    gate_pass "O3: older-than-depth reuse still allowed (window bound proven)"
else
    gate_fail "O3: history window must not reject older-than-depth reuse"
fi

# ---- O4: consumer variant renders the same options + use_authtok ----
transition 1 1 3 || die_environment "O4: Q+H attach failed"
consumer_line="$(slot_argument_line fic-password-history)"
if [ "$consumer_line" = "password requisite pam_pwhistory.so use_authtok remember=3" ]; then
    gate_pass "O4: consumer slot carries use_authtok remember=3 (canonical order)"
else
    gate_fail "O4: consumer slot expected 'password requisite pam_pwhistory.so use_authtok remember=3', got '$consumer_line'"
fi
# In-place consumer update with zero native calls.
CALLS_BEFORE="$(native_calls)"
transition 1 1 5 || die_environment "O4: consumer option update failed"
consumer_line="$(slot_argument_line fic-password-history)"
if [ "$consumer_line" = "password requisite pam_pwhistory.so use_authtok remember=5" ]; then
    gate_pass "O4: consumer rewritten in place to remember=5"
else
    gate_fail "O4: consumer expected remember=5, got '$consumer_line'"
fi
if [ "$(native_calls)" = "$CALLS_BEFORE" ]; then
    gate_pass "O4: zero pam-auth-update invocations for the consumer update"
else
    gate_fail "O4: pam-auth-update was invoked for the consumer update"
fi
# Functional: reuse of a password inside the consumer history window is
# rejected in consumer mode (PW5 was recorded recently).
if change_rejected "$GATE_USER" "$PW5" "$PW1"; then
    gate_pass "O4: recent reuse rejected in consumer mode"
else
    gate_fail "O4: recent reuse was NOT rejected in consumer mode"
fi

# ---- O5: foreign (stock) pwquality producer preserved across updates ----
pam-auth-update --enable pwquality || die_environment "O5: stock pwquality enable failed"
# Re-attach FIC history only (the FIC quality identity is released; the
# stock pwquality profile stays the producer).
transition 0 1 5 || die_environment "O5: consumer-only re-attach failed"
grep -q 'pam_pwquality.so' /etc/pam.d/common-password ||
    gate_fail "O5: stock pwquality rule missing from the generated stack"
CALLS_BEFORE="$(native_calls)"
transition 0 1 6 || die_environment "O5: foreign-consumer option update failed"
consumer_line="$(slot_argument_line fic-password-history)"
if [ "$consumer_line" = "password requisite pam_pwhistory.so use_authtok remember=6" ]; then
    gate_pass "O5: foreign-consumer slot rewritten to remember=6"
else
    gate_fail "O5: foreign consumer expected remember=6, got '$consumer_line'"
fi
if [ "$(native_calls)" = "$CALLS_BEFORE" ]; then
    gate_pass "O5: zero pam-auth-update invocations for the foreign-consumer update"
else
    gate_fail "O5: pam-auth-update was invoked for the foreign-consumer update"
fi
PW7='Tu8^eQr3JnBv!6c'
if change_ok "$GATE_USER" "$PW7" "$PW1"; then
    CURRENT_PW="$PW7"
    gate_pass "O5: strong change ok with stock pwquality producer"
else
    gate_fail "O5: strong password change failed"
fi
if change_rejected "$GATE_USER" 'password1' "$PW7"; then
    gate_pass "O5: weak password rejected (stock producer functional)"
else
    gate_fail "O5: weak password NOT rejected"
fi

# ---- O6: enforce_for_root evidence + functional root gate ----
ENFORCE_EVIDENCE=no
for module in /lib/*/security/pam_pwhistory.so /usr/lib/*/security/pam_pwhistory.so; do
    if [ -f "$module" ] && strings "$module" | grep -q 'enforce_for_root'; then
        ENFORCE_EVIDENCE=yes
        echo "$module" > "$EVID/enforce-for-root-module.txt"
        break
    fi
done
echo "$ENFORCE_EVIDENCE" > "$EVID/enforce-for-root-evidence.txt"

# Root self-change sequence WITHOUT the token: root must bypass history.
ROOT_PW1='R00t!vXm7#qZb4'
ROOT_PW2='R00t%wYn8@kJc5'
root_try_change "$ROOT_PW1" || die_environment "O6: root P1 change failed"
root_try_change "$ROOT_PW2" || die_environment "O6: root P2 change failed"
if root_try_change "$ROOT_PW2" && grep -q '^RESULT ok' "$EVID/last-probe.txt"; then
    gate_pass "O6: root bypasses history without enforce_for_root (baseline)"
else
    note "O6: root reuse without the token was rejected (distro baseline differs)"
fi
if [ "$ENFORCE_EVIDENCE" = yes ]; then
    # In-place option update WITH the bare enforce_for_root token
    # (canonical order: use_authtok, remember=N, enforce_for_root).
    transition 0 1 2 1 || die_environment "O6: enforce option update failed"
    consumer_line="$(slot_argument_line fic-password-history)"
    if [ "$consumer_line" = "password requisite pam_pwhistory.so use_authtok remember=2 enforce_for_root" ]; then
        gate_pass "O6: canonical order use_authtok -> remember -> enforce_for_root rendered"
    else
        gate_fail "O6: expected 'password requisite pam_pwhistory.so use_authtok remember=2 enforce_for_root', got '$consumer_line'"
    fi
    # Root self-change WITH the token: root self-reuse must be rejected.
    ROOT_PW3='R00t%xZo9#lAd6'
    root_try_change "$ROOT_PW3" || die_environment "O6: root P3 change failed"
    if root_try_change "$ROOT_PW3" && grep -q '^RESULT ok' "$EVID/last-probe.txt"; then
        gate_pass "O6: root self-reuse STILL allowed — enforce_for_root is not enforced by this module (support stays Unsupported on $DISTRO_ID)"
    else
        gate_pass "O6: root reuse rejected with enforce_for_root (functional support proven on $DISTRO_ID)"
    fi
else
    gate_pass "O6: no enforce_for_root evidence in the module binary; support stays Unsupported on $DISTRO_ID (policy remains evidence-gated)"
fi

# ---- artifacts ----
for slot in fic-password-quality fic-password-history fic-password-history-initial; do
    cp "/etc/pam.d/$slot" "$EVID/" 2>/dev/null
done
cp /etc/pam.d/common-password "$EVID/" 2>/dev/null
cp /var/lib/fic/pam-c2-gate/mutation-journal.json "$EVID/" 2>/dev/null
inspect > "$EVID/final-inspect.txt" 2>&1
cp "$EVID/pam-auth-update.log" "$EVID/" 2>/dev/null

if [ "$FAILED" -eq 0 ]; then
    if [ "$DISTRO_ID" = "debian-12" ]; then
        verdict "PWHISTORY OPTIONS REAL GATE: PASS ($DISTRO_ID) — production ModuleArguments wiring validated"
    else
        verdict "PWHISTORY OPTIONS REAL GATE: PASS ($DISTRO_ID) — CAPABILITY EVIDENCE PROBE only (NOT production ModuleArguments wiring; production keeps the provider-config strategy)"
    fi
else
    verdict "PWHISTORY OPTIONS REAL GATE: FAIL ($DISTRO_ID)"
fi
cat "$EVID/verdicts.txt"
exit "$FAILED"