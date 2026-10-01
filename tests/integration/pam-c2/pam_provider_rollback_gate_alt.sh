#!/bin/bash
# Step 7F REAL distro gate, ALT p11 variant. Same production driver as
# pam_provider_rollback_gate.sh, but the platform expectations are the ALT
# compiled profile: the faillock provider route is production evidence, the
# pwhistory route MUST be refused (ALT tcb/pwhistory topology strategy is
# NOT the managed provider path) and pwquality scenarios run only when the
# pwquality ProviderConfigFile capability is actually present.
#
# Run (never on a host):
#   docker run --rm -v "$PWD":/src:ro localhost/fic-rpm-builder:alt-p11 \
#       bash /src/tests/integration/pam-c2/pam_provider_rollback_gate_alt.sh
set -u

REPO="${GATE_REPO:-/src}"
EVID=/tmp/fic-provider-gate-evidence
DRIVER=/tmp/fic-provider-gate-bin/fic-pam-provider-rollback-driver
FAILED=0

mkdir -p "$EVID"
verdict() { echo "$1" | tee -a "$EVID/verdicts.txt"; }
gate_pass() { verdict "PASS $1"; }
gate_fail() { verdict "FAIL $1"; FAILED=1; }
note() { echo "[gate:alt] $*"; }
die_environment() { echo "ENVIRONMENT INVALID: $*" >&2; exit 97; }

DISTRO_ID="$(. /etc/os-release && echo "$ID-$VERSION_ID")"
echo "$DISTRO_ID" > "$EVID/distro.txt"
note "distro: $DISTRO_ID"
case "$DISTRO_ID" in
    altlinux*) ;;
    *) die_environment "ALT-only gate" ;;
esac
[ "$(id -u)" -eq 0 ] || die_environment "must run as root"
command -v cmake >/dev/null || die_environment "cmake missing in the ALT builder image"

GATE_PLATFORM=alt-p11
cmake -S "$REPO" -B /tmp/fic-provider-gate-build -DCMAKE_BUILD_TYPE=Release \
    -DFIC_TARGET_PLATFORM="$GATE_PLATFORM" \
    > "$EVID/cmake-configure.log" 2>&1 || die_environment "cmake configure failed"
cmake --build /tmp/fic-provider-gate-build --target fic-pam-provider-rollback-driver -j2 \
    > "$EVID/cmake-build.log" 2>&1 || die_environment "driver build failed"
DRIVER_BIN="$(find /tmp/fic-provider-gate-build -name fic-pam-provider-rollback-driver -type f | head -1)"
[ -n "$DRIVER_BIN" ] || die_environment "driver binary not found"
mkdir -p "$(dirname "$DRIVER")"
cp "$DRIVER_BIN" "$DRIVER"

FAILLOCK=/etc/security/faillock.conf
PWQUALITY=/etc/security/pwquality.conf
PWHISTORY=/etc/security/pwhistory.conf
[ -f "$FAILLOCK" ] || die_environment "$FAILLOCK missing"
[ -f "$PWHISTORY" ] || die_environment "$PWHISTORY missing"

printf '\n# fic-gate foreign\ndeny = 3\neven_deny_root\n' >> "$FAILLOCK"
printf '\n# fic-gate foreign\nremember = 5\n' >> "$PWHISTORY"
cp "$FAILLOCK" "$EVID/faillock.foreign"
cp "$PWHISTORY" "$EVID/pwhistory.foreign"
if [ -f "$PWQUALITY" ]; then
    printf '\n# fic-gate foreign\nminlen = 9\n' >> "$PWQUALITY"
    cp "$PWQUALITY" "$EVID/pwquality.foreign"
fi

"$DRIVER" report > "$EVID/routes.txt" 2>&1
cat "$EVID/routes.txt" | sed 's/^/[gate:alt]   /'
routed() { grep -q "^ROUTE $1 $2 routed" "$EVID/routes.txt"; }

assert_no_fic_markers() {
    for provider_file in "$FAILLOCK" "$PWHISTORY"; do
        if grep -q 'FIC_PAM_' "$provider_file"; then
            return 1
        fi
    done
    if [ -f "$PWQUALITY" ] && grep -q 'FIC_PAM_' "$PWQUALITY"; then
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------ A1
# faillock scalar apply -> disable, foreign byte-exact.
if "$DRIVER" apply pam_faillock deny 8 >> "$EVID/driver.log" 2>&1 \
    && grep -q 'FIC_PAM_PROVIDER_BLOCK' "$FAILLOCK"; then
    gate_pass "A1a faillock deny=8 apply (production executor)"
else
    gate_fail "A1a faillock deny=8 apply"
fi
if "$DRIVER" disable pam_faillock deny >> "$EVID/driver.log" 2>&1 \
    && cmp -s "$FAILLOCK" "$EVID/faillock.foreign"; then
    gate_pass "A1b faillock deny=8 disable: foreign byte-exact"
else
    gate_fail "A1b faillock deny=8 disable"
fi

# ------------------------------------------------------------------ A2
# faillock set-only flag FALSE over a foreign occurrence.
if "$DRIVER" apply-flag pam_faillock even_deny_root false \
    >> "$EVID/driver.log" 2>&1 \
    && grep -q 'FIC_PAM_SUPPRESS' "$FAILLOCK"; then
    gate_pass "A2a faillock even_deny_root=false wraps the foreign occurrence"
else
    gate_fail "A2a faillock even_deny_root=false apply"
fi
if "$DRIVER" disable-flag pam_faillock even_deny_root \
    >> "$EVID/driver.log" 2>&1 \
    && cmp -s "$FAILLOCK" "$EVID/faillock.foreign"; then
    gate_pass "A2b faillock even_deny_root=false disable: exact foreign line restored"
else
    gate_fail "A2b faillock even_deny_root=false disable"
fi

# ------------------------------------------------------------------ A3
# ALT pwhistory topology is NOT the managed provider route (typed
# platform decision, D12-analog exclusion on the ALT profile).
if routed pam_pwhistory remember; then
    gate_fail "A3 pwhistory provider route must be REFUSED on the ALT profile"
else
    if grep -q 'FIC_PAM_' "$PWHISTORY"; then
        gate_fail "A3 route refused but FIC markers exist in pwhistory.conf"
    else
        gate_pass "A3 pwhistory provider route refused on the ALT profile (tcb topology)"
    fi
fi

# ------------------------------------------------------------------ A4
# pwquality scenarios run only when the capability routes through the
# provider configuration on this image.
if routed pam_pwquality minlen; then
    if "$DRIVER" apply pam_pwquality minlen 12 >> "$EVID/driver.log" 2>&1 \
        && "$DRIVER" disable pam_pwquality minlen >> "$EVID/driver.log" 2>&1 \
        && cmp -s "$PWQUALITY" "$EVID/pwquality.foreign"; then
        gate_pass "A4 pwquality minlen provider rollback"
    else
        gate_fail "A4 pwquality minlen provider rollback"
    fi
else
    gate_pass "A4 pwquality provider route not configured on this image (skipped by route)"
fi

# ------------------------------------------------------------------ A5
# Package provider release sweep on whatever active records exist.
if "$DRIVER" apply pam_faillock unlock_time 30 >> "$EVID/driver.log" 2>&1; then
    : # one active record for the sweep
else
    gate_fail "A5 setup: faillock unlock_time apply failed"
fi
if "$DRIVER" preflight >> "$EVID/driver.log" 2>&1 \
    && "$DRIVER" release >> "$EVID/driver.log" 2>&1 \
    && assert_no_fic_markers \
    && cmp -s "$FAILLOCK" "$EVID/faillock.foreign"; then
    gate_pass "A5 package provider preflight+release: foreign-only final state"
else
    gate_fail "A5 package provider release"
fi

# ------------------------------------------------------------------ A6
# Retry idempotence after the release.
if "$DRIVER" disable pam_faillock unlock_time >> "$EVID/driver.log" 2>&1 \
    && assert_no_fic_markers; then
    gate_pass "A6 retry after release is an idempotent no-op"
else
    gate_fail "A6 retry after release"
fi

if [ "$FAILED" -eq 0 ]; then
    verdict "PASS $DISTRO_ID provider-rollback-gate-alt"
    echo "[gate:alt] ALL GATES PASSED on $DISTRO_ID"
    exit 0
fi
verdict "FAIL $DISTRO_ID provider-rollback-gate-alt"
echo "[gate:alt] GATE FAILURES on $DISTRO_ID"
exit 1
