#!/bin/bash
# Step 7F REAL distro gate: runtime rollback of the MANAGED PROVIDER
# configuration (Step 7B faillock scalars, Step 7C pwquality scalars,
# Step 7D pwhistory depth, Step 7E set-only flags) plus the package-removal
# provider release, through the PRODUCTION executors/rollback backend/
# package-release domain (fic-pam-provider-rollback-driver) with the
# compiled production platform profile, inside a DISPOSABLE container.
#
# Run (never on a host):
#   docker run --rm -v "$PWD":/src:ro debian:12 \
#       bash /src/tests/integration/pam-c2/pam_provider_rollback_gate.sh
#   docker run --rm -v "$PWD":/src:ro debian:13 \
#       bash /src/tests/integration/pam-c2/pam_provider_rollback_gate.sh
#   docker run --rm -v "$PWD":/src:ro ubuntu:24.04 \
#       bash /src/tests/integration/pam-c2/pam_provider_rollback_gate.sh
#   docker run --rm -v "$PWD":/src:ro ubuntu:26.04 \
#       bash /src/tests/integration/pam-c2/pam_provider_rollback_gate.sh
#
# Platform expectations (typed platform profile, never the distro name):
#   Debian 12            pwhistory ModuleArguments -> provider route REFUSED
#   Debian 13 / U24 / U26 pwhistory ProviderConfigFile -> provider route
#   every platform       faillock/pwquality provider scalars + flags
set -u

REPO="${GATE_REPO:-/src}"
EVID=/tmp/fic-provider-gate-evidence
DRIVER=/tmp/fic-provider-gate-bin/fic-pam-provider-rollback-driver
FAILED=0

mkdir -p "$EVID"
verdict() { echo "$1" | tee -a "$EVID/verdicts.txt"; }
gate_pass() { verdict "PASS $1"; }
gate_fail() { verdict "FAIL $1"; FAILED=1; }
note() { echo "[gate] $*"; }
die_environment() { echo "ENVIRONMENT INVALID: $*" >&2; exit 97; }

DISTRO_ID="$(. /etc/os-release && echo "$ID-$VERSION_ID")"
echo "$DISTRO_ID" > "$EVID/distro.txt"
note "distro: $DISTRO_ID"

case "$DISTRO_ID" in
    debian-12|debian-13|ubuntu-24.04|ubuntu-26.04) ;;
    *) die_environment "unsupported distro for the provider rollback gate" ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    die_environment "must run as root"
fi

# Offline mode: a prebuilt production driver binary can be injected with
# GATE_DRIVER (built on the host for EXACTLY this FIC_TARGET_PLATFORM).
# This keeps the gate REAL: the driver still runs the production executors
# against the real container PAM state; only the toolchain download is
# skipped when the sandbox has no distro mirror access.
mkdir -p "$(dirname "$DRIVER")"
if [ -n "${GATE_DRIVER:-}" ] && [ -x "$GATE_DRIVER" ]; then
    cp "$GATE_DRIVER" "$DRIVER"
    note "using prebuilt driver: $GATE_DRIVER"
else
    # Sandboxes often export a host loopback proxy that is unreachable from
    # inside the container; distro mirrors are directly reachable.
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
    export DEBIAN_FRONTEND=noninteractive
    apt-get update > "$EVID/apt-update.log" 2>&1 || die_environment "apt-get update failed"
    apt-get install -y --no-install-recommends \
        libpam-runtime libpam-modules libpam-pwquality \
        gcc g++ make cmake libssl-dev nlohmann-json3-dev libsqlite3-dev \
        pkg-config libsystemd-dev libglib2.0-dev qtbase5-dev \
        >> "$EVID/apt-install.log" 2>&1 || die_environment "apt-get install failed"

    GATE_PLATFORM="$DISTRO_ID"
    cmake -S "$REPO" -B /tmp/fic-provider-gate-build -DCMAKE_BUILD_TYPE=Release \
        -DFIC_TARGET_PLATFORM="$GATE_PLATFORM" \
        > "$EVID/cmake-configure.log" 2>&1 || die_environment "cmake configure failed"
    cmake --build /tmp/fic-provider-gate-build --target fic-pam-provider-rollback-driver -j2 \
        > "$EVID/cmake-build.log" 2>&1 || die_environment "driver build failed"
    DRIVER_BIN="$(find /tmp/fic-provider-gate-build -name fic-pam-provider-rollback-driver -type f | head -1)"
    [ -n "$DRIVER_BIN" ] || die_environment "driver binary not found"
    cp "$DRIVER_BIN" "$DRIVER"
fi

FAILLOCK=/etc/security/faillock.conf
PWQUALITY=/etc/security/pwquality.conf
PWHISTORY=/etc/security/pwhistory.conf

# Provider primaries are always pre-existing here (absent-primary creation
# is deliberately fail-closed in production). A provider whose primary (or
# whose provider package) is absent on THIS image simply has no provider
# route: those scenarios are skipped by the typed route decision, never by
# the distro name.
[ -f "$FAILLOCK" ] || die_environment "$FAILLOCK missing"

# Foreign administrator state (kept byte-exact across every rollback).
printf '\n# fic-gate foreign\ndeny = 3\neven_deny_root\n' >> "$FAILLOCK"
cp "$FAILLOCK" "$EVID/faillock.foreign"
"$DRIVER" report > "$EVID/routes.txt" 2>&1
routes() { cat "$EVID/routes.txt"; }
routed() { routes | grep -q "^ROUTE $1 $2 routed"; }
if [ -f "$PWQUALITY" ] && routed pam_pwquality minlen; then
    printf '\n# fic-gate foreign\nminlen = 9\nenforce_for_root\n' >> "$PWQUALITY"
    cp "$PWQUALITY" "$EVID/pwquality.foreign"
fi
if [ -f "$PWHISTORY" ] && routed pam_pwhistory remember; then
    printf '\n# fic-gate foreign\nremember = 5\n' >> "$PWHISTORY"
    cp "$PWHISTORY" "$EVID/pwhistory.foreign"
fi

CONFIG_FILES=""
for provider_file in "$FAILLOCK" "$PWQUALITY" "$PWHISTORY"; do
    [ -f "$provider_file" ] && CONFIG_FILES="$CONFIG_FILES $provider_file"
done

assert_no_fic_markers() {
    for provider_file in $CONFIG_FILES; do
        if grep -q 'FIC_PAM_' "$provider_file"; then
            return 1
        fi
    done
    return 0
}

assert_byte_exact() { cmp -s "$1" "$2"; }

# ---------------------------------------------------------------- report
routes > "$EVID/routes.txt"
note "routes:"
cat "$EVID/routes.txt" | sed 's/^/[gate]   /'

# ------------------------------------------------------------------ G1
# faillock scalar: apply -> disable releases the exact FIC entry and the
# foreign state becomes effective again byte-exact.
if "$DRIVER" apply pam_faillock deny 8 >> "$EVID/driver.log" 2>&1; then
    if grep -q 'FIC_PAM_PROVIDER_BLOCK' "$FAILLOCK" \
        && grep -q 'deny = 8' "$FAILLOCK"; then
        gate_pass "G1a faillock deny=8 apply (production executor, semantic proof)"
    else
        gate_fail "G1a faillock deny=8 apply produced no FIC ownership"
    fi
else
    gate_fail "G1a faillock deny=8 apply failed"
fi
if "$DRIVER" disable pam_faillock deny >> "$EVID/driver.log" 2>&1 \
    && assert_no_fic_markers \
    && assert_byte_exact "$FAILLOCK" "$EVID/faillock.foreign"; then
    gate_pass "G1b faillock deny=8 disable: markers gone, foreign byte-exact"
else
    gate_fail "G1b faillock deny=8 disable"
fi

# ------------------------------------------------------------------ G2
# faillock set-only flag FALSE over an existing foreign occurrence:
# disable unwraps the wrapper and restores the exact foreign line (§104).
if "$DRIVER" apply-flag pam_faillock even_deny_root false \
    >> "$EVID/driver.log" 2>&1; then
    if grep -q 'FIC_PAM_SUPPRESS' "$FAILLOCK" \
        && grep -q 'FIC_PAM_FLAG_DISABLED' "$FAILLOCK"; then
        gate_pass "G2a faillock even_deny_root=false wraps the foreign occurrence"
    else
        gate_fail "G2a faillock even_deny_root=false produced no wrapper"
    fi
else
    gate_fail "G2a faillock even_deny_root=false apply failed"
fi
if "$DRIVER" disable-flag pam_faillock even_deny_root \
    >> "$EVID/driver.log" 2>&1 \
    && assert_byte_exact "$FAILLOCK" "$EVID/faillock.foreign"; then
    gate_pass "G2b faillock even_deny_root=false disable: exact foreign line restored"
else
    gate_fail "G2b faillock even_deny_root=false disable"
fi

# ------------------------------------------------------------------ G3
# pwquality scalar with DISPLACED block (admin prepends a foreign line
# after the FIC apply): ownership ≠ placement — release still succeeds.
if ! [ -f "$PWQUALITY" ] || ! routed pam_pwquality minlen; then
    gate_pass "G3 pwquality provider route not configured on this image (skipped by route)"
elif "$DRIVER" apply pam_pwquality minlen 12 >> "$EVID/driver.log" 2>&1; then
    sed -i '1i top_foreign_rule = x' "$PWQUALITY"
    if "$DRIVER" disable pam_pwquality minlen >> "$EVID/driver.log" 2>&1 \
        && assert_no_fic_markers \
        && assert_byte_exact "$PWQUALITY" <(printf 'top_foreign_rule = x\n'; cat "$EVID/pwquality.foreign"); then
        gate_pass "G3 pwquality displaced-block release, foreign bytes exact"
    else
        gate_fail "G3 pwquality displaced-block release"
    fi
else
    gate_fail "G3 pwquality minlen=12 apply failed"
fi

# ------------------------------------------------------------------ G4
# pwquality flag FALSE over a foreign occurrence.
if ! [ -f "$PWQUALITY" ] || ! routed pam_pwquality minlen; then
    gate_pass "G4 pwquality provider route not configured on this image (skipped by route)"
elif "$DRIVER" apply-flag pam_pwquality enforce_for_root false \
    >> "$EVID/driver.log" 2>&1 \
    && grep -q 'FIC_PAM_SUPPRESS' "$PWQUALITY"; then
    gate_pass "G4a pwquality enforce_for_root=false wraps the foreign occurrence"
else
    gate_fail "G4a pwquality enforce_for_root=false apply"
fi
if ! [ -f "$PWQUALITY" ] || ! routed pam_pwquality minlen; then
    : # G4 skipped above
elif "$DRIVER" disable-flag pam_pwquality enforce_for_root \
    >> "$EVID/driver.log" 2>&1 \
    && assert_byte_exact "$PWQUALITY" "$EVID/pwquality.foreign"; then
    gate_pass "G4b pwquality enforce_for_root=false disable: foreign exact"
else
    gate_fail "G4b pwquality enforce_for_root=false disable"
fi

# ------------------------------------------------------------------ G5
# pwhistory provider route is the TYPED platform decision.
if routed pam_pwhistory remember; then
    if "$DRIVER" apply pam_pwhistory remember 10 >> "$EVID/driver.log" 2>&1 \
        && grep -q 'FIC_PAM_PROVIDER_BLOCK' "$PWHISTORY" \
        && "$DRIVER" disable pam_pwhistory remember >> "$EVID/driver.log" 2>&1 \
        && assert_byte_exact "$PWHISTORY" "$EVID/pwhistory.foreign"; then
        gate_pass "G5 pwhistory remember=10 provider rollback (ProviderConfigFile platform)"
    else
        gate_fail "G5 pwhistory remember provider rollback"
    fi
else
    if grep -qs 'FIC_PAM_' "$PWHISTORY"; then
        gate_fail "G5 pwhistory route refused but FIC markers exist"
    else
        gate_pass "G5 pwhistory provider route refused on this platform (typed decision)"
    fi
fi

# ------------------------------------------------------------------ G6
# Package provider release: preflight is strictly read-only, release
# removes every remaining active record and leaves foreign-only files.
if "$DRIVER" apply pam_faillock unlock_time 30 >> "$EVID/driver.log" 2>&1; then
    if [ -f "$PWQUALITY" ] && routed pam_pwquality minlen; then
        "$DRIVER" apply pam_pwquality minclass 3 >> "$EVID/driver.log" 2>&1 \
            || gate_fail "G6 setup: pwquality minclass apply failed"
    fi
else
    gate_fail "G6 setup: re-apply for the release sweep failed"
fi
MD5_BEFORE_CONFIG="$(cat $CONFIG_FILES 2>/dev/null | md5sum)"
if "$DRIVER" preflight >> "$EVID/driver.log" 2>&1; then
    MD5_AFTER_CONFIG="$(cat $CONFIG_FILES 2>/dev/null | md5sum)"
    if [ "$MD5_BEFORE_CONFIG" = "$MD5_AFTER_CONFIG" ]; then
        gate_pass "G6a package provider preflight passed read-only (§93)"
    else
        gate_fail "G6a package provider preflight MUTATED configuration"
    fi
else
    gate_fail "G6a package provider preflight failed"
fi
if "$DRIVER" release >> "$EVID/driver.log" 2>&1 \
    && assert_no_fic_markers \
    && assert_byte_exact "$FAILLOCK" "$EVID/faillock.foreign" \
    && { [ ! -f "$PWQUALITY" ] || ! routed pam_pwquality minlen \
         || assert_byte_exact "$PWQUALITY" "$EVID/pwquality.foreign"; } \
    && { [ ! -f "$PWHISTORY" ] || ! routed pam_pwhistory remember \
         || assert_byte_exact "$PWHISTORY" "$EVID/pwhistory.foreign"; }; then
    gate_pass "G6b package provider release: foreign-only final state (§106/§121)"
else
    gate_fail "G6b package provider release"
fi

# ------------------------------------------------------------------ G7
# Retry idempotence after the release: disable commands classify the
# released state as NothingToDo and never reconstruct FIC state.
if "$DRIVER" disable pam_faillock unlock_time >> "$EVID/driver.log" 2>&1 \
    && { [ ! -f "$PWQUALITY" ] || ! routed pam_pwquality minlen \
         || "$DRIVER" disable pam_pwquality minclass >> "$EVID/driver.log" 2>&1; } \
    && assert_no_fic_markers; then
    gate_pass "G7 retry after release is an idempotent no-op (§44/§87)"
else
    gate_fail "G7 retry after release"
fi

# Evidence dump for sandbox debugging (host-mounted dir, optional).
if [ -n "${GATE_EVIDENCE_OUT:-}" ] && [ -d "$GATE_EVIDENCE_OUT" ]; then
    cp -r "$EVID" "$GATE_EVIDENCE_OUT/evidence" 2>/dev/null || true
fi

if [ "$FAILED" -eq 0 ]; then
    verdict "PASS $DISTRO_ID provider-rollback-gate"
    echo "[gate] ALL GATES PASSED on $DISTRO_ID"
    exit 0
fi
verdict "FAIL $DISTRO_ID provider-rollback-gate"
echo "[gate] GATE FAILURES on $DISTRO_ID"
exit 1
