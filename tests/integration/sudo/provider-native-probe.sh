#!/bin/sh
set -eu

# Real sudo checks run only inside disposable containers. No host sudoers
# path or PAM is ever mounted by the matrix runner.
test -f /run/.containerenv || test -f /.dockerenv || {
    echo 'FAIL: container-only native probe' >&2
    exit 1
}
test "$(id -u)" = 0
sudo --version | head -1
printf 'provider=%s validator=%s\n' "$(readlink -f /usr/bin/sudo)" "$(readlink -f /usr/sbin/visudo 2>/dev/null || command -v visudo)"
stat -c '%U:%G %a %n' /etc/sudoers
probe_directory=$(mktemp -d /tmp/fic-sudo-provider-XXXXXX)
trap 'rm -rf "$probe_directory"' EXIT HUP INT TERM
useradd -m fic-sudo-probe
if command -v control >/dev/null 2>&1; then
    # ALT's native package intentionally defaults to restricted sudo (0700).
    # Enable only the fixture wheel group through the package's own facility.
    control sudo wheelonly
    usermod -a -G wheel fic-sudo-probe
fi
original_mode=$(stat -c '%a' /etc/sudoers)

# Probe a real user/command through the active provider, including an explicit
# request to disable env_reset. The provider guarantee must survive it.
printf 'Defaults !env_reset\nfic-sudo-probe ALL=(root) NOPASSWD: /usr/bin/env\n' > /etc/sudoers
chmod "$original_mode" /etc/sudoers
visudo -c
runuser -u fic-sudo-probe -- env FIC_NATIVE_SECRET=must_be_removed \
    sudo -n /usr/bin/env > "$probe_directory/environment"
if sudo --version | head -1 | grep -q '^sudo-rs '; then
    if grep -q '^FIC_NATIVE_SECRET=' "$probe_directory/environment"; then
        echo 'FAIL sudo-rs env_reset construction guarantee'
        exit 1
    fi
    echo 'PASS sudo-rs unconditional env_reset'
    for setting in 'Defaults !exempt_group' 'Defaults exempt_group=fic-sudo-probe' \
                   'Defaults:fic-sudo-probe exempt_group=fic-sudo-probe'; do
        printf '%s\nfic-sudo-probe ALL=(root) ALL\n' "$setting" > "$probe_directory/exempt"
        chmod "$original_mode" "$probe_directory/exempt"
        if visudo -c -f "$probe_directory/exempt" > "$probe_directory/exempt-result" 2>&1; then
            echo "FAIL sudo-rs accepted exempt_group mechanism: $setting"
            exit 1
        fi
        echo "PASS rejected unsupported mechanism: $setting"
    done
else
    grep -q '^FIC_NATIVE_SECRET=' "$probe_directory/environment"
    echo 'PASS classic env_reset remains configurable'
fi

# Continuation argument preservation must be established by authorization,
# independently of a successful visudo syntax check.
printf 'fic-sudo-probe ALL=(root) NOPASSWD: /usr/bin/printf allowed \\\n    argument\n' > /etc/sudoers
if visudo -c; then
    runuser -u fic-sudo-probe -- sudo -n /usr/bin/printf allowed argument > "$probe_directory/allowed"
    if runuser -u fic-sudo-probe -- sudo -n /usr/bin/printf forbidden > "$probe_directory/forbidden" 2>&1; then
        echo 'FAIL continuation dropped argument restrictions'
        exit 1
    fi
    echo 'PASS continuation preserves command argument restrictions'
elif sudo --version | head -1 | grep -q '^sudo-rs '; then
    echo 'PASS fail-closed rejection of unsupported continuation inside command arguments'
else
    echo 'FAIL classic continuation fixture rejected'
    exit 1
fi

printf 'fic-sudo-probe ALL=(root) NOPASSWD: /usr/bin/printf allowed argument, \\\n    /usr/bin/true\n' > /etc/sudoers
visudo -c
runuser -u fic-sudo-probe -- sudo -n /usr/bin/printf allowed argument > "$probe_directory/allowed"
runuser -u fic-sudo-probe -- sudo -n /usr/bin/true
if runuser -u fic-sudo-probe -- sudo -n /usr/bin/printf forbidden > "$probe_directory/forbidden" 2>&1; then
    echo 'FAIL command-list continuation widened permissions'
    exit 1
fi
echo 'PASS command-list continuation preserves arguments and inherited NOPASSWD'

# Authentication expectation with an expired timestamp; harmless printf is
# the only command the user may execute.
printf 'fic-sudo-probe ALL=(root) PASSWD: /usr/bin/printf allowed argument\n' > /etc/sudoers
visudo -c
if runuser -u fic-sudo-probe -- sudo -n /usr/bin/printf allowed argument > "$probe_directory/password" 2>&1; then
    echo 'FAIL PASSWD bypassed authentication'
    exit 1
fi
echo 'PASS PASSWD requires authentication'
