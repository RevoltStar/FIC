#!/bin/sh
# Run ONLY inside the explicitly marked disposable VM.
set -eu
[ "$(cat /sys/class/dmi/id/product_name)" = FIC-Prelogin-Disposable ]
[ -f /etc/fic-prelogin-test-vm ]
probe=/usr/local/sbin/fic-prelogin-pam-probe
config=/opt/fic/config/GLOBAL.conf
cp -p "$config" /run/fic-prelogin-tests/global-before
trap 'cat /run/fic-prelogin-tests/global-before > "$config"' EXIT HUP INT TERM
getent passwd fic-prelogin-test-user >/dev/null || useradd --no-create-home fic-prelogin-test-user
mode() {
    sed -i "s/^incident_response_mode.status=.*/incident_response_mode.status=$1/;s/^incident_response_mode.value=.*/incident_response_mode.value=$2/" "$config"
}
allowed() { "$probe" "$1" fic-prelogin-test-user; }
denied() { if "$probe" "$1" fic-prelogin-test-user; then echo 'unexpected PAM account success' >&2; exit 1; fi; }
mode ENABLE PASSIVE
systemctl stop fic.service
allowed lightdm; allowed lightdm-autologin
mode DISABLE ACTIVE
allowed lightdm; allowed lightdm-autologin
echo 'OFF/PASSIVE are neutral without daemon PASS'
mode ENABLE ACTIVE
denied lightdm; denied lightdm-autologin
"$probe" login root
echo 'ACTIVE unavailable denies ordinary account; local root recovery PASS'
echo READY > /run/fic-prelogin-tests/case
systemctl start fic.service
allowed lightdm; allowed lightdm-autologin
echo ISOLATE > /run/fic-prelogin-tests/case
denied lightdm; denied lightdm-autologin
echo 'ACTIVE production serializer/transport/PAM account decision PASS'
