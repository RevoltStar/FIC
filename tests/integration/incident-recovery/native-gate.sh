#!/bin/bash
# Run ONLY in a disposable Docker container; never mount host /etc or /opt/fic.
set -euo pipefail
[[ -f /.dockerenv && $(id -u) == 0 ]] || exit 2
binary=${1:?recovery_exemption_policy_tests path required}
getent group fic >/dev/null || groupadd -r fic
# These are the existing compiled production paths, not a reader override.
install -d -o root -g fic -m 2750 /opt/fic /opt/fic/config
printf '_schema_version=1\nlock_exempt_fic_members.status=ENABLE\n' > /opt/fic/config/GLOBAL.conf
printf '_schema_version=1\nlog_level=NoLog\n' > /opt/fic/config/AUDIT.conf
chown root:fic /opt/fic/config/{GLOBAL,AUDIT}.conf
chmod 640 /opt/fic/config/{GLOBAL,AUDIT}.conf
result=$(FIC_RECOVERY_NATIVE_GATE=container-only "$binary" --native)
printf '%s\n' "$result"
[[ "$result" == *"native production recovery policy/secure reader/status mutations: PASS"* ]]
