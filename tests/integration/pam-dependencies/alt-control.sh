#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 || ( $# == 2 && $2 == --i5 ) ]] || { echo 'usage: alt-control.sh ALT_BUILD_DIR [--i5]'; exit 2; }
build=$(realpath "$1");repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
if [[ ${2:-} == --i5 ]]; then
 out="$repo/build-pam-i5"; mkdir -p "$out"
 stem=${FIC_ALT_CONTROL_STEM:-native-control}
 [[ $stem =~ ^[a-zA-Z0-9-]+$ ]] || exit 2
 docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build:ro" -v "$out:/evidence" \
  fic-pam-dependencies-native:alt-p11 sh -ec '
   mkdir -p /opt/fic/bin /opt/fic/log /opt/fic/config /opt/fic/data /run/fic
   cp /build/fic/fic /opt/fic/bin/fic
   cp /build/fic/pam_fic_pwtxn.so /lib64/security/pam_fic_pwtxn.so
   chmod 755 /opt/fic/bin/fic /lib64/security/pam_fic_pwtxn.so
   cp /src/fic/src/resources/pam/fic-pwhistory.conf /etc/security/fic-pwhistory.conf
   cp /src/packaging/rpm/fic-pam-faillock /src/packaging/rpm/fic-pam-pwhistory /etc/control.d/facilities/
   chmod 755 /etc/control.d/facilities/fic-pam-*
   rpm -q pam-config control libpam0 libpasswdqc > /evidence/versions.log
   rpm -qf /lib64/security/pam_tcb.so >> /evidence/versions.log
   rpm -ql pam-config > /evidence/pam-config-files.log
   cat /etc/control.d/facilities/system-auth /etc/control.d/facilities/system-policy > /evidence/native-control-scripts.log
   /build/tests/pam_dependency_contract_tests --alt-control-i5 /evidence/"$1".json
  ' sh "$stem" > "$out/$stem.log" 2>&1
 python3 "$repo/tests/integration/pam-dependencies/check-i5-control.py" "$out/$stem.json"
 exit
fi
out="$repo/build-pam-r1-i3";mkdir -p "$out"
name="fic-pam-r1-alt-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" --network none --entrypoint /bin/sleep fic-ssh-lifecycle-native:alt-p11 infinity >/dev/null
docker exec "$name" mkdir -p /build/fic/generated/scripts/config
docker cp "$build/tests/pam_dependency_contract_tests" "$name:/usr/local/bin/pam-dependency-probe"
docker cp "$build/fic/generated/scripts/config/." "$name:/build/fic/generated/scripts/config/"
docker exec "$name" sh -c 'rpm -q pam-config control; rpm -qf /lib64/security/pam_passwdqc.so /lib64/security/pam_pwhistory.so; sha256sum /etc/control.d/facilities/system-auth' > "$out/alt-packages.log"
docker exec "$name" /usr/local/bin/pam-dependency-probe --alt-control /var/tmp/control.json > "$out/alt-control.log" 2>&1
docker cp "$name:/var/tmp/control.json" "$out/alt-control.json"
