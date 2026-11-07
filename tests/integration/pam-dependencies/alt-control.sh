#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'usage: alt-control.sh ALT_BUILD_DIR'; exit 2; }
build=$(realpath "$1");repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
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
