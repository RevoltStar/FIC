#!/usr/bin/env bash
# Disposable runtime only; no host bindings or network ports.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run-remote-package.sh IMAGE PLATFORM PACKAGES'; exit 2; }
image=$1 platform=$2 packages=$(realpath "$3")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)
name="fic-ssh-package-$$"
out="$repo/build-ssh-lifecycle/remote-$platform-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$out"
finish() { docker cp "$name:/var/tmp/fic-package-results/." "$out/" >/dev/null 2>&1 || true; docker rm -f "$name" >/dev/null 2>&1 || true; }
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp -e container=docker -e FIC_PACKAGE_LIFECYCLE_NATIVE=1 -e FIC_HOST_MNT_INODE="$(stat -Lc %i /proc/self/ns/mnt)" "$image" >/dev/null
docker inspect "$name" > "$out/container.json"
python3 - "$out/container.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))[0];h=c['HostConfig']
assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private'
assert not h['Binds'] and not h['PortBindings'] and not h['PidMode'] and h['IpcMode']!='host'
assert all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true'
docker exec "$name" mkdir -p /var/tmp/fic-packages
docker cp "$packages/." "$name:/var/tmp/fic-packages/"
docker cp "$repo/tests/integration/verified_config_service/openssh_native/remote_package_cases.py" "$name:/usr/local/bin/remote-package.py"
docker exec "$name" python3 /usr/local/bin/remote-package.py "$platform"
echo "Native remote package evidence: $out"
