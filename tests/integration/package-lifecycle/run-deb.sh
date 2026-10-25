#!/usr/bin/env bash
# No runtime host mounts, ports or host namespaces; actual DEBs are copied in.
set -euo pipefail
[[ $# == 2 || $# == 3 ]] || { echo 'usage: run-deb.sh IMAGE PACKAGE_DIRECTORY [deb_native.py|purge_failure_native.py]' >&2; exit 2; }
driver=${3:-deb_native.py}
case "$driver" in deb_native.py|purge_failure_native.py) ;; *) exit 2 ;; esac
image=$1 packages=$(realpath "$2")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
name="fic-deb-lifecycle-$$"
out="$repo/build-package-lifecycle/native-$(basename "$image")-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$out"
echo "Native evidence: $out"
finish() {
    docker cp "$name:/var/tmp/fic-package-results/." "$out/" >/dev/null 2>&1 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none \
    --tmpfs /run --tmpfs /tmp -e container=docker -e FIC_PACKAGE_LIFECYCLE_NATIVE=1 \
    -e FIC_HOST_MNT_INODE="$(stat -Lc %i /proc/self/ns/mnt)" "$image" >/dev/null
docker inspect "$name" > "$out/container.json"
python3 - "$out/container.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))[0]; h=c['HostConfig']
assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private'
assert not h['Binds'] and not h['PortBindings'] and not h['PidMode'] and h['IpcMode']!='host'
assert all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done'
docker exec "$name" timeout 60 sh -c 'systemctl is-system-running --wait >/dev/null 2>&1; exit 0'
docker exec "$name" mkdir -p /var/tmp/fic-packages
docker cp "$packages/." "$name:/var/tmp/fic-packages/"
docker cp "$repo/tests/integration/package-lifecycle/$driver" "$name:/usr/local/bin/deb-native.py"
docker exec "$name" python3 /usr/local/bin/deb-native.py
