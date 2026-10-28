#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-native.sh IMAGE PLATFORM'; exit 2; }
image=$1 platform=$2
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11);; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
build="$repo/build-sssd-i1/$platform"
mkdir -p "$build/native"
docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build:rw" "$image" sh -ec 'cmake -S /src/tests/integration/sssd-i1 -B /build -DFIC_TARGET_PLATFORM="$1" >/build/configure.log; cmake --build /build --target sssd_i1_probe -j2 >/build/build.log 2>&1' sh "$platform"
container="fic-sssd-i1-$platform-$$"
finish() {
 docker exec "$container" tar -C /run/sssd-research-out -cf - . 2>/dev/null | tar -C "$build/native" -xf - || true
 docker rm -f "$container" >/dev/null 2>&1 || true
}
trap finish EXIT
docker run -d --name "$container" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp -e container=docker -e FIC_SSSD_RESEARCH=1 -e FIC_SSSD_HOST_MNT="$(stat -Lc %i /proc/self/ns/mnt)" "$image" >/dev/null
docker inspect "$container" > "$build/native/container.json"
python3 - "$build/native/container.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))[0];h=c['HostConfig']
assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private' and not h['PidMode'] and h['IpcMode']!='host'
assert not h['Binds'] and not h['PortBindings'] and all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$container" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true; mkdir -p /run/sssd-research-out'
docker cp "$build/sssd_i1_probe" "$container:/usr/local/bin/sssd-i1-probe"
docker cp "$repo/tests/integration/sssd-research/common.py" "$container:/usr/local/bin/common.py"
docker cp "$repo/tests/integration/sssd-i1/native.py" "$container:/usr/local/bin/native.py"
docker exec "$container" python3 /usr/local/bin/native.py "$platform"
