#!/usr/bin/env bash
# Runtime has no host mounts, ports or network. Docker explicitly authorized.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run-native.sh IMAGE PLATFORM R1|R1_MORE|R1_ABSENT|R2|R2_AUTH|R2_LAZY'; exit 2; }
image=$1 platform=$2 stage=$3
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11) ;; *) exit 2;; esac
case "$stage" in R1|R1_MORE|R1_ABSENT|R2|R2_AUTH|R2_LAZY) ;; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
build="$repo/build-sssd-research/$platform"
mkdir -p "$build/$stage"
docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build:rw" "$image" sh -ec 'cmake -S /src/tests/integration/sssd-research -B /build -DFIC_TARGET_PLATFORM="$1"; cmake --build /build --target sssd_engine_probe -j2' sh "$platform"
name="fic-sssd-$stage-$platform-$$"
finish() { docker exec "$name" tar -C /run/sssd-research-out -cf - . 2>/dev/null | tar -C "$build/$stage" -xf - || true; docker rm -f "$name" >/dev/null 2>&1 || true; }
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp -e container=docker -e FIC_SSSD_RESEARCH=1 -e FIC_SSSD_ALT_ROOT_FIXTURE="${FIC_SSSD_ALT_ROOT_FIXTURE:-0}" -e FIC_SSSD_HOST_MNT="$(stat -Lc %i /proc/self/ns/mnt)" "$image" >/dev/null
docker inspect "$name" > "$build/$stage/container.json"
python3 - "$build/$stage/container.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))[0];h=c['HostConfig']
assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private' and not h['PidMode'] and h['IpcMode']!='host'
assert not h['Binds'] and not h['PortBindings'] and all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true; mkdir -p /run/sssd-research-out'
docker cp "$build/sssd_engine_probe" "$name:/usr/local/bin/sssd-engine-probe"
for script in common.py "${stage,,}.py"; do docker cp "$repo/tests/integration/sssd-research/$script" "$name:/usr/local/bin/$script"; done
if [[ "$stage" == R2* ]]; then docker cp "$repo/tests/integration/sssd-research/pam-probe.py" "$name:/usr/local/bin/pam-probe.py"; fi
docker exec "$name" python3 "/usr/local/bin/${stage,,}.py" "$platform"
