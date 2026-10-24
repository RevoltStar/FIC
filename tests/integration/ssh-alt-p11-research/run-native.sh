#!/usr/bin/env bash
# Research only, stock distro packages in an independent disposable PID1 container.
set -euo pipefail
[[ $# == 1 ]] || { echo 'usage: run-native.sh IMAGE' >&2; exit 2; }
image=$1 row=alt-p11
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
out="$repo/build-alt-ssh-research/$row"
mkdir -p "$out"
name="fic-alt-ssh-research-$row-$$"
marker=$(cat /proc/sys/kernel/random/uuid)
namespace=$(stat -Lc '%d:%i' /proc/self/ns/mnt)
cleanup() {
 docker exec "$name" tar -C /run/fic-alt-ssh-research/results -cf - . 2>/dev/null | tar -C "$out" -xf - || true
 docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp \
 -e container=docker -e FIC_ALT_RESEARCH="$marker" -e FIC_ALT_HOST_ROOT="$(stat -Lc '%d:%i' /)" -e FIC_ALT_HOST_NS="$namespace" "$image" >/dev/null
docker inspect "$name" > "$out/container.json"
python3 - "$out/container.json" <<'PY'
import json, sys
c=json.load(open(sys.argv[1]))[0]
assert c['HostConfig']['NetworkMode']=='none' and c['HostConfig']['CgroupnsMode']=='private'
assert not c['HostConfig']['Binds'] and not c['HostConfig']['PidMode'] and not c['HostConfig']['PortBindings']
assert all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep 0.1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true'
docker cp "$repo/tests/integration/ssh-alt-p11-research/research.py" "$name:/usr/local/bin/fic-alt-ssh-research.py"
docker exec "$name" python3 /usr/local/bin/fic-alt-ssh-research.py
