#!/usr/bin/env bash
# Research only, stock distro packages in an independent disposable PID1 container.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-native.sh IMAGE ubuntu2404|ubuntu2604' >&2; exit 2; }
image=$1 row=$2
case "$row" in ubuntu2404|ubuntu2604) ;; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
out="$repo/build-ubuntu-socket-research/$row"
mkdir -p "$out"
name="fic-socket-research-$row-$$"
marker=$(cat /proc/sys/kernel/random/uuid)
namespace=$(stat -Lc '%d:%i' /proc/self/ns/mnt)
cleanup() {
 docker exec "$name" tar -C /run/fic-socket-research/results -cf - . 2>/dev/null | tar -C "$out" -xf - || true
 docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp \
 -e container=docker -e FIC_SOCKET_RESEARCH="$marker" -e FIC_SOCKET_HOST_NS="$namespace" "$image" >/dev/null
docker inspect "$name" > "$out/container.json"
python3 - "$out/container.json" <<'PY'
import json, sys
c=json.load(open(sys.argv[1]))[0]
assert c['HostConfig']['NetworkMode']=='none' and c['HostConfig']['CgroupnsMode']=='private'
assert not c['HostConfig']['Binds'] and not c['HostConfig']['PidMode'] and not c['HostConfig']['PortBindings']
assert all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep 0.1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true'
docker cp "$repo/tests/integration/ssh-ubuntu-socket-research/research.py" "$name:/usr/local/bin/fic-socket-research.py"
docker exec "$name" python3 /usr/local/bin/fic-socket-research.py
