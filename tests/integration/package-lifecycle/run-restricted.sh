#!/usr/bin/env bash
# Real daemon gate only, not package-manager E2E. No runtime host mounts/network.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-restricted.sh IMAGE BUILT_FIC' >&2; exit 2; }
image=$1 binary=$2
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
[[ -f "$binary" ]] || exit 2
name="fic-lifecycle-foundation-$$"
host_mnt=$(stat -Lc '%i' /proc/self/ns/mnt)
finish() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none \
 --tmpfs /run --tmpfs /tmp -e container=docker \
 -e FIC_PACKAGE_LIFECYCLE_NATIVE=1 -e FIC_HOST_MNT_INODE="$host_mnt" "$image" >/dev/null
docker inspect "$name" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0]; h=c["HostConfig"]
assert h["NetworkMode"]=="none" and h["CgroupnsMode"]=="private"
assert not h["Binds"] and not h["PortBindings"] and not h["PidMode"] and h["IpcMode"]!="host"
assert all(m["Type"]=="tmpfs" and m["Destination"] in ("/run","/tmp") for m in c["Mounts"])
'
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done'
docker exec "$name" mkdir -p /opt/fic/bin
docker cp "$binary" "$name:/opt/fic/bin/fic"
docker cp "$repo/tests/integration/package-lifecycle/restricted_daemon.py" "$name:/usr/local/bin/restricted-daemon.py"
docker exec "$name" python3 /usr/local/bin/restricted-daemon.py
docker restart "$name" >/dev/null
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done'
docker exec "$name" python3 /usr/local/bin/restricted-daemon.py --resume-after-pid1-restart
echo 'PASS: PID1/container restart with fresh /run retains restricted durable admission'
