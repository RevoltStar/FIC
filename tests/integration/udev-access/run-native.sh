#!/usr/bin/env bash
# Only disposable Docker: no host binds/devices/network/namespaces or uevents.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-native.sh IMAGE BUILD_DIR' >&2; exit 2; }
image=$1 build=$2
[[ -x "$build/tests/udev_access_readiness_tests" ]]
name="fic-udev-access-$$"
container_id=''
trap 'if [[ -n "$container_id" ]]; then docker rm -f "$container_id" >/dev/null 2>&1 || true; fi' EXIT
# Keep Docker's default seccomp/AppArmor/device restrictions. In particular do
# not grant SYS_ADMIN or remount the host's cgroup hierarchy to make PID1 boot.
udev_bootstrap=$(cat <<'BOOT'
python3 - <<'CHECK'
import os
for p in ("/sys", "/proc/sys"):
    assert os.statvfs(p).f_flag & os.ST_RDONLY, p + " must be read-only"
s = open("/proc/self/status").read().splitlines()
for cap in ("CapEff:", "CapPrm:", "CapInh:", "CapBnd:", "CapAmb:"):
    assert int(next(x.split()[1] for x in s if x.startswith(cap)), 16) == 0
assert next(x.split()[1] for x in s if x.startswith("Seccomp:")) == "2"
assert next(x.split()[1] for x in s if x.startswith("NoNewPrivs:")) == "1"
CHECK
exec /lib/systemd/systemd --log-target=console
BOOT
)
container_id=$(docker create -t --name "$name" --entrypoint /bin/sh --cap-drop ALL --security-opt no-new-privileges \
  --cgroupns=private --network none --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  -e container=docker "$image" -ec "$udev_bootstrap")
docker inspect "$container_id" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0];h=c["HostConfig"]
assert h["Privileged"] is False
assert h["NetworkMode"]=="none" and h["CgroupnsMode"]=="private"
assert not h["Binds"] and not h["PidMode"] and not h["PortBindings"] and h["IpcMode"]!="host"
assert not h["CapAdd"] and h["CapDrop"]==["ALL"]
assert h["SecurityOpt"]==["no-new-privileges"]
assert not h["Devices"] and not h["DeviceRequests"] and not h["DeviceCgroupRules"]
assert all(m["Type"]=="tmpfs" and m["Destination"] in ("/run","/run/lock","/tmp") for m in c["Mounts"])
assert "/proc/sys" in h["ReadonlyPaths"]
'
docker start "$container_id" >/dev/null
if ! docker exec "$container_id" timeout 15 sh -ec '
  until systemctl show-environment >/dev/null 2>&1; do sleep .1; done
'; then
  docker logs "$container_id" >&2
  echo 'SKIP native udev scenarios 1–5: restricted Docker cannot provide a working systemd manager. Use a disposable VM or an independently isolated delegated systemd test environment; no privileged fallback.' >&2
  exit 77
fi
docker cp "$build/tests/udev_access_readiness_tests" "$container_id:/usr/local/bin/fic-udev-access-test"
docker exec -i "$container_id" timeout 90 bash -se <<'NATIVE'
export SYSTEMD_PAGER=cat
[[ $(cat /proc/1/comm) == systemd ]]
timeout 30 bash -c 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done'
mkdir -m700 /run/fic-udev-access-native
# Fixture-only permission to run manager AND its sockets with sysfs RO.
# Debian conditions otherwise silently skip socket activation in containers.
for unit in systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket; do
  mkdir -p "/run/systemd/system/$unit.d"
  printf '[Unit]\nConditionPathIsReadWrite=\n' > "/run/systemd/system/$unit.d/fixture.conf"
done
systemctl daemon-reload
expect() {
  local rc=0
  /usr/local/bin/fic-udev-access-test --native > "/run/fic-udev-access-native/$1.log" || rc=$?
  cat "/run/fic-udev-access-native/$1.log"
  [[ $rc == "$2" ]]
  echo "PASS $1"
}
systemctl stop systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket
expect stopped 10 # Rules out chroot success-without-ping behavior.
systemctl start systemd-udevd.service
expect responding 0
systemctl kill --kill-who=main --signal=STOP systemd-udevd.service
expect unresponsive 10
systemctl kill --kill-who=main --signal=CONT systemd-udevd.service
expect recovered 0
systemctl stop systemd-udevd.service
systemctl start systemd-udevd-control.socket
expect socket-activation 0
systemctl stop systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket
echo 'PASS native udev control observations; no triggers/settle/uevents/device mutations'
NATIVE
