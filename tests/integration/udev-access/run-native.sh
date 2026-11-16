#!/usr/bin/env bash
# Only disposable Docker: no host binds/devices/network/namespaces or uevents.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-native.sh IMAGE BUILD_DIR' >&2; exit 2; }
image=$1 build=$2
[[ -x "$build/tests/udev_access_readiness_tests" ]]
name="fic-udev-access-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none \
  --tmpfs /run --tmpfs /tmp -e container=docker "$image" sh -ec \
  'mount -o remount,ro /sys; mount --bind /proc/sys /proc/sys; mount -o remount,bind,ro /proc/sys; exec /sbin/init' >/dev/null
docker inspect "$name" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0];h=c["HostConfig"]
assert h["NetworkMode"]=="none" and h["CgroupnsMode"]=="private"
assert not h["Binds"] and not h["PidMode"] and not h["PortBindings"] and h["IpcMode"]!="host"
assert all(m["Type"]=="tmpfs" for m in c["Mounts"])
'
docker cp "$build/tests/udev_access_readiness_tests" "$name:/usr/local/bin/fic-udev-access-test"
docker exec -i "$name" timeout 90 bash -se <<'NATIVE'
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
