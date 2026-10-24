#!/usr/bin/env bash
# ONLY disposable containers. No published ports, host binds or host namespaces.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-native.sh IMAGE debian-12|debian-13|ubuntu-24.04|ubuntu-26.04' >&2; exit 2; }
image=$1 platform=$2
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04) ;; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)
build="$repo/build-openssh-native/$platform"
mkdir -p "$build/evidence"
docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build" "$image" \
 sh -ec 'cmake -S /src/tests/integration/verified_config_service/openssh_native -B /build -DFIC_TARGET_PLATFORM="$1"; cmake --build /build --target openssh_native_driver -j2' sh "$platform"
# The unprivileged runner may not inspect root PID1's namespace; its own
# namespace is the one Docker must NOT reuse (no --pid/--network/--mount host).
host_mnt=$(stat -Lc '%d:%i' /proc/self/ns/mnt)
host_root=$(stat -Lc '%d:%i' /)
token=$(cat /proc/sys/kernel/random/uuid)
name="fic-openssh-$platform-$$"
host_units() {
 for p in /etc/ssh/sshd_config /etc/default/ssh /etc/systemd/system/ssh.service /usr/lib/systemd/system/ssh.service /lib/systemd/system/ssh.service; do
  if [[ -f "$p" && -r "$p" ]]; then sha256sum "$p"; elif [[ -e "$p" ]]; then echo "UNREADABLE $p"; else echo "ABSENT $p"; fi
 done
}
host_units > "$build/host-before.txt"
finish() {
 # systemd may remount /run in its live namespace; Docker archive/cp can see
 # the underlying rootfs instead. Export only the sanitized result directory.
 docker exec "$name" tar -C /run/fic-openssh-results -cf - . 2>/dev/null | tar -C "$build/evidence" -xf - || true
 docker rm -f "$name" >/dev/null 2>&1 || true
 host_units > "$build/host-after.txt"
 cmp "$build/host-before.txt" "$build/host-after.txt"
}
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none \
 --tmpfs /run --tmpfs /tmp -e container=docker \
 -e FIC_OPENSSH_DISPOSABLE="$token" -e FIC_OPENSSH_HOST_MNT="$host_mnt" -e FIC_OPENSSH_HOST_ROOT="$host_root" "$image" >/dev/null
docker inspect "$name" > "$build/container-inspect.json"
python3 - "$build/container-inspect.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))[0]
assert c['HostConfig']['NetworkMode'] == 'none'
assert c['HostConfig']['CgroupnsMode'] == 'private'
assert not c['HostConfig']['Binds'] and not c['HostConfig']['PortBindings']
assert not c['HostConfig']['PidMode'] and not c['HostConfig']['IpcMode'] == 'host'
assert all(m['Type'] == 'tmpfs' and m['Destination'] in ('/run', '/tmp') for m in c['Mounts']), 'no host binds/volumes in runtime container'
PY
docker exec "$name" timeout 60 sh -ec '
 until systemctl show-environment >/dev/null 2>&1; do sleep 0.1; done
 systemctl is-system-running --wait >/dev/null 2>&1 || true
 case "$(systemctl is-system-running)" in running|degraded) ;; *) exit 1;; esac
 mkdir -m 700 /run/fic-openssh-work /run/fic-openssh-results
 printf %s "$FIC_OPENSSH_DISPOSABLE" > /run/fic-openssh-work/runner-marker
'
docker cp "$build/openssh_native_driver" "$name:/usr/local/bin/fic-openssh-driver"
docker cp "$repo/tests/integration/verified_config_service/openssh_native/harness.py" "$name:/usr/local/bin/fic-openssh-harness.py"
if [[ "$platform" == ubuntu-* ]]; then
 docker cp "$repo/tests/integration/verified_config_service/openssh_native/ubuntu_socket.py" "$name:/usr/local/bin/fic-ubuntu-socket.py"
 docker exec "$name" python3 /usr/local/bin/fic-ubuntu-socket.py
else
 docker exec "$name" python3 /usr/local/bin/fic-openssh-harness.py
fi
