#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-package.sh DEBIAN12_PACKAGES BUILD_DIR'; exit 2; }
packages=$(realpath "$1")
build=$(realpath "$2")
daemon_sha=$(sha256sum "$build/fic/fic" | cut -d' ' -f1)
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
platform=debian-12;tag=debian12
out="$repo/build-sysctl-validation/package-debian12";mkdir -p "$out"
name="fic-sysctl-package-$$"
finish(){ docker cp "$name:/var/tmp/sysctl-package-results/." "$out/" >/dev/null 2>&1 || true;docker rm -f "$name" >/dev/null 2>&1 || true; }
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp \
 -e container=docker -e FIC_SYSCTL_NATIVE=1 -e FIC_EXPECTED_DAEMON_SHA256="$daemon_sha" -e FIC_HOST_NET="$(stat -Lc %i /proc/self/ns/net)" \
 --entrypoint /bin/sh "fic-ssh-lifecycle-native:$tag" -ec '
 mount --make-rprivate /
 mount --bind /proc/sys /proc/sys
 mount --bind /proc/sys/net /proc/sys/net
 mount -o remount,bind,ro /proc/sys
 mount --rbind /sys /sys
 mount -o remount,bind,ro /sys
 exec /lib/systemd/systemd
 ' >/dev/null
docker inspect "$name" > "$out/container.json"
python3 - "$out/container.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))[0];h=c['HostConfig']
assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private' and not h['Binds'] and not h['PortBindings'] and not h['PidMode'] and h['IpcMode']!='host'
assert all(x['Type']=='tmpfs' and x['Destination'] in ('/run','/tmp') for x in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true'
docker exec "$name" python3 -c 'import os; assert os.statvfs("/proc/sys/kernel").f_flag & os.ST_RDONLY; assert not os.statvfs("/proc/sys/net").f_flag & os.ST_RDONLY'
docker exec "$name" mkdir -p /var/tmp/fic-packages
docker cp "$packages/." "$name:/var/tmp/fic-packages/"
docker cp "$repo/tests/integration/sysctl-ownership/package_cases.py" "$name:/usr/local/bin/sysctl-package-cases.py"
docker exec "$name" python3 /usr/local/bin/sysctl-package-cases.py
