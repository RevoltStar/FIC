#!/usr/bin/env bash
# Disposable Docker only. Runtime has no host binds, ports or shared namespaces.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run-native.sh TAG PLATFORM BUILD_DIR' >&2; exit 2; }
tag=$1 platform=$2 build=$(realpath "$3")
case "$tag:$platform" in debian12:debian-12|debian13:debian-13|ubuntu2404:ubuntu-24.04|ubuntu2604:ubuntu-26.04|alt-p11:alt-p11) ;; *) exit 2;; esac
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
out="$repo/build-sysctl-validation/$platform";mkdir -p "$out"
docker run --rm --network none -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
 -v "$repo:/src:ro" -v "$build:/build" "fic-package-native:$tag" sh -ec '
 cmake -S /src -B /build -DFIC_TARGET_PLATFORM="$1"
 cmake --build /build --target sysctl_native_driver sysctl_ownership_tests sysctl_configuration_tests -j2
 ' sh "$platform" > "$out/build.log" 2>&1
docker run --rm --network none --cap-drop DAC_OVERRIDE --cap-drop DAC_READ_SEARCH \
 -v "$repo:/src:ro" -v "$build:/build" "fic-ssh-lifecycle-native:$tag" \
 ctest --test-dir /build -R '^sysctl_(configuration|ownership)_tests$' --output-on-failure > "$out/unit.log" 2>&1
name="fic-sysctl-$platform-$$"
finish(){
 docker exec "$name" journalctl -u systemd-sysctl.service -n 50 --no-pager > "$out/loader-journal.log" 2>&1 || true
 docker rm -f "$name" >/dev/null 2>&1 || true
}
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp \
 -e container=docker -e FIC_SYSCTL_NATIVE=1 -e FIC_HOST_NET="$(stat -Lc %i /proc/self/ns/net)" \
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
docker cp "$repo/tests/integration/sysctl-ownership/prefix_probe.py" "$name:/usr/local/bin/prefix-probe.py"
docker exec "$name" python3 /usr/local/bin/prefix-probe.py > "$out/prefix.json" 2> "$out/prefix.log"
docker cp "$build/tests/sysctl_native_driver" "$name:/usr/local/bin/fic-sysctl-native-driver"
docker exec "$name" /usr/local/bin/fic-sysctl-native-driver > "$out/backend.json" 2> "$out/backend.log"
python3 - "$out/backend.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['status']=='PASS'
PY
printf 'PASS native SYSCTL %s\n' "$platform"
