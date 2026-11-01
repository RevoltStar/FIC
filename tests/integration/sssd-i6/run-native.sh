#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 2 && $# -le 3 ]] || { echo 'usage: run-native.sh IMAGE PLATFORM [SCENARIO]' >&2; exit 2; }
image=$1 platform=$2 scenario=${3:-positive}
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11);; *) exit 2;; esac
case "$scenario" in positive|stopped-apply|journal-invalid|relation-conflict|domain-key-drift|remaining-enabled-unowned|remaining-enabled-unowned-matching-foreign|acknowledgement-unowned-matching-foreign|late-foreign|foreign-relation|package-release-refusal|cas-drift|cleanup-failure|wrong-registry-generation|journal-finalization-failure|crash-before-save|crash-before-ack|runtime-generation-change|receipt-substitution|legacy-v2-awaiting|wrong-physical-witness|legacy-upgrade-applied|legacy-upgrade-prepared|legacy-upgrade-rollback-failed);; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
build="$repo/build-sssd-i6/$platform"
python3 "$repo/tests/integration/sssd-i6/source-manifest.py" check "$build/source-manifest.json"
python3 - "$build" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);r=json.loads((p/'build-receipt.json').read_text())
assert r['exit_code']==0 and r['clean_build'] and r['source_sha256']==json.loads((p/'source-manifest.json').read_text())
assert hashlib.sha256((p/'fic/fic').read_bytes()).hexdigest()==r['symbols_sha256']
for name,h in r['packages'].items():assert hashlib.sha256((p/'lifecycle-packages'/name).read_bytes()).hexdigest()==h,name
PY
legacy="$repo/build-sssd-i6/legacy-$platform"
if [[ "$scenario" == legacy-upgrade-* ]]; then
 python3 - "$legacy" <<'PY_LEGACY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);r=json.loads((p/'legacy-build-receipt.json').read_text())
assert r['exit_code']==0 and r['clean_build'] and r['base']=='4717cfd4af6df9297b1a6234759258a415dcea34' and r['source_tree']=='deec5ba63986ff9cd0ba875e92dda4df4e4caceb'
for name,h in r['packages'].items():assert hashlib.sha256((p/'lifecycle-packages'/name).read_bytes()).hexdigest()==h
assert hashlib.sha256((p/'fic/fic').read_bytes()).hexdigest()==r['symbols_sha256']
PY_LEGACY
fi
out="$build/native/$scenario";mkdir -p "$out";rm -f "$out/completion.json"
python3 "$repo/tests/integration/sssd-i6/source-manifest.py" --harness > "$out/harness-manifest.json"
name="fic-sssd-i6-$platform-$scenario-$$"
finish() {
 docker exec "$name" tar -C /run/sssd-research-out -cf - . 2>/dev/null | tar -C "$out" -xf - || true
 docker rm -f "$name" >/dev/null 2>&1 || true
}
trap finish EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none --tmpfs /run --tmpfs /tmp \
 -e container=docker -e FIC_SSSD_RESEARCH=1 -e FIC_SSSD_HOST_MNT="$(stat -Lc %i /proc/self/ns/mnt)" "$image" >/dev/null
docker inspect "$name" > "$out/container.json"
python3 - "$out/container.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))[0];h=c['HostConfig']
assert h['NetworkMode']=='none' and h['CgroupnsMode']=='private' and not h['PidMode'] and h['IpcMode']!='host'
assert not h['Binds'] and not h['PortBindings'] and all(m['Type']=='tmpfs' and m['Destination'] in ('/run','/tmp') for m in c['Mounts'])
PY
docker exec "$name" timeout 60 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done; systemctl is-system-running --wait >/dev/null 2>&1 || true; mkdir -p /run/sssd-research-out /var/tmp/fic-packages'
docker cp "$build/lifecycle-packages/." "$name:/var/tmp/fic-packages/"
docker cp "$build/fic/fic" "$name:/var/tmp/fic-symbols"
if [[ "$scenario" == legacy-upgrade-* ]]; then
 docker exec "$name" mkdir -p /var/tmp/fic-legacy-packages
 docker cp "$legacy/lifecycle-packages/." "$name:/var/tmp/fic-legacy-packages/"
 docker cp "$legacy/fic/fic" "$name:/var/tmp/fic-legacy-symbols"
fi
docker cp "$repo/tests/integration/sssd-research/common.py" "$name:/usr/local/bin/common.py"
docker cp "$repo/tests/integration/sssd-i6/native.py" "$name:/usr/local/bin/native.py"
docker cp "$repo/tests/integration/sssd-i6/debugger-fault.py" "$name:/usr/local/bin/debugger-fault.py"
docker exec "$name" python3 /usr/local/bin/native.py "$platform" "$scenario"
python3 "$repo/tests/integration/sssd-i6/source-manifest.py" check "$build/source-manifest.json"
python3 "$repo/tests/integration/sssd-i6/source-manifest.py" --harness check "$out/harness-manifest.json"
docker exec "$name" cat /run/sssd-research-out/results.json > "$out/results.json"
python3 - "$build" "$out" "$legacy" "$scenario" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);out=Path(sys.argv[2]);report=json.loads((out/'results.json').read_text())
assert report['experiments']['result']['status']=='PASS'
(out/'completion.json').write_text(json.dumps({'exit_code':0,'report_sha256':hashlib.sha256((out/'results.json').read_bytes()).hexdigest(),'build_receipt_sha256':hashlib.sha256((p/'build-receipt.json').read_bytes()).hexdigest(),'harness_sha256':json.loads((out/'harness-manifest.json').read_text()),'legacy_build_receipt_sha256':hashlib.sha256((Path(sys.argv[3])/'legacy-build-receipt.json').read_bytes()).hexdigest() if sys.argv[4].startswith('legacy-upgrade-') else None},indent=2)+'\n')
PY
