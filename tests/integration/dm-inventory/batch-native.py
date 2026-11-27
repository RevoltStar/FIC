"""Compare the previous and current production inventory in a disposable fixture."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

assert Path("/proc/1/comm").read_text().strip() == "systemd"
assert Path("/.dockerenv").exists()
previous, current = sys.argv[1:3]
prop = "--property=Id,Names,LoadState,ActiveState,Description,ExecStart,UnitFileState"

def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(str(args) + "\n" + result.stdout + result.stderr)
    return result.stdout

# Known executable behind an unrelated unit name; no display manager package.
Path("/usr/local/bin/sddm").write_text("#!/bin/sh\nexec /bin/sleep infinity\n")
Path("/usr/local/bin/sddm").chmod(0o755)
Path("/etc/systemd/system/fic-unrelated-name.service").write_text(
    "[Service]\nExecStart=/usr/local/bin/sddm\n")
run("systemctl", "daemon-reload")
run("systemctl", "start", "fic-unrelated-name.service")
# Keep every raw response rather than dropping repeats in an Id-keyed map.
asked = ["fic-dm-enabled.service", "fic-dm-alias.service", "fic-dm-enabled.service"]
text = run("systemctl", "show", *asked, "--no-pager", prop)
raw = [dict(line.split("=",1) for line in block.splitlines())
       for block in text.strip().split("\n\n")]
assert all(p["Id"] == "fic-dm-enabled.service" for p in raw)
assert all(any(name in p["Names"].split() for p in raw) for name in asked)
runs = []
reference_names = None
reference_snapshot = None
# Warm manager-loaded set once so both modes see the same union.
warm = json.loads(run(previous))
# Compare every requested name's complete property projection, independently of
# the final DM classification. Do not collapse aliases into an Id-only map.
def properties_for(requested):
    output = run("systemctl", "show", *requested, "--no-pager", prop)
    blocks = [dict(line.split("=", 1) for line in block.splitlines())
              for block in output.strip().split("\n\n")]
    result = {}
    for name in requested:
        matches = [block for block in blocks if name in block["Names"].split()]
        assert matches, ("missing property response", name)
        assert all(block == matches[0] for block in matches), ("conflicting response", name)
        result[name] = matches[0]
    return result
all_names = warm["requested_names"]
individual_properties = {}
batch_properties = {}
for name in all_names:
    individual_properties.update(properties_for([name]))
for offset in range(0, len(all_names), 32):
    batch_properties.update(properties_for(all_names[offset:offset+32]))
assert individual_properties == batch_properties, "per-request property projection changed"
for repetition in range(3):
    for mode, executable in (("individual", previous), ("batch32", current)):
        stop = threading.Event()
        samples = []
        def probe():
            while not stop.is_set():
                begin = time.monotonic()
                run("systemctl", "show", "--property=Version")
                samples.append((time.monotonic()-begin)*1000)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(probe)
            try:
                result = json.loads(run(executable))
            finally:
                stop.set()
            future.result()
        names = result.pop("requested_names")
        assert len(names) == len(set(names)), "union duplicated a requested name"
        if reference_names is None:
            reference_names = sorted(names)
            reference_snapshot = result["snapshot"]
        assert sorted(names) == reference_names, "requested coverage changed"
        assert result["snapshot"] == reference_snapshot, "production classification changed"
        assert result["ok"] and result["snapshot"]["complete"]
        assert result["snapshot"]["managers"]["SDDM"]["running"]
        assert result["show_calls"] == (len(names) if mode == "individual" else (len(names)+31)//32)
        result.update(mode=mode, repetition=repetition, requested_count=len(names),
                      max_probe_ms=max(samples), probe_samples=len(samples),
                      over_250ms=sum(x > 250 for x in samples))
        runs.append(result)
missing_old = json.loads(run(previous, "--include-missing"))
missing_new = json.loads(run(current, "--include-missing"))
assert missing_old["ok"] and missing_new["ok"]
assert "fic-dm-nonexistent.service" in missing_new["requested_names"]
assert sorted(missing_old["requested_names"]) == sorted(missing_new["requested_names"])
assert missing_old["snapshot"] == missing_new["snapshot"]
out = {"property_equivalence": True, "missing_native_response": True, "fixtures": json.loads(Path("/evidence/fixtures.json").read_text()),
       "requested_names": reference_names, "classification": reference_snapshot,
       "alias_raw_blocks": len(raw), "alias_requested": asked, "runs": runs}
Path("/evidence/batch.json").write_text(json.dumps(out, indent=2)+"\n")
print(json.dumps(out, indent=2))
