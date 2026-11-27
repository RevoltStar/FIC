"""Disposable systemd fixture and transport measurements. No FIC apply."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

assert Path("/proc/1/comm").read_text().strip() == "systemd"
assert Path("/.dockerenv").exists()
def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=60)
def systemctl(*args, check=True):
    return run("systemctl", *args, check=check)
def put(path, content):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
unit = "[Unit]\nDescription=FIC DM inventory fixture\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n"
for name in ("enabled", "runtime", "disabled", "custom-dm", "template@"):
    put("/etc/systemd/system/fic-dm-" + name + ".service", unit)
put("/etc/systemd/system-generators/fic-dm-fixture",
    '#!/bin/sh\ncat > "$1/fic-dm-generated.service" <<\'UNIT\'\n' + unit + 'UNIT\n')
os.chmod("/etc/systemd/system-generators/fic-dm-fixture", 0o755)
os.symlink("/dev/null", "/etc/systemd/system/fic-dm-masked.service")
os.symlink("fic-dm-enabled.service", "/etc/systemd/system/fic-dm-alias.service")
systemctl("daemon-reload")
systemctl("enable", "fic-dm-enabled.service")
systemctl("enable", "--runtime", "fic-dm-runtime.service")
systemctl("start", "fic-dm-template@instance.service", "fic-dm-custom-dm.service")
run("systemd-run", "--unit=fic-dm-transient", "/bin/sleep", "infinity")

args = ("list-unit-files", "--type=service", "--no-legend", "--no-pager")
def rows(root=False):
    output = systemctl(*(("--root=/",) if root else ()), *args).stdout
    return dict(line.split()[:2] for line in output.splitlines() if line.strip())
server, client = rows(), rows(True)
assert server == client, {"server_only": list(server.items() - client.items()),
                          "client_only": list(client.items() - server.items())}
expected = {"enabled": "enabled", "runtime": "enabled-runtime", "disabled": "disabled",
            "masked": "masked", "alias": "alias", "generated": "generated",
            "template@": "disabled", "transient": "transient", "custom-dm": "disabled"}
fixtures = {}
for name, state in expected.items():
    key = "fic-dm-" + name + ".service"
    assert server.get(key) == state, (key, server.get(key), state)
    fixtures[key] = state
loaded = systemctl("list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain").stdout
assert "fic-dm-template@instance.service" in loaded
units = sorted(set(server) | {line.split()[0] for line in loaded.splitlines() if line.strip()})
units = [u for u in units if not u.endswith("@.service")]
if "--setup-only" in sys.argv:
    Path("/evidence/fixtures.json").write_text(json.dumps({
        "version": systemctl("--version").stdout.splitlines()[0],
        "unit_files_equivalent": server == client, "fixtures": fixtures,
        "instance_in_loaded": True}, indent=2) + "\n")
    sys.exit(0)
prop = "--property=Id,Names,LoadState,ActiveState,Description,ExecStart,UnitFileState"
def blocks(text):
    result = {}
    for block in text.strip().split("\n\n"):
        values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        assert "Id" in values
        key = values["Id"]
        if key in result:
            assert result[key] == values
        result[key] = values
    return result
start = time.monotonic()
individual = {}
for u in units:
    individual.update(blocks(systemctl("show", u, "--no-pager", prop).stdout))
single_elapsed = time.monotonic() - start
start = time.monotonic()
batched = {}
for offset in range(0, len(units), 32):
    batched.update(blocks(systemctl("show", *units[offset:offset+32], "--no-pager", prop).stdout))
batch_elapsed = time.monotonic() - start
assert individual == batched, "batched properties differ"
missing = systemctl("show", "fic-dm-enabled.service", "fic-dm-missing.service", "--no-pager", prop, check=False)
partial = blocks(missing.stdout)
assert partial["fic-dm-missing.service"]["LoadState"] == "not-found"
# systemctl show batches still do per-unit D-Bus work, not one atomic snapshot.
timings = {}
for mode in ("server", "client"):
    samples, elapsed = [], []
    stop = threading.Event()
    def probe():
        while not stop.is_set():
            begin = time.monotonic()
            systemctl("show", "--property=Version")
            samples.append((time.monotonic() - begin) * 1000)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        future = pool.submit(probe)
        try:
            for _ in range(3):
                begin = time.monotonic()
                rows(mode == "client")
                elapsed.append(time.monotonic() - begin)
        finally:
            stop.set()
        future.result()
    timings[mode] = {"enumeration_seconds": elapsed,
                     "probe_samples": len(samples),
                     "max_probe_ms": max(samples),
                     "over_250ms": sum(x > 250 for x in samples)}
result = {"version": systemctl("--version").stdout.splitlines()[0], "pid1": "systemd",
          "unit_file_rows": len(server), "fixtures": fixtures, "equivalent": True,
          "concrete_instance_in_loaded": True, "show_units": len(units),
          "individual": {"processes": len(units), "seconds": single_elapsed},
          "batch32": {"processes": (len(units)+31)//32, "seconds": batch_elapsed, "equivalent": True},
          "missing_batch_exit": missing.returncode, "timings": timings}
Path("/evidence/result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
