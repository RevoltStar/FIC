"""Preparation component only, in a disposable private systemd container.

Does not install FIC, finalize a lifecycle, or demonstrate package recovery.
Run setup, restart the container, then verify.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

assert os.environ.get("FIC_MAINTENANCE_NATIVE") == "1"
assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
assert Path("/run/.containerenv").exists() or Path("/.dockerenv").exists()
root = Path("/var/lib/m1-native-coordinator")
units = ("fic.service", "fic-device.service", "fic-notify.service",
         "fic_get_device_info.service", "fic_get_device_udev_info.service")


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=40)
    if check:
        assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result


def prepare(check=True):
    return run("/usr/local/bin/m1-coordinator", "prepare", check=check)


if sys.argv[1] == "setup":
    assert not root.exists(), "fresh coordinator fixture required"
    root.mkdir(mode=0o700)
    (root / "bin").mkdir()
    (root / "hash").mkdir()
    shutil.copyfile("/usr/local/bin/m1-coordinator", root / "runtime")
    shutil.copyfile("/usr/local/bin/m1-coordinator", root / "bin/fic")
    for path in (root / "runtime", root / "bin/fic"):
        path.chmod(0o755)
    for unit in units:
        assert not os.path.lexists(Path("/etc/systemd/system") / unit)
        assert (Path("/usr/lib/systemd/system") / unit).is_file(), "dummy units required"
    run("systemctl", "start", *units)
    run("systemctl", "stop", "fic-notify.service")
    foreign = Path("/etc/systemd/system/fic-notify.service")
    foreign.symlink_to("/dev/null")
    (root / "foreign-inode").write_text(str(foreign.lstat().st_ino))
    run("systemctl", "daemon-reload")
    first = prepare().stdout.strip()
    state = json.loads((root / "state/state.json").read_text())
    assert len(first) == 32 and state["id"] == state["mask_id"] == first
    assert state["version"] == 2 and state["phase"] == 0  # Installing
    assert not (root / "journal.json").exists()
    (root / "expected-id").write_text(first)
    (root / "bin/fic").unlink()  # simulate unpack after retained inventory
elif sys.argv[1] == "verify":
    expected = (root / "expected-id").read_text()
    assert prepare().stdout.strip() == expected
    assert not (root / "journal.json").exists()
    inventory = root / "state/operations" / expected / "writers.json"
    original = inventory.read_bytes()
    try:
        inventory.write_text("corrupt\n")
        refused = prepare(check=False)
        assert refused.returncode != 0 and "inventory" in refused.stderr
    finally:
        inventory.write_bytes(original)
    assert prepare().stdout.strip() == expected
else:
    raise AssertionError("unknown native stage")

for unit in units:
    assert run("systemctl", "show", unit, "-p", "MainPID", "--value").stdout.strip() == "0"
    assert run("systemctl", "start", unit, check=False).returncode != 0
foreign = Path("/etc/systemd/system/fic-notify.service")
assert foreign.readlink() == Path("/dev/null")
assert str(foreign.lstat().st_ino) == (root / "foreign-inode").read_text()
if sys.argv[1] == "verify":
    run("/usr/local/bin/m1-coordinator", "restore-fixture")
    assert str(foreign.lstat().st_ino) == (root / "foreign-inode").read_text()
    for unit in units:
        if unit != "fic-notify.service":
            assert not os.path.lexists(Path("/etc/systemd/system") / unit)
    run("systemctl", "daemon-reload")
print("PASS preparation component: " + sys.argv[1] +
      "; persistent masks, retained writer inventory, no journal/release/finalization", flush=True)
