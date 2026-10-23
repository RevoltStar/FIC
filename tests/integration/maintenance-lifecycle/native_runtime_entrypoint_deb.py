"""Actual FIC ELF + native dpkg prerequisite/preinst, dummy package payload.

This is NOT the final FIC package lifecycle: configure/finalizer/erase/recovery
are deliberately not modelled by a successful package transaction here.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

assert os.environ.get("FIC_MAINTENANCE_NATIVE") == "1"
assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
assert Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
verify_only = len(sys.argv) == 3 and sys.argv[2] == "verify-refusals"
assert verify_only or not Path("/var/lib/fic-lifecycle").exists(), "fresh canonical lifecycle fixture required"
root = Path(tempfile.mkdtemp(prefix="m1-runtime-entrypoint-", dir="/var/lib"))
runtime = "/usr/libexec/fic/fic-runtime"


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    print(result.stdout + result.stderr, end="", flush=True)
    if check:
        assert result.returncode == 0, (args, result.returncode)
    return result


def security_snapshot():
    result = {}
    for directory in (Path("/etc/pam.d"), Path("/etc/ssh"), Path("/opt/fic")):
        for path in [directory, *directory.rglob("*")]:
            if not os.path.lexists(path):
                result[str(path)] = None
            else:
                info = path.lstat()
                content = os.readlink(path) if path.is_symlink() else (
                    hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "directory")
                result[str(path)] = (info.st_ino, info.st_mode, info.st_uid, info.st_gid, content)
    return result


def verify_refusals():
    before = security_snapshot()
    state = Path("/var/lib/fic-lifecycle/state.json").read_bytes()
    refused = run(sys.argv[1], "--maintenance", "package-prepare", "upgrade", "1", "1", check=False)
    assert refused.returncode != 0 and "executing engine differs" in refused.stderr
    for command, action, version, abi in (("package-prepare", "upgrade", "wrong", "1"),
                                        ("package-prepare", "upgrade", "1", "2")):
        refused = run(runtime, "--maintenance", command, action, version, abi, check=False)
        assert refused.returncode != 0 and "runtime prerequisite" in refused.stderr
    assert security_snapshot() == before and Path("/var/lib/fic-lifecycle/state.json").read_bytes() == state
    print("PASS: copied engine/version/ABI mismatch refused before security mutations")


if verify_only:
    verify_refusals()
    sys.exit(0)


def package(name, version, payload=False, request="1"):
    tree = root / (name + "-" + version)
    control = tree / "DEBIAN"
    control.mkdir(parents=True)
    metadata = f"Package: {name}\nVersion: {version}\nArchitecture: all\nMaintainer: M1 native <fixture@example.invalid>\nDescription: disposable runtime entrypoint fixture\n"
    if not payload:
        metadata += "Pre-Depends: fic-runtime (= 1)\n"
        script = control / "preinst"
        script.write_text("#!/bin/sh\nset -e\n" + runtime + " --maintenance package-prepare install " + request + " 1\n")
    else:
        target = tree / runtime.lstrip("/")
        target.parent.mkdir(parents=True)
        shutil.copyfile(sys.argv[1], target)
        target.chmod(0o755)
        script = control / "postinst"
        script.write_text("#!/bin/sh\nset -e\nif " + runtime +
                          " --maintenance package-prepare install 1 1; then\n"
                          "  echo 'ERROR: half-configured runtime admitted' >&2; exit 99\nfi\n"
                          "test ! -e /var/lib/fic-lifecycle\n")
    script.chmod(0o755)
    (control / "control").write_text(metadata)
    archive = root / (name + "-" + version + ".deb")
    run("dpkg-deb", "--build", str(tree), str(archive))
    return str(archive)


for name in ("fic", "fic-runtime", "fic-m1-entrypoint-fixture"):
    assert run("dpkg-query", "-W", "-f=${Status}", name, check=False).returncode != 0, "fresh package DB required"
before = security_snapshot()
run("dpkg", "-i", package("fic-runtime", "1", payload=True))
assert security_snapshot() == before and not Path("/var/lib/fic-lifecycle").exists()
identity = run(runtime, "--build-info").stdout.splitlines()
assert "lifecycle_package_version=1" in identity and "lifecycle_abi=1" in identity
rejected = run("dpkg", "-i", package("fic-m1-entrypoint-fixture", "2", request="2"), check=False)
assert rejected.returncode != 0 and "runtime prerequisite" in rejected.stderr
assert security_snapshot() == before and not Path("/var/lib/fic-lifecycle").exists()
run("dpkg", "-i", package("fic-m1-entrypoint-fixture", "1"))
assert security_snapshot() == before, "preparation touched policy/PAM/incident resources"
assert Path("/var/lib/fic-lifecycle/state.json").is_file()
assert not Path("/opt/fic/db/mutation-journal.json").exists()
for unit in ("fic.service", "fic-device.service", "fic-notify.service",
             "fic_get_device_info.service", "fic_get_device_udev_info.service"):
    assert run("systemctl", "start", unit, check=False).returncode != 0
assert run(runtime, check=False).returncode != 0, "prepared operation allowed daemon startup"
verify_refusals()
print("PASS: real ELF native preinst, exact runtime version/ABI, half-configured refusal, fenced preparation; NOT full FIC lifecycle")
