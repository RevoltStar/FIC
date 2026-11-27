"""Real FIC RPM lifecycle with journal-bound PAM suppression."""
import json
import os
from pathlib import Path
import subprocess
import time

assert os.environ.get("FIC_PACKAGE_LIFECYCLE_NATIVE") == "1"
assert Path("/proc/1/comm").read_text().strip() == "systemd"
assert os.stat("/proc/self/ns/mnt").st_ino != int(os.environ["FIC_HOST_MNT_INODE"])
results = Path("/var/tmp/fic-package-results")
results.mkdir()
events = []


def run(*args, success=True):
    process = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=300)
    events.append({"command": args, "exit": process.returncode, "output": process.stdout})
    (results / "commands.json").write_text(json.dumps(events, indent=2))
    print("EXIT", process.returncode, " ".join(args), flush=True)
    assert (process.returncode == 0) == success, process.stdout
    return process.stdout


def cli(*args, success=True):
    return run("/opt/fic/bin/fic-cli", *args, success=success)


def package(name):
    candidates = Path("/var/tmp/fic-packages").glob(name + "-*.rpm")
    matches = [str(path) for path in candidates
               if run("rpm", "-qp", "--qf", "%{NAME}", str(path)) == name]
    assert len(matches) == 1, matches
    return matches[0]


service = Path("/etc/pam.d/lightdm")
stock = service.read_bytes()
assert b"user ingroup nopasswdlogin" in stock
run("systemctl", "disable", "--now", "sshd.service")
run("chmod", "0400", "/etc/sudoers.d/99-sudopw")
run("visudo", "-c")
run("rpm", "-Uvh", *[package(name) for name in ("fic-dick", "fic", "fic-cli")])
assert Path("/var/lib/fic-lifecycle/status").read_text() == "INSTALLED\n"
assert "disable_nopasswdlogin" in cli("policy", "list", "IDENTITY_ACCESS")
config = Path("/opt/fic/config/IDENTITY_ACCESS.conf")
assert "disable_nopasswdlogin.status=DISABLE" in config.read_text()
cli("policy", "enable", "IDENTITY_ACCESS", "disable_nopasswdlogin")
cli("policy", "apply", "IDENTITY_ACCESS", "disable_nopasswdlogin")
assert b"FIC_PAM_NOPASSWDLOGIN BEGIN" in service.read_bytes()
cli("policy", "set", "GLOBAL", "periodic_apply_min_pause", "0")
cli("policy", "set", "GLOBAL", "check_interval", "60")
run("systemctl", "restart", "fic.service")
# Explicit fixture external replacement with the installed stock bytes.
# Actual GDM RPM replacement is tested separately by upgrade-alt.sh.
service.write_bytes(stock)
deadline = time.monotonic() + 90
while b"FIC_PAM_NOPASSWDLOGIN BEGIN" not in service.read_bytes() and time.monotonic() < deadline:
    time.sleep(0.5)
assert b"FIC_PAM_NOPASSWDLOGIN BEGIN" in service.read_bytes()
print("PASS periodic repair after external stock-byte replacement", flush=True)

owned = b"# administrator\n" + service.read_bytes()
temporary = service.with_suffix(".native-test")
temporary.write_bytes(owned)
temporary.replace(service)
cli("policy", "apply", "IDENTITY_ACCESS", "disable_nopasswdlogin")
assert service.read_bytes() == owned
saved = config.read_bytes()
# A corrupt physical witness must block removal without damaging the file.
broken = owned.replace(b"FIC_PAM_NOPASSWDLOGIN BEGIN", b"FIC_PAM_NOPASSWDLOGIN BROKEN", 1)
service.write_bytes(broken)
cli("prepare-uninstall")
cli("policy", "rollback", "all", success=False)
assert service.read_bytes() == broken
assert Path("/var/lib/fic-lifecycle/status").read_text() == "UNINSTALLING\n"
service.write_bytes(owned)
run("rpm", "-e", "fic-cli", "fic")
assert service.read_bytes() == b"# administrator\n" + stock
assert config.read_bytes() == saved
assert Path("/var/lib/fic-lifecycle/status").read_text() == "REMOVED\n"
journal = json.loads(Path("/opt/fic/db/mutation-journal.json").read_bytes())
records = [r for r in journal["records"] if r["policy"]["policy"] == "disable_nopasswdlogin"]
assert records and all(r["status"] == "rolled_back" for r in records)
run("rpm", "-e", "fic-dick")
(results / "result.json").write_text(json.dumps({"result": "PASS", "policy": "disable_nopasswdlogin"}))
