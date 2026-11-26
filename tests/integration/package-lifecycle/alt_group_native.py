"""Real ALT p11 RPM removal with independent USER_CREATION and NSS ownership."""
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
    candidates = list(Path("/var/tmp/fic-packages").glob(name + "-*.rpm"))
    matches = [str(path) for path in candidates
               if run("rpm", "-qp", "--qf", "%{NAME}", str(path)) == name]
    assert len(matches) == 1, matches
    return matches[0]


packages = [package(name) for name in ("fic-dick", "fic", "fic-cli")]
backend = Path("/usr/lib/alterator/backend3/ldap-users")
role = Path("/etc/role")
common = Path("/etc/role.d/localadmins.role")
alt_role = Path("/etc/role.d/localadmins.fic")
useradd_defaults = Path("/etc/default/useradd")
nsswitch = Path("/etc/nsswitch.conf")
resources = (backend, role, common, useradd_defaults, nsswitch)
original = {file: file.read_bytes() for file in resources}

run("rpm", "-q", "libnss-role", "alterator-roles-common", "alterator-ldap-users")
dependencies = run("rpm", "-qp", "--requires", packages[1])
assert not any(dep.startswith(("alterator-ldap-users", "libnss-role"))
               for dep in dependencies.splitlines())
run("systemctl", "disable", "--now", "sshd.service")
run("chmod", "0400", "/etc/sudoers.d/99-sudopw")
run("visudo", "-c")
run("rpm", "-Uvh", *packages)
lifecycle = Path("/var/lib/fic-lifecycle/status")
assert lifecycle.read_text() == "INSTALLED\n"
run("systemctl", "is-active", "fic.service")

config = Path("/opt/fic/config/IDENTITY_ACCESS.conf")
values = {
    "user_default_supplementary_groups": ("audio", '["audio"]'),
    "alt_ldap_users_default_groups": ("video", '["video"]'),
    "alt_role_groups": ('{"localadmins":["audio"]}', '{"localadmins":["audio"]}'),
}
for policy, (editor_value, stored_value) in values.items():
    assert f"{policy}.status=DISABLE" in config.read_text()
    cli("policy", "set", "IDENTITY_ACCESS", policy, editor_value)
    assert f"{policy}.value={stored_value}" in config.read_text()
    cli("policy", "enable", "IDENTITY_ACCESS", policy)
    cli("policy", "apply", "IDENTITY_ACCESS", policy)

assert b"GROUPS=audio" in useradd_defaults.read_bytes()
assert b'default_groups="video"' in backend.read_bytes()
assert role.read_text() == "localadmins:audio\n"
assert common.readlink() == Path(alt_role.name)
assert alt_role.read_bytes() == original[common]
assert nsswitch.read_bytes() == original[nsswitch]
late = common.with_name("fic-lifecycle-late.role")
late_backup = late.with_suffix(".fic")
cli("policy", "set", "GLOBAL", "periodic_apply_min_pause", "0")
cli("policy", "set", "GLOBAL", "check_interval", "60")
run("systemctl", "restart", "fic.service")
late.write_text("localadmins:video\n")
deadline = time.monotonic() + 90
while not late.is_symlink() and time.monotonic() < deadline:
    time.sleep(0.5)
assert late.readlink() == Path(late_backup.name)
print("PASS periodic apply neutralized a new role file", flush=True)
saved = config.read_bytes()

# Bulk release leaves other domains able to complete when one ALT owner conflicts.
held_link = common.with_suffix(".saved")
common.rename(held_link)
common.symlink_to(alt_role.name)
foreign_inode = common.lstat().st_ino
cli("prepare-uninstall")
cli("policy", "rollback", "all", success=False)
assert common.lstat().st_ino == foreign_inode and common.is_symlink()
assert backend.read_bytes() == original[backend]
assert useradd_defaults.read_bytes() == original[useradd_defaults]
assert config.read_bytes() == saved
common.unlink()
held_link.rename(common)

# The real scriptlet retries the proven release under the durable uninstall fence.
run("rpm", "-e", "fic-cli", "fic")
assert lifecycle.read_text() == "REMOVED\n"
assert not Path("/opt/fic/bin/fic").exists()
assert config.read_bytes() == saved
assert not common.is_symlink() and not alt_role.exists()
assert not late.is_symlink() and not late_backup.exists()
assert late.read_text() == "localadmins:video\n"
assert all(file.read_bytes() == content for file, content in original.items())
journal = json.loads(Path("/opt/fic/db/mutation-journal.json").read_bytes())
for policy in values:
    records = [r for r in journal["records"] if r["policy"]["policy"] == policy]
    assert records and all(r["status"] == "rolled_back" for r in records)
run("rpm", "-e", "fic-dick")
(results / "result.json").write_text(json.dumps({"result": "PASS", "policies": list(values)}))
