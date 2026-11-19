"""Real Debian 13 packages, daemon rollback, Linux-PAM and loopback LDAP."""
import ctypes as c
import ctypes.util
import json
import os
from pathlib import Path
import subprocess

assert os.environ.get("FIC_PACKAGE_LIFECYCLE_NATIVE") == "1"
assert Path("/proc/1/comm").read_text().strip() == "systemd"
assert os.stat("/proc/self/ns/mnt").st_ino != int(os.environ["FIC_HOST_MNT_INODE"])
assert {p.name for p in Path("/sys/class/net").iterdir()} == {"lo"}
assert "VERSION_ID=\"13\"" in Path("/etc/os-release").read_text()
out = Path("/var/tmp/fic-package-results")
out.mkdir()
slot = Path("/etc/pam.d/fic-empty-password")
common = Path("/etc/pam.d/common-auth")
selection = Path("/var/lib/pam/auth")
config = Path("/opt/fic/config/IDENTITY_ACCESS.conf")
name = "deny_empty_password_login"
journal = Path("/opt/fic/db/mutation-journal.json")
nonce = "fic-d13-fixture"
password = "Fixture-password-42"


def run(*args, expected=True, input=None, env=None):
    p = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, timeout=180, env=env)
    with (out / "commands.log").open("a") as log:
        print("EXIT", p.returncode, *args, "\n", p.stdout, file=log)
    print("EXIT", p.returncode, *args, flush=True)
    assert (p.returncode == 0) == expected, p.stdout
    return p.stdout


def policy(command, name=name, expected=True):
    return run("/opt/fic/bin/fic-cli", "policy", command, "IDENTITY_ACCESS", name,
               expected=expected)


class Message(c.Structure):
    _fields_ = [("style", c.c_int), ("text", c.c_char_p)]


class Response(c.Structure):
    _fields_ = [("text", c.c_void_p), ("code", c.c_int)]


Conversation = c.CFUNCTYPE(c.c_int, c.c_int, c.POINTER(c.POINTER(Message)),
                          c.POINTER(c.POINTER(Response)), c.c_void_p)


class Conv(c.Structure):
    _fields_ = [("callback", Conversation), ("data", c.c_void_p)]


pam = c.CDLL(ctypes.util.find_library("pam"))
libc = c.CDLL(None)
libc.calloc.argtypes = [c.c_size_t, c.c_size_t]
libc.calloc.restype = c.c_void_p
libc.strdup.argtypes = [c.c_char_p]
libc.strdup.restype = c.c_void_p
pam.pam_start.argtypes = [c.c_char_p, c.c_char_p, c.POINTER(Conv), c.POINTER(c.c_void_p)]
pam.pam_authenticate.argtypes = [c.c_void_p, c.c_int]
pam.pam_end.argtypes = [c.c_void_p, c.c_int]


def authenticate(user, token, expected):
    @Conversation
    def answer(count, messages, responses, data):
        allocation = libc.calloc(count, c.sizeof(Response))
        if not allocation:
            return 5
        entries = c.cast(allocation, c.POINTER(Response))
        for i in range(count):
            if messages[i].contents.style == 1:
                entries[i].text = libc.strdup(token.encode())
            elif messages[i].contents.style == 2:
                entries[i].text = libc.strdup(user.encode())
        responses[0] = entries
        return 0

    handle = c.c_void_p()
    conv = Conv(answer, None)
    assert pam.pam_start(nonce.encode(), user.encode(), c.byref(conv), c.byref(handle)) == 0
    rc = pam.pam_authenticate(handle, 0)
    pam.pam_end(handle, rc)
    print("PAM", user, "status", rc, flush=True)
    with (out / "pam.log").open("a") as log:
        print(user, rc, file=log)
    assert (rc == 0) == expected


def selected():
    return selection.read_text().splitlines().count("Module: fic-empty-password-hook")


def owned():
    data = json.loads(journal.read_text())
    return [item for item in data["records"] if item["resource"] == "capability/" + name
            and item["status"] == "applied"]


def native_domain_login():
    env = dict(os.environ, FIC_SSSD_RESEARCH="1",
               FIC_SSSD_HOST_MNT=os.environ["FIC_HOST_MNT_INODE"],
               FIC_SSSD_TEST_PAM_SERVICE=nonce)
    result = Path("/run/sssd-research-out/results.json")
    try:
        run("python3", "/usr/local/bin/r2_auth.py", "debian-13", "--online-only", env=env)
    finally:
        if result.exists():
            (out / "sssd.json").write_bytes(result.read_bytes())


try:
    run("findmnt", "-n", "-T", "/sys", "-o", "OPTIONS")
    run("mount", "--rbind", "/sys", "/sys")
    run("mount", "-o", "remount,bind,ro", "/sys")
    assert os.statvfs("/sys").f_flag & os.ST_RDONLY
    subprocess.run(["systemctl", "stop", "ssh.service", "ssh.socket"], check=False, timeout=30)
    run("/usr/local/bin/d13-ownership-tests")
    root = Path("/var/tmp/fic-packages")
    packages = [str(next(root.glob(p + "_*.deb"))) for p in ("fic-dick", "fic", "fic-cli")]
    run("dpkg", "-i", *packages)
    run("systemctl", "is-active", "fic.service")
    assert f"{name}.status=DISABLE" in config.read_text()
    assert f"{name}.value=ENABLE" in config.read_text()
    assert selected() == 1 and "substack fic-empty-password" in common.read_text()
    neutral = slot.read_bytes()

    Path(f"/etc/pam.d/{nonce}").write_text("@include common-auth\n")
    run("useradd", "fic-d13-empty")
    run("passwd", "-d", "fic-d13-empty")
    run("useradd", "fic-d13-password")
    run("chpasswd", input=f"fic-d13-password:{password}\n")
    run("useradd", "fic-d13-locked")
    run("chpasswd", input=f"fic-d13-locked:{password}\n")
    run("passwd", "-l", "fic-d13-locked")
    run("pam-auth-update", "--enable", "sss")
    before = common.read_bytes()
    choices = selection.read_bytes()
    assert b"pam_sss.so" in before and b"pam_unix.so nullok" in before
    authenticate("fic-d13-empty", "", True)

    policy("enable")
    policy("apply")
    witness = slot.read_bytes()
    records = owned()
    assert len(records) == 1 and f'mutation={records[0]["id"]}\n'.encode() in witness
    authenticate("fic-d13-empty", "", False)
    authenticate("fic-d13-password", password, True)
    authenticate("fic-d13-password", "wrong", False)
    authenticate("fic-d13-locked", password, False)
    assert common.read_bytes() == before and selection.read_bytes() == choices
    run("pam-auth-update", "--enable", "sss")
    policy("apply")
    assert owned() == records and slot.read_bytes() == witness and common.read_bytes() == before

    common.write_bytes(before.replace(b"pam_unix.so nullok", b"pam_unix.so nullresetok"))
    run("chage", "-d", "0", "fic-d13-empty")
    policy("apply")
    authenticate("fic-d13-empty", "", False)
    common.write_bytes(before)

    native_domain_login()

    # Changed foreign auth graph must be diagnosed on apply; rollback still
    # uses the exact slot and leaves the foreign change byte-for-byte intact.
    missing_hook = b"".join(line for line in before.splitlines(keepends=True)
                            if b"substack fic-empty-password" not in line)
    common.write_bytes(missing_hook)
    policy("apply", expected=False)
    policy("disable")
    assert common.read_bytes() == missing_hook and slot.read_bytes() == neutral
    policy("disable")
    assert not owned()
    strict = before.replace(b"pam_unix.so nullok", b"pam_unix.so")
    common.write_bytes(strict)
    policy("enable")
    policy("apply")
    assert not owned() and common.read_bytes() == strict
    policy("disable")
    assert common.read_bytes() == strict
    common.write_bytes(before)

    policy("enable", "enable_authentication_lockout")
    policy("apply", "enable_authentication_lockout")
    policy("enable")
    policy("apply")
    policy("apply", "enable_authentication_lockout")
    authenticate("fic-d13-empty", "", False)
    authenticate("fic-d13-password", password, True)
    password_stack = Path("/etc/pam.d/common-password").read_bytes()
    witness = slot.read_bytes()
    records = owned()
    run("dpkg", "-i", *packages)
    policy("apply")
    assert slot.read_bytes() == witness and owned() == records and selected() == 1
    assert Path("/etc/pam.d/common-password").read_bytes() == password_stack
    authenticate("fic-d13-empty", "", False)
    authenticate("fic-d13-password", password, True)

    saved = config.read_bytes()
    run("/opt/fic/bin/fic-cli", "prepare-uninstall")
    run("/opt/fic/bin/fic-cli", "policy", "rollback", "all")
    assert slot.read_bytes() == neutral and not owned() and config.read_bytes() == saved
    run("dpkg", "--remove", "fic-cli", "fic", "fic-dick")
    assert selected() == 0
    assert b"pam_sss.so" in common.read_bytes()
    assert b"fic-empty-password" not in common.read_bytes()
    assert all(b"fic-empty-password" not in path.read_bytes()
               for path in Path("/etc/pam.d").iterdir() if path.is_file() and path != slot)
    authenticate("fic-d13-empty", "", True)
    print("D13 empty-password native lifecycle passed", flush=True)
finally:
    diagnostic = subprocess.run(["journalctl", "--no-pager", "-u", "fic.service",
                                 "-u", "sssd.service"], text=True, capture_output=True)
    (out / "journal.log").write_text(diagnostic.stdout)
