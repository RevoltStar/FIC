"""Debian 13 D13-2 proof with real PAM, Google TOTP, and the existing SSSD fixture."""
import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

assert os.environ["FIC_PACKAGE_LIFECYCLE_NATIVE"] == "1"
assert Path("/proc/1/comm").read_text().strip() == "systemd"
assert os.stat("/proc/self/ns/mnt").st_ino != int(os.environ["FIC_HOST_MNT_INODE"])
assert {p.name for p in Path("/sys/class/net").iterdir()} == {"lo"}
assert 'VERSION_ID="13"' in Path("/etc/os-release").read_text()
out = Path("/var/tmp/fic-package-results")
out.mkdir(exist_ok=True)
pam = Path("/etc/pam.d")
common = pam / "common-auth"
slot = pam / "fic-mfa"
store = Path("/etc/security/fic-mfa")
proof = "/usr/local/bin/d13-mfa-proof"
auth = "/var/tmp/d13-pam-auth"
mock = "/var/tmp/d13-pam-outcome.so"
user = "fic-mfa-test"
empty = "fic-mfa-empty"
password = secrets.token_hex(24)


def run(*args, expected=True, input=None, env=None, timeout=90):
    p = subprocess.run(args, input=input, env=env, timeout=timeout,
                       capture_output=True, text=True)
    with (out / "commands.log").open("a") as log:
        print(p.returncode, " ".join(args), p.stdout, p.stderr, file=log)
    assert (p.returncode == 0) == expected, (args, p.returncode, p.stdout, p.stderr)
    return p


def authenticate(label, subject, primary, otp, expected, service="login", env=None):
    p = run(auth, service, subject, expected=expected, input=f"{primary}\n{otp}\n", env=env)
    print(label, p.stdout.strip(), flush=True)
    with (out / "pam.log").open("a") as log:
        print(label, p.stdout.strip(), p.stderr.strip(), file=log)
    return p


def prepare_secret(subject):
    key = secrets.token_bytes(20)
    secret = store / f"totp-{subject}"
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(base64.b32encode(key).decode() + '\n" TOTP_AUTH\n')
    return key, secret


def totp(key, step_offset=0):
    count = int(time.time()) // 30 + step_offset
    mac = hmac.new(key, count.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 15
    code = int.from_bytes(mac[offset:offset + 4], "big") & 0x7fffffff
    return f"{code % 1000000:06d}"


def wrong_totp(key):
    valid = {totp(key, step) for step in range(-2, 3)}
    return next(f"{code:06d}" for code in range(10) if f"{code:06d}" not in valid)


def structural(mode, expected=True, reason=None, service="login"):
    p = run(proof, mode, service, expected=expected)
    if reason:
        assert reason in p.stderr, p.stderr


def policy(command, name):
    run("/opt/fic/bin/fic-cli", "policy", command, "IDENTITY_ACCESS", name)


def exercise_flow_negs(generated, required):
    def negative(body, reason=None):
        common.write_text(body)
        structural("installed", False, reason)
        assert common.read_text() == body and slot.read_text() == required

    unix = r"(?m)^auth\s+\[success=\d+ default=ignore\]\s+pam_unix\.so([^\n]*)"
    negative(re.sub(unix, r"auth sufficient pam_unix.so\1", generated), "bypasses")
    negative(re.sub(unix, r"auth [success=done default=ignore] pam_unix.so\1", generated),
             "bypasses")
    if "pam_sss.so" in generated:
        sss = r"(?m)^auth\s+\[success=\d+ default=ignore\]\s+pam_sss\.so([^\n]*)"
        negative(re.sub(sss, r"auth sufficient pam_sss.so\1", generated), "bypasses")
    # A jump to an outer permit after the MFA substack.
    auth_entries = [line for line in generated.splitlines() if line.startswith("auth")]
    unix_index = next(i for i, line in enumerate(auth_entries) if "pam_unix.so" in line)
    bypass = len(auth_entries) - unix_index - 1
    if any(" include" in line or "\tinclude" in line for line in auth_entries):
        # Fixtures use one-rule faillock includes, preserving numeric size.
        assert all(len((pam / line.split()[-1]).read_text().splitlines()) >= 1
                   for line in auth_entries if "include" in line)
    negative(re.sub(unix, rf"auth [success={bypass} default=ignore] pam_unix.so\1",
                    generated) + "\nauth required pam_permit.so\n", "bypasses")
    negative(generated + "\nauth [success=reset default=ignore] pam_permit.so\n", "reset")
    negative(generated + "\nauth substack fic-mfa\n", "duplicate")
    negative(re.sub(r"(?m)^auth\s+substack\s+fic-mfa\s*$", "", generated))
    negative(generated + "\nauth include fic-unexpected\n")
    common.write_text(generated)
    slot.write_text(required.replace(" noskewadj", " nullok noskewadj"))
    structural("installed", False, "unsupported or untrusted content")
    slot.write_text(required)


def exercise_linux_pam(key, required):
    config = pam / "fic-mfa-controls"
    substack = pam / "fic-mfa-test-substack"
    try:
        config.write_text("auth required pam_unix.so\nauth substack fic-mfa-test-substack\n")
        factor = "auth [success=done default=die] "
        for result in ("success", "ignore", "auth_err", "system_err"):
            substack.write_text(factor + f"{mock} {result}\n")
            authenticate("mock-" + result, user, password, "-", result == "success", config.name)
        for control in ("required", "requisite"):
            substack.write_text(f"auth {control} {mock} ignore\n")
            authenticate(control + " with PAM_IGNORE and prior success", user,
                         password, "-", True, config.name)
        substack.write_text(required)
        p = authenticate("prior required password failure and real valid OTP", user,
                         "incorrect", totp(key), False, config.name)
        assert "otp_prompts=1" in p.stdout
        permissive = required.replace("[success=ok default=die]", "required")
        substack.write_text(permissive.replace(" noskewadj", " nullok noskewadj"))
        # Root has a password entry but no registration in this fixture.
        # Use the test module as a successful primary to isolate nullok.
        config.write_text(f"auth required {mock} success\nauth substack fic-mfa-test-substack\n")
        authenticate("real Google nullok with optional PAM_IGNORE", "root", "-", "-",
                     True, config.name)
        substack.write_text(required)
        config.write_text("auth requisite pam_unix.so\nauth substack fic-mfa-test-substack\n"
                          f"auth requisite {mock} token\n")
        env = dict(os.environ, FIC_FIXTURE_PASSWORD=password)
        authenticate("Google OTP leaves primary token intact", user, password, totp(key),
                     True, config.name, env)
        config.write_text("auth required pam_unix.so\nauth substack fic-mfa-test-substack\n"
                          f"auth required {mock} auth_err\n")
        for result in ("success", "ignore", "system_err"):
            substack.write_text(factor + f"{mock} {result}\n")
            p = authenticate("substack done/die remains inside boundary " + result,
                             user, password, "-", False, config.name)
            assert "mock:auth_err" in p.stderr
    finally:
        config.unlink(missing_ok=True)
        substack.unlink(missing_ok=True)


def exercise_sssd():
    primary = os.environ["FIC_FIXTURE_DOMAIN_PASSWORD"]
    key, registration = prepare_secret("research@test")
    try:
        structural("installed")
        p = authenticate("SSSD password and TOTP", "research@test", primary, totp(key), True)
        assert "password_prompts=1 otp_prompts=1" in p.stdout
        authenticate("SSSD password and invalid OTP", "research@test", primary, wrong_totp(key), False)
        authenticate("invalid SSSD password and valid OTP", "research@test", "incorrect", totp(key), False)
        p = authenticate("unqualified SSSD name is refused before OTP", "research", primary, totp(key), False)
        assert "otp_prompts=0" in p.stdout
        exercise_flow_negs(common.read_text(), slot.read_text())
        path = Path("/etc/sssd/sssd.conf")
        original = path.read_text()
        path.write_text(original.replace("pam_passkey_auth=false", "pam_passkey_auth=true"))
        try:
            structural("installed", False, "pam_passkey_auth")
        finally:
            path.write_text(original)
    finally:
        registration.unlink()


def main():
    run("mount", "--rbind", "/sys", "/sys")
    run("mount", "-o", "remount,bind,ro", "/sys")
    assert os.statvfs("/sys").f_flag & os.ST_RDONLY
    run("gcc", "-Wall", "-Wextra", "/var/tmp/auth.c", "-lpam", "-o", auth)
    run("gcc", "-Wall", "-Wextra", "-shared", "-fPIC", "/var/tmp/outcome.c", "-lpam", "-o", mock)
    run("dpkg-query", "-W", "libpam0g", "libpam-runtime", "libpam-google-authenticator", "libpam-sss")
    packages = Path("/var/tmp/fic-packages")
    run("dpkg", "-i", *(str(next(packages.glob(name + "_*.deb")))
                       for name in ("fic-dick", "fic", "fic-cli")), timeout=180)
    assert not slot.exists() and not Path("/usr/share/pam-configs/fic-mfa-hook").exists()
    run("pam-auth-update", "--disable", "sss")
    # libnss-sss edits both databases during installation. The password
    # proof keeps shadow local even after the fixture enables SSSD passwd.
    nss_file = Path("/etc/nsswitch.conf")
    nss = re.sub(r"(?m)^passwd:.*$", "passwd: files systemd", nss_file.read_text())
    nss_file.write_text(re.sub(r"(?m)^shadow:.*$", "shadow: files systemd", nss))
    run("useradd", user)
    run("chpasswd", input=f"{user}:{password}\n")
    run("useradd", empty)
    run("passwd", "-d", empty)
    store.mkdir(mode=0o700)
    key, registration = prepare_secret(user)
    empty_key, _ = prepare_secret(empty)
    (Path("/usr/share/pam-configs") / "fic-mfa-hook").write_text(run(proof, "profile").stdout)
    neutral = run(proof, "neutral").stdout
    required = run(proof, "required").stdout
    assert run(proof, "required").stdout == required
    slot.write_text(neutral)
    run("pam-auth-update", "--enable", "fic-mfa-hook")
    generated = common.read_text()
    (out / "common-auth.local").write_text(generated)
    structural("candidate", False, "empty local password")
    assert slot.read_text() == neutral and common.read_text() == generated
    structural("candidate", False, "unsupported", "cron")

    # Strict external Unix is sufficient, independent of D13-1 ownership.
    common.write_text(generated.replace("pam_unix.so nullok", "pam_unix.so"))
    structural("candidate")
    slot.write_text(required)
    structural("installed")
    authenticate("strict external Unix plus TOTP", user, password, totp(key), True)

    slot.write_text(neutral)
    common.write_text(generated)
    lockout = "enable_authentication_lockout"
    deny_empty = "deny_empty_password_login"
    for name in (lockout, deny_empty):
        policy("enable", name)
        policy("apply", name)
    structural("candidate")
    slot.write_text(required)
    structural("installed")
    p = authenticate("correct local password and TOTP", user, password, totp(key), True)
    assert "password_prompts=1 otp_prompts=1" in p.stdout
    tally = run("faillock", "--user", user).stdout
    authenticate("correct local password, invalid OTP", user, password, wrong_totp(key), False)
    assert run("faillock", "--user", user).stdout == tally
    authenticate("wrong local password, valid OTP", user, "incorrect", totp(key), False)
    assert run("faillock", "--user", user).stdout != tally
    authenticate("wrong local password, invalid OTP", user, "incorrect", wrong_totp(key), False)
    authenticate("empty local password, valid OTP", empty, "", totp(empty_key), False)
    authenticate("unknown user", "fic-mfa-missing", password, "invalid", False)
    authenticate("no OTP response", user, password, "-", False)
    original = registration.read_bytes()
    registration.unlink()
    authenticate("missing OTP registration", user, password, "-", False)
    registration.write_bytes(original)
    registration.chmod(0o644)
    structural("installed", False, "metadata")
    authenticate("wrong registration permissions", user, password, totp(key), False)
    registration.chmod(0o600)
    registration.write_text("!!!!\n")
    structural("installed", False, "TOTP-only")
    authenticate("corrupt registration", user, password, "invalid", False)
    registration.write_bytes(original)

    module = next(Path("/usr/lib").glob("*/security/pam_google_authenticator.so"))
    hidden = module.with_suffix(".hidden")
    module.rename(hidden)
    try:
        structural("installed", False, "missing or untrusted PAM module")
        authenticate("missing provider", user, password, totp(key), False)
    finally:
        hidden.rename(module)

    exercise_linux_pam(key, required)
    exercise_flow_negs(generated, required)

    # The existing policies must still be usable around the experimental slot.
    existing_guard = (pam / "fic-empty-password").read_bytes()
    policy("apply", deny_empty)
    assert (pam / "fic-empty-password").read_bytes() == existing_guard
    policy("apply", lockout)
    run("pam-auth-update", "--enable", "sss")
    (out / "common-auth.sssd").write_bytes(common.read_bytes())
    env = dict(os.environ, FIC_SSSD_RESEARCH="1",
               FIC_SSSD_HOST_MNT=os.environ["FIC_HOST_MNT_INODE"])
    run("python3", "/usr/local/bin/r2_auth.py", "debian-13", "--mfa-only", env=env, timeout=180)
    print("D13-2 real PAM and StructuralEffective passed", flush=True)


if sys.argv[1:] == ["--sssd"]:
    exercise_sssd()
else:
    try:
        main()
    finally:
        if store.is_dir():
            for credential in store.iterdir():
                credential.unlink()
            store.rmdir()
        diagnostics = subprocess.run(["journalctl", "--no-pager", "-u", "fic.service"],
                                     text=True, capture_output=True)
        (out / "daemon.log").write_text(diagnostics.stdout)
    (out / "result.json").write_text('{"ok": true, "suite": "d13_mfa_native"}\n')
