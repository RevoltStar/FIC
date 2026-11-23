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

from ssh_gate import exercise_ssh

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
        print(p.returncode, " ".join(map(str, args)), p.stdout, p.stderr, file=log)
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


def exercise_forward(subject, primary, key, registration, sssd):
    mode = "sssd" if sssd else "local"

    def render(part):
        return run(proof, part, "forward", mode).stdout

    service = pam / "xrdp-sesman"
    factor = pam / render("slot-name").strip()
    previous = service.read_bytes() if service.exists() else None
    assert not factor.exists()
    attachment = render("attachment") + "@include common-account\n@include common-session\n"
    service.write_text(attachment)
    factor.write_text(render("neutral"))
    try:
        run(proof, "candidate", "forward", mode, service.name)
        body = render("required")
        factor.write_text(body)
        run(proof, "installed", "forward", mode, service.name)

        accepted = run(auth, service.name, subject, "--lifecycle", input=f"{primary}{totp(key)}\n-\n")
        assert "authenticate=0 account=0 establish=0 open=0 close=0 delete=0 end=0" in accepted.stdout
        assert "password_prompts=1 otp_prompts=0" in accepted.stdout
        for label, given in (
            ("wrong password", "incorrect" + totp(key)),
            ("wrong OTP", primary + wrong_totp(key)),
            ("password only", primary),
            ("OTP only (empty password)", totp(key)),
        ):
            authenticate(f"forward {mode} {label}", subject, given, "-", False, service.name)
        original = registration.read_bytes()
        try:
            registration.unlink()
            authenticate(f"forward {mode} missing registration", subject, primary + totp(key),
                         "-", False, service.name)
            registration.write_text("!!!!\n")
            registration.chmod(0o600)
            authenticate(f"forward {mode} damaged registration", subject, primary + totp(key),
                         "-", False, service.name)
        finally:
            registration.write_bytes(original)
            registration.chmod(0o600)

        factor.write_text(body.replace(" forward_pass", ""))
        run(proof, "installed", "forward", mode, service.name, expected=False)
        factor.write_text(body)

        env = dict(os.environ, FIC_FIXTURE_PASSWORD=primary)
        service.write_text(attachment + f"auth required {mock} token\n")
        authenticate("extracted token equals original password", subject, primary + totp(key),
                     "-", True, service.name, env)
        service.write_text(f"auth optional {mock} seed-token\n" + attachment)
        run(proof, "installed", "forward", mode, service.name, expected=False)
        authenticate("forward_pass cannot use a previously seeded password", subject, totp(key),
                     "-", False, service.name, env)
    finally:
        factor.unlink()
        if previous is None:
            service.unlink()
        else:
            service.write_bytes(previous)


def exercise_sssd():
    domain = "research@test"
    primary = os.environ["FIC_FIXTURE_DOMAIN_PASSWORD"]
    local_password = os.environ["FIC_FIXTURE_LOCAL_PASSWORD"]
    local_key, empty_key = (
        base64.b32decode((store / f"totp-{name}").read_bytes().splitlines()[0])
        for name in (user, empty)
    )
    key, registration = prepare_secret(domain)
    nss = Path("/etc/nsswitch.conf")
    original_nss = nss.read_text()
    if os.environ.get("FIC_D13_SSH_CUTOVER") == "sssd":
        from mfa_cases import exercise_verified_cutover
        try:
            exercise_verified_cutover(run, domain, primary, lambda: totp(key), lambda: wrong_totp(key), True)
        finally:
            registration.unlink()
        return

    def matrix(label):
        for name, provider in ((user, "files"), (empty, "files"), (domain, "sss")):
            expected = run("getent", "-s", provider, "passwd", name).stdout
            assert run("getent", "passwd", name).stdout == expected
            # Each NSS order gets the same starting state. The previous
            # matrix deliberately leaves failed attempts in the tally.
            run("faillock", "--user", name, "--reset")
        run("getent", "-s", "files", "passwd", domain, expected=False)
        assert not any(line.partition(":")[0] == domain
                       for line in Path("/etc/shadow").read_text().splitlines())
        for name, correct, seed, supplied, otp_ok, success in (
            (user, local_password, local_key, True, True, True),
            (user, local_password, local_key, True, False, False),
            (user, local_password, local_key, False, True, False),
            (empty, "", empty_key, True, True, False),
            (domain, primary, key, True, True, True),
            (domain, primary, key, True, False, False),
            (domain, primary, key, False, True, False),
        ):
            result = authenticate(
                f"{label}: {name} primary={supplied} otp={otp_ok}",
                name, correct if supplied else "incorrect",
                totp(seed) if otp_ok else wrong_totp(seed), success)
            if success:
                assert "password_prompts=1 otp_prompts=1" in result.stdout

    try:
        group = re.search(r"(?m)^group:\s*(.+)$", original_nss).group(1).split()
        assert set(group) == {"files", "systemd", "sss"} and group[0] == "files"
        structural("installed")
        matrix("files sss (proven); systemd in group")
        for order in ("files systemd sss", "files sss systemd"):
            mixed = re.sub(r"(?m)^passwd:.*$", f"passwd: {order}", original_nss)
            mixed = re.sub(r"(?m)^shadow:.*$", "shadow: files systemd", mixed)
            nss.write_text(mixed)
            structural("installed", False, "systemd can overlap the SSSD namespace")
            matrix(f"{order} (sample only; Unsupported)")
        nss.write_text(re.sub(r"(?m)^shadow:.*$", "shadow: files systemd", original_nss))
        structural("installed", False, "unsupported NSS shadow route")
        nss.write_text(original_nss)
        p = authenticate("unqualified SSSD name is refused before OTP", "research", primary, totp(key), False)
        assert "otp_prompts=0" in p.stdout
        exercise_flow_negs(common.read_text(), slot.read_text())
        path = Path("/etc/sssd/sssd.conf")
        original = path.read_text()
        try:
            path.write_text(original.replace("pam_passkey_auth=false", "pam_passkey_auth=true"))
            structural("installed", False, "pam_passkey_auth")
            path.write_text(original.replace("[domain/test]\n", "[domain/test]\npwfield=x\n"))
            structural("installed", False, "domain/test/pwfield")
        finally:
            path.write_text(original)
        exercise_forward(domain, primary, key, registration, True)
        exercise_ssh(run, domain, primary, lambda: totp(key), lambda: wrong_totp(key),
                     registration, True)
    finally:
        nss.write_text(original_nss)
        registration.unlink()


def run_sssd_fixture(nss_file):
    run("pam-auth-update", "--enable", "sss")
    (out / "common-auth.sssd").write_bytes(common.read_bytes())
    nss = re.sub(r"(?m)^passwd:.*$", "passwd: files sss", nss_file.read_text())
    nss_file.write_text(re.sub(r"(?m)^shadow:.*$", "shadow: files", nss))
    env = dict(os.environ, FIC_SSSD_RESEARCH="1",
               FIC_FIXTURE_LOCAL_PASSWORD=password,
               FIC_SSSD_HOST_MNT=os.environ["FIC_HOST_MNT_INODE"])
    run("python3", "/usr/local/bin/r2_auth.py", "debian-13", "--mfa-only", env=env, timeout=420)


def main():
    run("mount", "--rbind", "/sys", "/sys")
    run("mount", "-o", "remount,bind,ro", "/sys")
    assert os.statvfs("/sys").f_flag & os.ST_RDONLY
    run("gcc", "-Wall", "-Wextra", "/var/tmp/auth.c", "-lpam", "-o", auth)
    run("gcc", "-Wall", "-Wextra", "-shared", "-fPIC", "/var/tmp/outcome.c", "-lpam", "-o", mock)
    run("gcc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "/var/tmp/ssh_observer.c",
        "-ldl", "-lpam", "-o", "/var/tmp/d13-ssh-observer.so")
    module_dir = next(Path("/usr/lib").glob("*/security/pam_google_authenticator.so")).parent
    run("install", "-m", "0644", "/var/tmp/pam_fic_ssh_stage.so", module_dir)
    Path("/run/sshd").mkdir(exist_ok=True)
    run("ssh-keygen", "-A")
    run("dpkg-query", "-W", "openssh-server", "openssh-client", "libpam0g", "libpam-runtime", "libpam-google-authenticator",
        "libpam-sss", "libnss-systemd")
    packages = Path("/var/tmp/fic-packages")
    run("dpkg", "-i", *(str(next(packages.glob(name + "_*.deb")))
                       for name in ("fic-dick", "fic", "fic-cli")), timeout=180)
    cutover = os.environ.get("FIC_D13_SSH_CUTOVER")
    if cutover:
        run("install", "-m", "0644", "/var/tmp/pam_fic_access-cutover.so", module_dir / "pam_fic_access.so")
    assert not slot.exists() and not Path("/usr/share/pam-configs/fic-mfa-hook").exists()
    run("pam-auth-update", "--disable", "sss")
    # libnss-sss edits both databases during installation. The password
    # proof keeps shadow local even after the fixture enables SSSD passwd.
    nss_file = Path("/etc/nsswitch.conf")
    (out / "nsswitch.image").write_text(nss_file.read_text())
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
    ssh_faillock = os.environ.get("FIC_D13_SSH_FAILLOCK")
    if ssh_faillock:
        assert ssh_faillock in ("preauth-required", "preauth-requisite")
        run("/opt/fic/bin/fic-cli", "policy", "set", "IDENTITY_ACCESS", lockout,
            ssh_faillock.replace("-", "_"))
    for name in (lockout, deny_empty):
        policy("enable", name)
        policy("apply", name)
    if cutover == "sssd":
        run_sssd_fixture(nss_file)
        return
    if cutover == "local":
        from mfa_cases import exercise_verified_cutover
        exercise_verified_cutover(run, user, password, lambda: totp(key), lambda: wrong_totp(key))
        return
    if ssh_faillock:
        exercise_ssh(run, user, password, lambda: totp(key), lambda: wrong_totp(key),
                     registration, False, ssh_faillock)
        return
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
    for state in ("missing", "corrupt"):
        code = totp(key)
        authenticate(f"valid registration before {state} credential test",
                     user, password, code, True)
        try:
            if state == "missing":
                registration.unlink()
            else:
                registration.write_text("!!!!\n")
                structural("installed", False, "TOTP-only")
            p = authenticate(f"{state} OTP registration with valid code",
                             user, password, code, False)
            assert "password_prompts=1" in p.stdout and "otp_prompts=0" not in p.stdout
        finally:
            registration.write_bytes(original)
            registration.chmod(0o600)
    authenticate("restored OTP registration", user, password, totp(key), True)
    try:
        registration.chmod(0o644)
        structural("installed", False, "metadata")
        authenticate("wrong registration permissions", user, password, totp(key), False)
    finally:
        registration.chmod(0o600)

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

    lifecycle = run(auth, "login", user, "--lifecycle", input=f"{password}\n{totp(key)}\n")
    assert "authenticate=0 account=0 establish=0 open=0 close=0 delete=0 end=0" in lifecycle.stdout
    exercise_forward(user, password, key, registration, False)
    exercise_ssh(run, user, password, lambda: totp(key), lambda: wrong_totp(key),
                 registration, False)

    # The existing policies must still be usable around the experimental slot.
    existing_guard = (pam / "fic-empty-password").read_bytes()
    policy("apply", deny_empty)
    assert (pam / "fic-empty-password").read_bytes() == existing_guard
    policy("apply", lockout)
    run_sssd_fixture(nss_file)
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
        messages = subprocess.run(
            ["journalctl", "--no-pager", "-o", "cat", "_COMM=d13-pam-auth",
             "--grep=Accepted google_authenticator|Invalid verification code|No secret configured|"
             "Invalid file contents|valid BASE32 encoded secret|authentication failure|pam_faillock"],
            text=True, capture_output=True)
        (out / "pam-provider.log").write_text(messages.stdout)
    (out / "result.json").write_text('{"ok": true, "suite": "d13_mfa_native"}\n')
