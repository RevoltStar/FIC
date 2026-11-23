"""Native OpenSSH driver imported by the isolated Debian 13 PAM gate."""
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import time

SERVICE = "fic-sshd-mfa"
CHAINS = "publickey,keyboard-interactive:pam password,keyboard-interactive:pam"
OUT = Path("/var/tmp/fic-package-results")
PAM = Path("/etc/pam.d")
PROOF = "/usr/local/bin/d13-mfa-proof"
OBSERVER = "/var/tmp/d13-ssh-observer.so"

ASKPASS = """#!/bin/sh
case "$1" in
  *'Verification code:'*) item=otp ;;
  *) item=password ;;
esac
if test -f "$FIC_FIXTURE_DIR/first-bad-$item"; then
    rm "$FIC_FIXTURE_DIR/first-bad-$item"
    echo "$item-invalid" >> "$FIC_FIXTURE_DIR/prompts"
    cat "$FIC_FIXTURE_DIR/bad-$item"
else
    echo "$item" >> "$FIC_FIXTURE_DIR/prompts"
    cat "$FIC_FIXTURE_DIR/$item"
fi
"""


def exercise_ssh(run, subject, password, valid_code, wrong_code, registration, sssd, faillock=None):
    mode = "sssd" if sssd else "local"
    family = "ssh" if faillock is None else f"ssh-{faillock}"
    def render(part):
        return run(PROOF, part, family, mode).stdout

    attachment = render("attachment")
    slot = PAM / render("slot-name").strip()
    service = PAM / SERVICE
    original = (PAM / "sshd").read_text()
    assert original.count("@include common-auth") == 1
    assert not service.exists() and not slot.exists()
    service.write_text(original.replace("@include common-auth", attachment.rstrip()))
    slot.write_text(render("neutral"))
    try:
        run(PROOF, "candidate", family, mode, SERVICE)
        body = render("required")
        slot.write_text(body)
        run(PROOF, "installed", family, mode, SERVICE)
        service.write_text(service.read_text() + "auth sufficient pam_permit.so\n")
        run(PROOF, "installed", family, mode, SERVICE, expected=False)
        service.write_text(original.replace("@include common-auth", attachment.rstrip()))

        # The lifecycle runner mounts /tmp noexec. ssh must execute askpass.
        with tempfile.TemporaryDirectory(prefix="fic-native-ssh-", dir="/var/tmp") as path:
            run_matrix(run, Path(path), subject, password, valid_code, wrong_code,
                       registration, mode, faillock)
    finally:
        service.unlink()
        slot.unlink()


def run_matrix(run, directory, subject, password, valid_code, wrong_code, registration, mode, faillock):
    account = pwd.getpwnam(subject)
    home = Path(account.pw_dir)
    home.mkdir(exist_ok=True)
    os.chown(home, account.pw_uid, account.pw_gid)
    key_dir = home / ".ssh"
    key_dir.mkdir(mode=0o700)
    os.chown(key_dir, account.pw_uid, account.pw_gid)
    for name in ("valid-key", "wrong-key"):
        run("ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(directory / name))
    authorized = key_dir / "authorized_keys"
    authorized.write_bytes((directory / "valid-key.pub").read_bytes())
    authorized.chmod(0o600)
    os.chown(authorized, account.pw_uid, account.pw_gid)

    askpass = directory / "askpass"
    askpass.write_text(ASKPASS)
    askpass.chmod(0o700)
    config = directory / "sshd_config"
    config.write_text(f"""ListenAddress 127.0.0.1
Port 2222
UsePAM yes
PAMServiceName {SERVICE}
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no
HostbasedAuthentication no
ExposeAuthInfo no
AuthenticationMethods {CHAINS}
""")
    run("/usr/sbin/sshd", "-t", "-f", str(config))
    effective = run("/usr/sbin/sshd", "-T", "-f", str(config)).stdout.splitlines()
    assert f"pamservicename {SERVICE}" in effective and f"authenticationmethods {CHAINS}" in effective

    env = dict(os.environ, DISPLAY="none", SSH_ASKPASS_REQUIRE="force",
               SSH_ASKPASS=str(askpass), FIC_FIXTURE_DIR=str(directory), LC_ALL="C")
    trace = directory / "pam-trace"
    trace.touch(mode=0o600)

    def attempt(label, method, prompts, *, success=False, identity=subject, key=None,
                bad_password=False, bad_otp=False, retry=None, fault=None, no_registration=False,
                auth_rc=None, account_rc=None):
        (directory / "prompts").write_text("")
        (directory / "password").write_text(("wrong-fixture-password" if bad_password else password)+"\n")
        (directory / "bad-password").write_text("wrong-fixture-password\n")
        (directory / "otp").write_text((wrong_code() if bad_otp else valid_code())+"\n")
        (directory / "bad-otp").write_text(wrong_code()+"\n")
        if retry:
            (directory / f"first-bad-{retry}").touch()
        trace.write_text("")
        original_registration = registration.read_bytes()
        if no_registration:
            registration.unlink()
        elif label == "damaged registration":
            registration.write_text("!!!!\n")

        server_env = dict(os.environ, LD_PRELOAD=OBSERVER, FIC_SSH_PAM_TRACE=str(trace),
                          FIC_SSH_PAM_FAULT=fault or "")
        with (directory / "sshd.log").open("w") as server_log:
            server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", config],
                                      stdout=server_log, stderr=server_log, env=server_env)
            try:
                time.sleep(0.25)
                assert server.poll() is None
                cli = ["ssh", "-p", "2222", "-o", f"PreferredAuthentications={method}",
                       "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                       "-o", "LogLevel=ERROR", "-o", f"NumberOfPasswordPrompts={3 if retry else 1}"]
                cli += ["-o", "IdentitiesOnly=yes", "-i", directory / key] if key else [
                    "-o", "PubkeyAuthentication=no"]
                client = subprocess.run(cli + ["-l", identity, "127.0.0.1", "printf FIC_SESSION_OK"],
                                        stdin=subprocess.DEVNULL, text=True, timeout=25,
                                        capture_output=True, env=env)
                if success and client.returncode == 0:
                    # The client can see exit-status before the server
                    # finishes closing the PAM session and deleting credentials.
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        recorded = trace.read_text()
                        if " close " in recorded and " setcred flags=4 " in recorded and " end " in recorded:
                            break
                        time.sleep(0.05)
            finally:
                server.terminate()
                server.wait(timeout=10)
                if no_registration or label == "damaged registration":
                    registration.write_bytes(original_registration)
                    registration.chmod(0o600)

        observed = (directory / "prompts").read_text().splitlines()
        calls = trace.read_text().splitlines()
        outcome = client.returncode == 0 and client.stdout == "FIC_SESSION_OK"
        with (OUT / "ssh-pam.log").open("a") as log:
            print(f"{mode} {label}: rc={client.returncode} command={outcome} prompts={observed}", file=log)
            for line in calls:
                print(line, file=log)
            for line in (directory / "sshd.log").read_text().splitlines():
                if line.startswith(("Accepted ", "Failed ", "PAM:")):
                    # Discard any optional key fingerprint suffix.
                    print(line.split(" ssh2:")[0], file=log)
        assert outcome == success and observed == prompts, (
            mode, label, client.returncode, observed, client.stderr,
            (directory / "sshd.log").read_text().splitlines()[-20:])
        assert all(line.startswith(SERVICE + " ") for line in calls), (mode, label, calls)
        if success:
            for phase in ("start flags=0 rc=0", "account flags=0 rc=0", "setcred flags=2 rc=0",
                          "open flags=0 rc=0", "close flags=32768 rc=0", "setcred flags=4 rc=0",
                          "end flags=0 rc=0"):
                assert any(phase in line for line in calls), (mode, label, phase, calls)
        else:
            assert client.returncode != 0 and "FIC_SESSION_OK" not in client.stdout, label
            assert not any(" open " in line for line in calls), (mode, label, calls)
        if fault == "publish":
            assert any("publish-fault" in line and "evidence=missing" in line for line in calls), calls
        if fault == "setcred":
            assert any("auth flags=1 rc=0" in line for line in calls), calls
            assert any("setcred flags=2 rc=6" in line for line in calls), calls
        if fault in ("publish", "remove"):
            assert any(f" {fault}-fault " in line for line in calls), (label, calls)
        if auth_rc is not None:
            assert any(f" auth flags=1 rc={auth_rc} " in line for line in calls), (label, calls)
        if account_rc is not None:
            assert any(f" account flags=0 rc={account_rc} " in line for line in calls), (label, calls)

    pwd_method = "password,keyboard-interactive"
    key_method = "publickey,keyboard-interactive"
    if faillock is not None:
        def tally():
            raw = run("faillock", "--user", subject).stdout
            return sum(line.rstrip().endswith("V") for line in raw.splitlines())

        try:
            run("faillock", "--user", subject, "--reset")
            assert tally() == 0
            for n in range(2):
                attempt(f"{faillock} wrong password", pwd_method, ["password"], bad_password=True)
                assert tally() == n + 1
            attempt(f"{faillock} wrong OTP after valid password", pwd_method, ["password", "otp"],
                    bad_otp=True)
            assert tally() == 2
            attempt(f"{faillock} wrong OTP after valid key", key_method, ["otp"],
                    key="valid-key", bad_otp=True)
            assert tally() == 2
            attempt(f"{faillock} reaches threshold", pwd_method, ["password"], bad_password=True)
            assert tally() == 3
            attempt(f"{faillock} locked despite valid factors", pwd_method, ["password"])
            for _ in range(2):
                attempt(f"{faillock} locked despite valid key and OTP", key_method, [],
                        key="valid-key", auth_rc=7)
                assert tally() == 3
            run("faillock", "--user", subject, "--reset")
            attempt(f"{faillock} password and OTP after reset", pwd_method, ["password", "otp"], success=True)
            attempt(f"{faillock} wrong password after reset", pwd_method, ["password"], bad_password=True)
            assert tally() == 1
            attempt(f"{faillock} complete authentication clears the tally", pwd_method,
                    ["password", "otp"], success=True)
            assert tally() == 0
            attempt(f"{faillock} wrong password before key login", pwd_method, ["password"], bad_password=True)
            assert tally() == 1
            attempt(f"{faillock} key and OTP clears the tally", key_method, ["otp"], success=True, key="valid-key")
            assert tally() == 0
            config_file = Path("/etc/security/faillock.conf")
            original = config_file.read_bytes()
            try:
                # Force a real tally I/O error (ENOTDIR), as opposed to an absent tally.
                config_file.write_text("dir = /dev/null/fic-ssh-faillock\n")
                attempt(f"{faillock} preauth I/O error in OTP stage", key_method, [],
                        key="valid-key", auth_rc=4)
                attempt(f"{faillock} preauth I/O error in password stage", pwd_method,
                        ["password"], auth_rc=4)
            finally:
                config_file.write_bytes(original)
            assert tally() == 0
            attempt("missing evidence with faillock", key_method, [], key="valid-key", fault="publish")
            attempt("malformed evidence with faillock", key_method, [], key="valid-key", fault="malformed")
            mode_file = Path("/opt/fic/config/GLOBAL.conf")
            original_mode = mode_file.read_text()
            assert "incident_response_mode.status=" in original_mode
            assert "incident_response_mode.value=" in original_mode
            active_mode = "\n".join(
                "incident_response_mode.status=ENABLE" if line.startswith("incident_response_mode.status=")
                else "incident_response_mode.value=ACTIVE" if line.startswith("incident_response_mode.value=")
                else line for line in original_mode.split("\n"))
            run("systemctl", "stop", "fic.service")
            try:
                mode_file.write_text(active_mode)
                attempt("incident ACTIVE after valid password and OTP", pwd_method, ["password", "otp"],
                        auth_rc=0, account_rc=6)
                attempt("incident ACTIVE after valid key and OTP", key_method, ["otp"], key="valid-key",
                        auth_rc=0, account_rc=6)
            finally:
                mode_file.write_text(original_mode)
                run("systemctl", "start", "fic.service")
            print(f"{mode} {faillock} SSH faillock passed", flush=True)
        finally:
            run("faillock", "--user", subject, "--reset")
        return
    attempt("valid password and OTP", pwd_method, ["password", "otp"], success=True)
    attempt("valid key and OTP", key_method, ["otp"], success=True, key="valid-key")
    attempt("wrong password", pwd_method, ["password"], bad_password=True)
    attempt("wrong key", key_method, [], key="wrong-key")
    attempt("wrong OTP after password", pwd_method, ["password", "otp"], bad_otp=True)
    attempt("wrong OTP after key", key_method, ["otp"], key="valid-key", bad_otp=True)
    attempt("password only", "password", ["password"])
    attempt("key only", "publickey", [], key="valid-key")
    attempt("OTP only", "keyboard-interactive", [])
    attempt("no registration", pwd_method, ["password", "otp"], no_registration=True)
    attempt("damaged registration", key_method, ["otp"], key="valid-key")

    if mode == "local":
        attempt("unknown identity", pwd_method, ["password"], identity="fic-no-such-account")
        attempt("malformed evidence", key_method, [], key="valid-key", fault="malformed")
        attempt("password evidence publication failure", pwd_method, ["password"], fault="publish")
        attempt("key evidence publication failure", key_method, [], key="valid-key", fault="publish")
        attempt("initial empty evidence removal failure", pwd_method, ["password"], fault="remove")
        attempt("key evidence removal failure", key_method, [], key="valid-key", fault="remove")
        attempt("invalid PAM identity after key", key_method, [], key="valid-key", fault="bad-name")
        attempt("setcred after validated key and OTP fails", key_method, ["otp"],
                key="valid-key", fault="setcred")
        attempt("hostbased alone", "hostbased", [])
        attempt("password retry", pwd_method, ["password-invalid", "password", "otp"],
                retry="password", success=True)
        attempt("key failed then password", "publickey,password,keyboard-interactive",
                ["password", "otp"], key="wrong-key", success=True)
        attempt("OTP retry after password", pwd_method, ["password", "otp-invalid", "otp"],
                retry="otp", success=True)
        attempt("OTP retry after key", key_method, ["otp-invalid", "otp"], key="valid-key",
                retry="otp", success=True)
    print(f"{mode} real OpenSSH MFA matrix passed", flush=True)
