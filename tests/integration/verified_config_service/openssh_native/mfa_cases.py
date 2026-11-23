"""Debian 13 test-only cutover driven by FIC C++ planner, CAS and verified adapter."""
import hashlib
import itertools
import json
import os
import pwd
import select
import subprocess
import tempfile
from pathlib import Path


def exercise_verified_cutover(run, user, password, otp, wrong_otp, sssd=False):
    main = Path("/etc/ssh/sshd_config")
    host_key = "/etc/ssh/ssh_host_ed25519_key"
    snapshot = f"PasswordAuthentication yes\nHostKey {host_key}\n".encode() + main.read_bytes()
    main.write_bytes(snapshot)
    unix = pwd.getpwnam(user)
    Path(unix.pw_dir).mkdir(exist_ok=True)
    os.chown(unix.pw_dir, unix.pw_uid, unix.pw_gid)
    pam = Path("/etc/pam.d")
    service = pam / "fic-sshd-mfa"
    slot = pam / "fic-mfa-ssh-auth"
    work = Path("/run/fic-openssh-work")
    root = Path("/var/tmp/fic-package-results")
    driver = "/usr/local/bin/fic-openssh-driver"
    family = "ssh-preauth-required"
    primary = "sssd" if sssd else "local"
    def sha(value):
        return hashlib.sha256(value).hexdigest()

    def invoke(action, data, expected=True, label=None):
        request = work / "request.json"
        request.write_text(json.dumps(data))
        value = json.loads(subprocess.run([driver, action, str(request)], check=True,
                            text=True, capture_output=True, timeout=80).stdout)
        (root / ("cutover-" + (label or action) + ".json")).write_text(json.dumps(value, indent=2))
        assert "harness_error" not in value, value
        if action in ("mfa-plan", "mfa-cas"):
            assert bool(value.get("success")) == expected, value
        return value

    def file(path):
        p = Path(path)
        return {"path": str(p), "sha256": sha(p.read_bytes())}

    def directory(path):
        p = Path(path)
        manifest = {}
        directories = []
        for item in p.rglob("*"):
            assert not item.is_symlink(), str(item)
            relative = str(item.relative_to(p))
            if item.is_file():
                manifest[relative] = sha(item.read_bytes())
            elif item.is_dir():
                directories.append(relative)
        return {"path": str(p), "directory": True, "manifest": manifest,
                "directories": sorted(directories)}

    def refs():
        paths = [file(main), directory("/etc/ssh/sshd_config.d"), file("/etc/default/ssh")]
        paths.extend((file(host_key), file(host_key + ".pub")))
        module = next(Path("/usr/lib").glob("*/security/pam_fic_ssh_stage.so")).parent
        paths += [directory(pam), directory(module), directory("/etc/security/fic-mfa"),
                  file("/etc/security/faillock.conf"), file("/etc/passwd"), file("/etc/nsswitch.conf")]
        if sssd:
            paths.extend((file("/etc/sssd/sssd.conf"), directory("/etc/sssd/conf.d")))
        return {"paths": paths, "timeout_ms": 60000, "policies": {"ssh_use_pam": "yes"}}

    def install(enable, owned):
        params = refs()
        params.update(main_before=sha(main.read_bytes()), enable=enable, previously_owned=owned, sssd=sssd)
        params["main_after"] = invoke("mfa-plan", params)["sha256"]
        assert invoke("mfa-cas", params)["success"]
        assert sha(main.read_bytes()) == params["main_after"]
        for reference in params["paths"]:
            if reference["path"] == str(main):
                reference["sha256"] = params["main_after"]
        if enable:
            params["mfa"] = {"faillock": "preauth_required", "sssd": sssd}
        return params

    local = (pam / "sshd").read_text()
    assert local.count("@include common-auth") == 1
    service.write_text(local.replace("@include common-auth", "auth substack fic-mfa-ssh-auth"))
    slot.write_text(run("/usr/local/bin/d13-mfa-proof", "required", family, primary).stdout)
    run("/usr/local/bin/d13-mfa-proof", "installed", family, primary, "fic-sshd-mfa")
    Path("/etc/default/ssh").write_text("SSHD_OPTS=\n")
    run("systemctl", "enable", "--now", "ssh.service")
    run("systemctl", "is-active", "ssh.service")
    run("systemctl", "restart", "ssh.service")

    def systemd_identity():
        return run("systemctl", "show", "-p", "InvocationID", "-p", "MainPID",
                   "ssh.service").stdout

    generation = systemd_identity()
    main.write_bytes(b"LogLevel VERBOSE\n" + snapshot)
    try:
        run("systemctl", "reload", "ssh.service")
        assert generation == systemd_identity(), "update the receipt model for this OpenSSH build"
        print("Runtime identity alone does not distinguish SSH reload", flush=True)
    finally:
        main.write_bytes(snapshot)
        run("systemctl", "reload", "ssh.service")

    with tempfile.TemporaryDirectory(dir="/var/tmp") as td:
        lab = Path(td)
        ask = lab / "askpass"
        ask.write_text("#!/bin/sh\ncase \"$1\" in *'Verification code:'*) cat \"$LAB/otp\";; *) cat \"$LAB/pw\";; esac\n")
        ask.chmod(0o700)
        (lab / "pw").write_text(password + "\n")
        env = dict(os.environ, LAB=td, DISPLAY="none", SSH_ASKPASS_REQUIRE="force",
                   SSH_ASKPASS=str(ask), LC_ALL="C")

        key = lab / "identity"
        run("ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(key))
        key_dir = Path(unix.pw_dir) / ".ssh"
        key_dir.mkdir(mode=0o700)
        os.chown(key_dir, unix.pw_uid, unix.pw_gid)
        authorized = key_dir / "authorized_keys"
        authorized.write_bytes(key.with_suffix(".pub").read_bytes())
        authorized.chmod(0o600)
        os.chown(authorized, unix.pw_uid, unix.pw_gid)
        sources = itertools.count(2)

        def ssh_args(method, command, use_key):
            # Isolate authentication cases from per-source penalties accrued
            # by other negative cases on this local listener.
            options = ["ssh", "-b", f"127.0.0.{next(sources)}", "-o", "StrictHostKeyChecking=no", "-o",
                "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o",
                f"PreferredAuthentications={method}", "-o", "NumberOfPasswordPrompts=1"]
            if use_key:
                options += ["-o", "IdentitiesOnly=yes", "-i", str(key)]
            return options + ["-l", user, "127.0.0.1", command]

        def launch(method, success, verification=None, use_key=False, primary_password=None):
            (lab / "otp").write_text((verification or otp()) + "\n")
            (lab / "pw").write_text((password if primary_password is None else primary_password) + "\n")
            result = subprocess.run(ssh_args(method, "printf FIC_NATIVE_OK", use_key),
                stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=20)
            assert (result.returncode == 0 and result.stdout == "FIC_NATIVE_OK") == success, (result.returncode, result.stdout, result.stderr)
            assert "kex_exchange_identification" not in result.stderr and "Connection refused" not in result.stderr, result.stderr
            print(f"test SSH {method}: accepted={success}", flush=True)

        # Test image has stock PasswordAuthentication and the original PAM service.
        launch("password", True)
        conflict = Path("/etc/ssh/sshd_config.d/19-fixture-conflict.conf")
        conflict.write_text("PasswordAuthentication no\n")
        try:
            plan = refs()
            plan.update(main_before=sha(snapshot), enable=True, previously_owned=False, sssd=sssd)
            refused = invoke("mfa-plan", plan, expected=False, label="foreign-include")
            assert "conflicting SSH MFA directive" in refused.get("diagnostic", ""), refused
            assert main.read_bytes() == snapshot
        finally:
            conflict.unlink()
        with subprocess.Popen(ssh_args("password", "echo FIC_READY; read -r line; echo FIC_STILL_OPEN", False),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, env=env) as session:
            try:
                assert select.select([session.stdout], [], [], 15)[0]
                assert session.stdout.readline().strip() == "FIC_READY"
                expected = install(True, False)
                launch("password", True)
                result = invoke("adapter", expected, label="activation")
                print("C++ verified adapter result", result.get("adapter_status"), result.get("adapter_diagnostic"), flush=True)
                assert result.get("adapter_success"), result
                runtime = result["adapter_runtime"]
                assert len(runtime["mfa_reference"]) == 64 and runtime["InvocationID"]
                assert runtime["MainPID"] == run("systemctl", "show", "-p", "MainPID",
                                                 "--value", "ssh.service").stdout.strip()
                stdout, _ = session.communicate("continue\n", timeout=15)
                assert session.returncode == 0 and stdout == "FIC_STILL_OPEN\n"
                print("Existing SSH session survived verified cutover", flush=True)
            finally:
                if session.poll() is None:
                    session.kill()
        launch("password", False)
        launch("password,keyboard-interactive", True)
        launch("publickey,keyboard-interactive", True, use_key=True)
        launch("publickey", False, use_key=True)
        launch("keyboard-interactive", False)
        ordinary = {key: value for key, value in expected.items() if key != "mfa"}
        refused = invoke("adapter", ordinary, label="ordinary-without-mfa-authority")
        assert not refused.get("adapter_success") and not refused.get("activation_invoked"), refused
        launch("password,keyboard-interactive", False, primary_password="invalid fixture password")
        registration = Path("/etc/security/fic-mfa") / f"totp-{user}"
        hold = registration.with_suffix(".inactive")
        registration.rename(hold)
        try:
            launch("publickey,keyboard-interactive", False, use_key=True)
        finally:
            hold.rename(registration)

        # The same service must enforce the real incident PAM module even when
        # the authorization daemon is absent. Keep the test socket isolated.
        mode_file = Path("/opt/fic/config/GLOBAL.conf")
        mode = mode_file.read_text()
        assert "incident_response_mode.status=" in mode
        active = "\n".join(
            "incident_response_mode.status=ENABLE" if line.startswith("incident_response_mode.status=")
            else "incident_response_mode.value=ACTIVE" if line.startswith("incident_response_mode.value=")
            else line for line in mode.split("\n"))
        run("systemctl", "stop", "fic.service")
        try:
            mode_file.write_text(active)
            launch("password,keyboard-interactive", False)
            launch("publickey,keyboard-interactive", False, use_key=True)
        finally:
            mode_file.write_text(mode)
        # Recheck exactly the same credentials and runtime with the daemon
        # still stopped. Only the mode file changed between these checks.
        launch("password,keyboard-interactive", True)
        launch("publickey,keyboard-interactive", True, use_key=True)
        print("Incident account decision followed the mode for both MFA pairs", flush=True)

        # No recovery uses the saved MFA result after a source has drifted.
        approved = refs()
        approved["mfa"] = expected["mfa"]
        old_slot = slot.read_bytes()
        slot.write_bytes(old_slot + b"# unauthorized fixture change\n")
        try:
            drift = invoke("adapter", approved, label="pam-drift")
            assert not drift.get("adapter_success") and not drift.get("activation_invoked"), drift
        finally:
            slot.write_bytes(old_slot)
        selector = next(Path("/usr/lib").glob("*/security/pam_fic_ssh_stage.so"))
        hidden = selector.with_suffix(".hidden")
        selector.rename(hidden)
        try:
            missing = invoke("adapter", approved, label="selector-missing")
            assert not missing.get("adapter_success") and not missing.get("activation_invoked"), missing
        finally:
            hidden.rename(selector)
        active_bytes = main.read_bytes()
        active_generation = systemd_identity()
        main.write_bytes(active_bytes + b"InvalidFicFixtureDirective yes\n")
        try:
            run("systemctl", "reload", "ssh.service", expected=False)
            assert active_generation == systemd_identity()
            faulty = invoke("adapter", approved, label="failed-reload")
            assert not faulty.get("adapter_success") and not faulty.get("activation_invoked"), faulty
            launch("password", False)
            launch("publickey,keyboard-interactive", True, use_key=True)
            print("Failed reload retained the MFA listener and was refused by the adapter", flush=True)
        finally:
            main.write_bytes(active_bytes)
        launch("password,keyboard-interactive", False, wrong_otp())
        legacy = install(False, True)
        launch("password", False)
        assert invoke("adapter", legacy, label="rollback").get("adapter_success")
        launch("password", True)
        assert main.read_bytes() == snapshot and service.exists()
        run("systemctl", "stop", "ssh.service")
        plan = refs()
        plan.update(main_before=sha(snapshot), enable=True, previously_owned=False, sssd=sssd)
        invoke("mfa-plan", plan, expected=False, label="stopped-runtime")
        assert main.read_bytes() == snapshot
