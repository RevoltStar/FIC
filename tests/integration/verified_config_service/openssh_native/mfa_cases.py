"""Debian 13 test-only cutover driven by FIC C++ planner, CAS and verified adapter."""
import hashlib
import itertools
import json
import os
import pwd
import re
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def exercise_verified_cutover(run, user, password, otp, wrong_otp, sssd=False):
    main = Path("/etc/ssh/sshd_config")
    production = os.environ.get("FIC_D13_SSH_CUTOVER_PRODUCTION") == "1"
    lifecycle = os.environ.get("FIC_D13_MFA_PACKAGE_LIFECYCLE") == "active"
    assert not lifecycle or production
    algorithms = ("rsa", "ecdsa", "ed25519") if production and sssd else ("ed25519",)
    host_keys = [f"/etc/ssh/ssh_host_{algorithm}_key" for algorithm in algorithms]
    explicit_keys = "".join(f"HostKey {key}\n" for key in host_keys)
    snapshot = f"PasswordAuthentication yes\n{explicit_keys}".encode() + main.read_bytes()
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
        if action in ("mfa-plan", "mfa-cas", "mfa-reference"):
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
        for key in host_keys:
            paths.extend((file(key), file(key + ".pub")))
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
    Path("/etc/default/ssh").write_text("SSHD_OPTS=\n")
    run("systemctl", "enable", "--now", "ssh.service")
    run("systemctl", "is-active", "ssh.service")
    run("systemctl", "restart", "ssh.service")
    generation_before_plan = run("systemctl", "show", "-p", "InvocationID", "-p", "MainPID",
                                 "ssh.service").stdout
    projection = refs()
    projection.update(main_before=sha(snapshot), project_pam=True, sssd=sssd)
    invoke("mfa-plan", dict(projection, discover_pam=True), label="before-pam-publication")
    invoke("mfa-plan", dict(projection, mutate_candidate=True), expected=False,
           label="refuse-mutated-pam-candidate")
    assert main.read_bytes() == snapshot and not service.exists() and not slot.exists()
    assert run("systemctl", "show", "-p", "InvocationID", "-p", "MainPID",
               "ssh.service").stdout == generation_before_plan
    rendered_slot = run("/usr/local/bin/d13-mfa-proof", "required", family, primary).stdout
    slot.write_text(rendered_slot)
    try:
        collision = dict(refs(), main_before=sha(snapshot), project_pam=True, sssd=sssd)
        result = invoke("mfa-plan", collision, expected=False, label="refuse-identical-foreign-pam-slot")
        assert "already exists" in result["diagnostic"], result
        assert main.read_bytes() == snapshot and not service.exists() and slot.read_text() == rendered_slot
    finally:
        slot.unlink()
    if not production:
        service.write_text(local.replace("@include common-auth", "auth substack fic-mfa-ssh-auth"))
        slot.write_text(rendered_slot)
        run("/usr/local/bin/d13-mfa-proof", "installed", family, primary, "fic-sshd-mfa")

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
        port = 22

        def ssh_args(method, command, use_key):
            # Isolate authentication cases from per-source penalties accrued
            # by other negative cases on this local listener.
            options = ["ssh", "-p", str(port), "-b", f"127.0.0.{next(sources)}", "-o", "StrictHostKeyChecking=no", "-o",
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
        if production:
            cli = "/opt/fic/bin/fic-cli"
            mfa = "ssh_mfa_required"
            def policy(command, name, expected=True):
                call = run(cli, "policy", command, "NET", name, expected=expected)
                print(f"production {command} {name}: {call.stdout.strip()}", flush=True)

            def verify_pair():
                launch("password", False)
                launch("password,keyboard-interactive", True)
                launch("publickey,keyboard-interactive", True, use_key=True)
                launch("publickey", False, use_key=True)

            assert not service.exists() and not slot.exists()
            policy("isdisable", mfa)
            policy("enable", mfa)
            slot.write_text(rendered_slot)
            try:
                policy("apply", mfa, expected=False)
                assert not service.exists() and main.read_bytes() == snapshot and slot.read_text() == rendered_slot
            finally:
                slot.unlink()
            with subprocess.Popen(ssh_args("password", "echo FIC_READY; read -r line; echo FIC_STILL_OPEN", False),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, env=env) as session:
                try:
                    assert select.select([session.stdout], [], [], 15)[0]
                    assert session.stdout.readline().strip() == "FIC_READY"
                    policy("apply", mfa)
                    stdout, _ = session.communicate("continue\n", timeout=15)
                    assert session.returncode == 0 and stdout == "FIC_STILL_OPEN\n"
                finally:
                    if session.poll() is None:
                        session.kill()
            assert service.is_file() and slot.is_file()
            verify_pair()
            run("faillock", "--user", user, "--reset")
            for _ in range(3):
                launch("password,keyboard-interactive", False, primary_password="invalid fixture password")
            launch("password,keyboard-interactive", False)
            launch("publickey,keyboard-interactive", False, use_key=True)
            run("faillock", "--user", user, "--reset")
            run(cli, "policy", "set", "NET", "ssh_port", "2222")
            policy("enable", "ssh_port")
            policy("apply", "ssh_port")
            port = 2222
            verify_pair()
            policy("apply", "ssh_use_pam")
            verify_pair()
            policy("enable", "ssh_pubkey_auth")
            policy("apply", "ssh_pubkey_auth")
            verify_pair()
            policy("apply", mfa)
            verify_pair()
            policy("apply", "all")
            verify_pair()
            if lifecycle:
                def baseline_ssh():
                    nonlocal port
                    port = 22
                    launch("password", True)

                def restored_mfa():
                    nonlocal port
                    port = 2222
                    verify_pair()

                def hold_session():
                    (lab / "otp").write_text(otp() + "\n")
                    return subprocess.Popen(
                        ssh_args("publickey,keyboard-interactive",
                                 "echo FIC_READY; read -r line; echo FIC_STILL_OPEN", True),
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True, env=env)

                exercise_package_lifecycle(run, user, main, service, slot, verify_pair,
                                           baseline_ssh, restored_mfa, hold_session, sssd)
                return
            if not sssd:
                run(cli, "policy", "set", "GLOBAL", "check_interval", "60")
            run("systemctl", "restart", "fic.service")
            policy("apply", "ssh_port")
            verify_pair()
            if not sssd:
                generation_before_periodic = systemd_identity()
                deadline = time.monotonic() + 100
                while systemd_identity() == generation_before_periodic and time.monotonic() < deadline:
                    time.sleep(1)
                assert systemd_identity() != generation_before_periodic, "no verified periodic SSH activation"
                # IPC and periodic apply share the daemon event loop. Once it
                # responds, the restarts for the observed pass have completed.
                policy("isenable", mfa)
                verify_pair()
                print("Periodic apply retained SSH MFA", flush=True)
            old_slot = slot.read_bytes()
            slot.write_bytes(old_slot + b"# fixture drift\n")
            try:
                policy("apply", "ssh_port", expected=False)
                policy("disable", mfa, expected=False)
            finally:
                slot.write_bytes(old_slot)
            saved_ssh = main.read_bytes()
            modified_ssh, count = re.subn(
                rb"(?im)^(pamservicename[ \t]+)fic-sshd-mfa$", rb"\g<1>sshd", saved_ssh)
            assert count == 1
            main.write_bytes(modified_ssh)
            try:
                policy("apply", "ssh_port", expected=False)
                assert main.read_bytes() == modified_ssh
            finally:
                main.write_bytes(saved_ssh)
            journal = Path("/opt/fic/db/mutation-journal.json")
            saved_journal = journal.read_bytes()
            try:
                journal.write_bytes(b"invalid fixture journal\n")
                policy("apply", "ssh_port", expected=False)
            finally:
                journal.write_bytes(saved_journal)
            held_journal = journal.with_name("mutation-journal.json.fixture")
            journal.rename(held_journal)
            try:
                policy("apply", "ssh_port", expected=False)
            finally:
                held_journal.rename(journal)
            verify_pair()
            policy("disable", "ssh_port")
            port = 22
            verify_pair()
            policy("enable", "ssh_port")
            policy("apply", "ssh_port")
            port = 2222
            policy("disable", mfa)
            assert not service.exists() and not slot.exists()
            assert "#@FIC_POLICY_BEGIN name=ssh_port@\nPort 2222\n#@FIC_POLICY_END name=ssh_port@" in main.read_text()
            launch("password", True)
            policy("disable", mfa)
            policy("enable", mfa)
            policy("apply", mfa)
            verify_pair()
            policy("disable", mfa)
            return
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
                invoke("mfa-reference", dict(expected, discover_pam=True), label="independent-reference")
                drifted = dict(expected, paths=[
                    dict(path, sha256="0" * 64) if path["path"] == "/etc/nsswitch.conf" else path
                    for path in expected["paths"]])
                invoke("mfa-reference", drifted, expected=False, label="refuse-drifted-pam-reference")
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

        run("faillock", "--user", user, "--reset")
        for _ in range(3):
            launch("password,keyboard-interactive", False, primary_password="invalid fixture password")
        launch("password,keyboard-interactive", False)
        launch("publickey,keyboard-interactive", False, use_key=True)
        run("faillock", "--user", user, "--reset")
        launch("password,keyboard-interactive", True)
        launch("publickey,keyboard-interactive", True, use_key=True)
        print("Verified listener enforced faillock for both MFA chains", flush=True)

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

def exercise_package_lifecycle(run, user, main, service, slot, verify_pair, baseline_ssh,
                               restored_mfa, hold_session, sssd):
    cli = "/opt/fic/bin/fic-cli"
    net = Path("/opt/fic/config/NET.conf")
    journal = Path("/opt/fic/db/mutation-journal.json")
    witness = journal.with_suffix(".json.initialized")
    state = Path("/var/lib/fic-lifecycle/status")
    secret = Path("/etc/security/fic-mfa") / f"totp-{user}"
    initial_secret = secret.read_bytes()
    owned_pam_files = {path: (path.stat().st_ino, path.read_bytes()) for path in (service, slot)}
    selector = next(Path("/usr/lib").glob("*/security/pam_fic_ssh_stage.so"))

    def version(package):
        return run("dpkg-query", "-W", "-f=${Version}", package).stdout

    def installed(package):
        result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package],
                                capture_output=True, text=True, timeout=15)
        return result.stdout.strip() == "installed"

    def mfa_records():
        return [entry for entry in json.loads(journal.read_text())["records"]
                if entry["resource"] == "ssh:/etc/ssh/sshd_config:fic-sshd-mfa"]

    def selections():
        return dict(line.split("=", 1) for line in net.read_text().splitlines()
                    if line.startswith("ssh_") and "=" in line)

    def remove(expected=True):
        return run("apt-get", "-y", "remove", "fic", expected=expected, timeout=240)

    def report(result):
        start = result.stdout.index("\n{\n") + 1
        return json.JSONDecoder().raw_decode(result.stdout[start:])[0]

    saved = selections()
    assert saved["ssh_mfa_required.status"] == saved["ssh_port.status"] == "ENABLE"
    assert saved["ssh_port.value"] == "2222"
    before = mfa_records()
    assert len(before) == 1 and before[0]["undo"]["phase"] == "applied", before
    assert before[0]["undo"]["sssd"] == sssd
    previous_version = version("fic")
    archives = [str(next(Path("/var/tmp/fic-upgrade-packages").glob(name + "_*.deb")))
                for name in ("fic-dick", "fic", "fic-cli")]
    new_version = run("dpkg-deb", "-f", archives[1], "Version").stdout.strip()
    run("dpkg", "--compare-versions", previous_version, "lt", new_version)
    upgraded = run("apt-get", "-y", "install", *archives, timeout=240)
    assert "ownership rollback" not in upgraded.stdout + upgraded.stderr
    assert version("fic") == new_version and state.read_text() == "INSTALLED\n"
    assert mfa_records() == before and witness.is_file()
    assert selections() == saved and secret.read_bytes() == initial_secret
    assert owned_pam_files == {path: (path.stat().st_ino, path.read_bytes()) for path in (service, slot)}
    assert selector.is_file()
    verify_pair()
    run(cli, "policy", "apply", "NET", "ssh_mfa_required")
    assert mfa_records() == before and not run("dpkg", "--audit").stdout.strip()
    print(f"native upgrade retained SSH MFA and ownership: {previous_version} -> {new_version}", flush=True)

    # Pre-publication refusals retain ownership and ordinary SSH/PAM inputs.
    # apt removes the dependent client before the main package's prerm.
    # Preserve a fixture client to probe the live daemon after failed removal.
    retry_cli = "/var/tmp/fic-lifecycle-client"
    shutil.copy2(cli, retry_cli)
    ssh_before = main.read_bytes()
    slot_before = slot.read_bytes()
    slot.write_bytes(slot_before + b"# fixture drift\n")
    try:
        failure = report(remove(False))
        groups = {row["resource_group"]: row["status"] for row in failure["results"]
                  if "resource_group" in row}
        assert groups["NET:SshEdit:ssh_mfa_required"] == "FAILED", groups
        assert any("ownership or content changed" in row.get("message", "")
                   for row in failure["results"])
        assert groups["NET:SshEdit:ssh_port"] == groups["PAM"] == "BLOCKED_BY_DEPENDENCY", groups
        if sssd:
            assert all(status == "BLOCKED_BY_DEPENDENCY" for group, status in groups.items()
                       if group.startswith("IDENTITY_ACCESS:SSSD:"))
        assert state.read_text() == "UNINSTALLING\n" and main.read_bytes() == ssh_before
        assert mfa_records() == before and selector.exists() and installed("fic")
        denied = run(retry_cli, "policy", "apply", "NET", "ssh_mfa_required", expected=False)
        assert "в процессе удаления" in denied.stdout + denied.stderr
    finally:
        slot.write_bytes(slot_before)

    journal_before = journal.read_bytes()
    journal.write_text("invalid journal fixture\n")
    try:
        failure = report(remove(False))
        assert failure["error_code"] == "ROLLBACK_STATE_UNPROVEN" and "results" not in failure
        assert state.read_text() == "UNINSTALLING\n" and selector.exists()
        assert main.read_bytes() == ssh_before and slot.read_bytes() == slot_before
    finally:
        journal.write_bytes(journal_before)

    foreign = slot.parent / "mfa-lifecycle-foreign"
    foreign.write_text("auth required pam_fic_ssh_stage.so\n")
    try:
        failure = report(remove(False))
        assert any("foreign PAM source references" in row.get("message", "") for row in failure["results"]), failure
        assert foreign.exists() and selector.exists() and mfa_records() == before
    finally:
        foreign.unlink()

    with hold_session() as session:
        try:
            assert select.select([session.stdout], [], [], 15)[0]
            assert session.stdout.readline().strip() == "FIC_READY"
            failure = report(remove(False))
            assert any("SSH sessions or authentication children" in row.get("message", "")
                       for row in failure["results"]), failure
            stdout, _ = session.communicate("continue\n", timeout=15)
            assert session.returncode == 0 and stdout == "FIC_STILL_OPEN\n"
        finally:
            if session.poll() is None:
                session.kill()

    run("systemctl", "stop", "ssh.service")
    try:
        assert not report(remove(False))["ok"]
        assert selector.exists() and mfa_records() == before
    finally:
        run("systemctl", "start", "ssh.service")

    removed = report(remove())
    assert removed["ok"], removed
    groups = [row["resource_group"] for row in removed["results"]
              if row.get("status") == "RELEASED" and "resource_group" in row]
    mfa = groups.index("NET:SshEdit:ssh_mfa_required")
    port = groups.index("NET:SshEdit:ssh_port")
    assert mfa < groups.index("PAM") and mfa < port
    assert all(mfa < index for index, group in enumerate(groups)
               if group.startswith(("NET:SshEdit:", "IDENTITY_ACCESS:SSSD:" if sssd else "NET:SshEdit:"))
               and group != "NET:SshEdit:ssh_mfa_required")
    assert all(index < port for index, group in enumerate(groups)
               if group.startswith("NET:SshEdit:") and group != "NET:SshEdit:ssh_port")

    def prove_removed():
        assert not installed("fic") and state.read_text() == "REMOVED\n"
        assert not selector.exists() and not service.exists() and not slot.exists()
        assert "d13_mfa_" not in main.read_text() and "#@FIC" not in main.read_text()
        assert selections() == saved and secret.read_bytes() == initial_secret and witness.is_file()
        assert all(record["status"] == "rolled_back" and record["undo"]["phase"] == "released"
                   for record in mfa_records())
        assert not run("dpkg", "--audit").stdout.strip()
        baseline_ssh()

    prove_removed()
    print("native standard remove released active MFA, preserved saved selections and TOTP", flush=True)
    run("apt-get", "-y", "install", *archives, timeout=240)
    assert selections() == saved and service.is_file() and slot.is_file() and selector.is_file()
    restored_mfa()
    after = mfa_records()
    assert len(after) == 2 and after[0]["id"] == before[0]["id"] and after[1]["id"] != before[0]["id"]
    assert after[1]["undo"]["phase"] == "applied", after
    assert report(remove())["ok"]
    prove_removed()
    run("apt-get", "-y", "purge", "fic", "fic-dick", timeout=180)
    assert not net.exists() and not journal.exists() and not witness.exists()
    assert not selector.exists() and secret.read_bytes() == initial_secret
    assert not run("dpkg", "--audit").stdout.strip()
    print("native reinstall restored MFA through startup apply, remove and late purge preserved TOTP", flush=True)
