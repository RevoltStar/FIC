#!/usr/bin/env python3

import re
import subprocess
import sys
import tempfile
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def field(profile: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", profile, re.MULTILINE)
    require(match is not None, f"PAM profile has no {name} field")
    return match.group(1).strip()


def optional_field(profile: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", profile, re.MULTILINE)
    return "" if match is None else match.group(1).strip()


def function_body(script: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$",
        script,
        re.MULTILINE | re.DOTALL,
    )
    require(match is not None, f"packaging builder has no function {name}")
    return match.group("body")


def main() -> int:
    root = Path(sys.argv[1])
    profile_dir = root / "packaging/deb/pam-configs"
    expected = {
        "fic-faillock-notify": {
            "Name": "FIC PAM faillock pre-authentication and account check",
            "Priority": "1025",
            "rules": (
                "pam_faillock.so preauth",
                "required\t\t\tpam_faillock.so",
            ),
        },
        "fic-faillock-authfail": {
            "Name": "FIC PAM faillock failed authentication counter",
            "Priority": "1",
            "rules": ("[default=die]\t\t\tpam_faillock.so authfail",),
        },
        "fic-faillock-preauth-required": {
            "Name": "FIC PAM faillock pre-authentication and account check (required)",
            "Priority": "1025",
            "rules": (
                "pam_faillock.so preauth",
                "required\t\t\tpam_faillock.so",
            ),
        },
        "fic-faillock-authsucc": {
            "Name": "FIC PAM faillock success accounting and lock denial",
            "Priority": "1025",
            "rules": ("required\t\t\tpam_faillock.so authsucc",),
        },
        "fic-faillock-hook-preauth": {
            "Name": "FIC permanent pam_faillock preauth hook",
            "Priority": "100000",
            "rules": ("include                     fic-faillock-preauth",),
        },
        "fic-faillock-hook-authfail": {
            "Name": "FIC permanent pam_faillock authfail hook",
            "Priority": "-100000",
            "rules": ("include                     fic-faillock-authfail",),
        },
        "fic-faillock-hook-authsucc": {
            "Name": "FIC permanent pam_faillock authsucc hook",
            "Priority": "-100000",
            "rules": ("include                     fic-faillock-authsucc",),
        },
        "fic-faillock-hook-account": {
            "Name": "FIC permanent pam_faillock account hook",
            "Priority": "100000",
            "rules": ("include                     fic-faillock-account",),
        },
        "fic-pwquality": {
            "Name": "FIC PAM password quality checking",
            "Priority": "1024",
            "rules": ("requisite\t\t\tpam_pwquality.so retry=3",),
        },
        "fic-pwhistory": {
            "Name": "FIC PAM password history checking",
            "Priority": "1023",
            "rules": (
                "pam_pwhistory.so use_authtok",
                "requisite\t\t\tpam_pwhistory.so",
            ),
        },
    }
    prohibited_arguments = (
        "deny=",
        "fail_interval=",
        "unlock_time=",
        "remember=",
        "enforce_for_root",
        "try_first_pass",
    )

    for name, contract in expected.items():
        path = profile_dir / name
        require(path.is_file() and not path.is_symlink(), f"missing physical PAM profile: {name}")
        profile = path.read_text(encoding="utf-8")
        require(field(profile, "Name") == contract["Name"], f"wrong Name in {name}")
        require(field(profile, "Default") == "no", f"{name} must default to disabled")
        require(field(profile, "Priority") == contract["Priority"], f"wrong Priority in {name}")
        for rule in contract["rules"]:
            require(rule in profile, f"{name} is missing rule: {rule}")
        for argument in prohibited_arguments:
            require(argument not in profile, f"{name} embeds policy argument: {argument}")

    notify = (profile_dir / "fic-faillock-notify").read_text(encoding="utf-8")
    require(field(notify, "Auth-Type") == "Primary", "notify profile Auth-Type is not Primary")
    require(field(notify, "Account-Type") == "Primary", "notify profile Account-Type is not Primary")
    require("requisite\t\t\tpam_faillock.so preauth" in notify, "notify profile has wrong preauth control")

    authfail = (profile_dir / "fic-faillock-authfail").read_text(encoding="utf-8")
    require(field(authfail, "Auth-Type") == "Primary", "authfail profile Auth-Type is not Primary")
    preauth_required = (profile_dir / "fic-faillock-preauth-required").read_text(encoding="utf-8")
    require(field(preauth_required, "Auth-Type") == "Primary",
            "preauth-required profile Auth-Type is not Primary")
    require(field(preauth_required, "Account-Type") == "Primary",
            "preauth-required profile Account-Type is not Primary")
    require("required\t\t\tpam_faillock.so preauth" in preauth_required,
            "preauth-required profile has wrong preauth control")
    authsucc = (profile_dir / "fic-faillock-authsucc").read_text(encoding="utf-8")
    # authsucc must run in the Additional auth block: a Primary authsucc is
    # jumped over by successful primary credential providers (success=N
    # jumps past the whole primary block into pam_permit), which lets a
    # locked user with a correct password authenticate.
    require(field(authsucc, "Auth-Type") == "Additional",
            "authsucc profile Auth-Type is not Additional; Primary authsucc "
            "is bypassed by primary provider success jumps")
    require("required\t\t\tpam_faillock.so authsucc" in authsucc,
            "authsucc profile has wrong control; upstream sufficient must not "
            "be copied blindly and the denial must not be skippable")
    require("sufficient" not in authsucc, "authsucc profile must not use sufficient control")
    require("Account-Type" not in authsucc,
            "authsucc profile must not add an account pam_faillock phase")
    # The three strategy-selector profiles conflict with each other so
    # pam-auth-update cannot generate a mixed strategy. The shared authfail
    # profile must not conflict with them because every strategy recipe
    # enables authfail together with one selector.
    selector_profiles = {
        "fic-faillock-notify",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
    }
    for conflicting in selector_profiles:
        profile = (profile_dir / conflicting).read_text(encoding="utf-8")
        conflicts = optional_field(profile, "Conflicts")
        for other in selector_profiles:
            if other == conflicting:
                continue
            require(other in conflicts,
                    f"{conflicting} does not declare a Conflicts entry for {other}")
        require("fic-faillock-authfail" not in conflicts,
                f"{conflicting} conflicts with the shared authfail profile")
    authfail_conflicts = optional_field(authfail, "Conflicts")
    for selector in selector_profiles:
        require(selector not in authfail_conflicts,
                f"authfail conflicts with required selector {selector}")

    quality = (profile_dir / "fic-pwquality").read_text(encoding="utf-8")
    require(field(quality, "Password-Type") == "Primary",
            "pwquality profile Password-Type is not Primary")
    require("pwquality" not in optional_field(quality, "Conflicts").split(),
            "fic-pwquality must not conflict with the distro pwquality profile")

    history = (profile_dir / "fic-pwhistory").read_text(encoding="utf-8")
    require(field(history, "Password-Type") == "Primary", "history profile Password-Type is not Primary")
    require("Password-Initial:" in history, "history profile has no Password-Initial stanza")

    deb_builder = (root / "packaging/deb/build-fic-debian12-deb.sh").read_text(encoding="utf-8")
    sourced = subprocess.run(
        ["bash", "-c",
         'set -- 0.1.0; source "$BUILDER"; '
         'declare -F write_common_preinst >/dev/null; '
         'declare -F write_fic_pam_preinst >/dev/null'],
        cwd=root,
        env={"PATH": "/usr/bin:/bin", "BUILDER":
             str(root / "packaging/deb/build-fic-debian12-deb.sh")},
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        sourced.returncode == 0,
        "Debian PAM preinst helpers are not top-level shell functions: " +
        sourced.stderr.strip(),
    )
    rpm_builder = (root / "packaging/rpm/build-fic-alt-p11-rpm.sh").read_text(encoding="utf-8")
    rpm_facility_path = root / "packaging/rpm/fic-pam-faillock"
    rpm_facility = rpm_facility_path.read_text(encoding="utf-8")
    rpm_history_facility_path = root / "packaging/rpm/fic-pam-pwhistory"
    rpm_history_facility = rpm_history_facility_path.read_text(encoding="utf-8")
    fic_cmake = (root / "fic/CMakeLists.txt").read_text(encoding="utf-8")

    fic_package = function_body(deb_builder, "build_fic_package")
    fic_dick_package = function_body(deb_builder, "build_fic_dick_package")
    fic_pam_preinst_start = deb_builder.find("\nwrite_fic_pam_preinst() {")
    fic_pam_preinst_end = deb_builder.find(
        "\nwrite_common_postinst() {", fic_pam_preinst_start + 1
    )
    require(fic_pam_preinst_start >= 0 and
            fic_pam_preinst_end > fic_pam_preinst_start,
            "Debian builder has no bounded write_fic_pam_preinst function")
    fic_pam_preinst = deb_builder[fic_pam_preinst_start:fic_pam_preinst_end]
    require('write_fic_pam_preinst "$package_root"' in fic_package,
            "Debian fic package does not use the legacy PAM upgrade guard")
    for legacy_id in (
        "fic-faillock-notify",
        "fic-faillock-authfail",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
        "fic-pwquality",
        "fic-pwhistory",
    ):
        require(legacy_id in fic_pam_preinst,
                f"upgrade guard misses legacy PAM identifier {legacy_id}")
    require('"${1:-}" = "upgrade"' in fic_pam_preinst,
            "legacy PAM guard is not limited to upgrades")
    fic_postinst = function_body(deb_builder, "write_system_integration_symlink_postinst")
    fic_prerm = function_body(deb_builder, "write_system_integration_symlink_prerm")
    generic_prerm = function_body(deb_builder, "write_symlink_prerm")

    require("/opt/fic/db/mutation-journal.json" in fic_pam_preinst and
            '"status": "(prepared|applied|rollback_failed)"' in fic_pam_preinst,
            "legacy PAM upgrade guard does not inspect active journal provenance")
    require("active_units=" in fic_pam_preinst and
            'systemctl start "$unit" || true' in fic_pam_preinst,
            "legacy PAM upgrade guard does not restore services after race refusal")
    require('local profile_dir="$package_root/usr/share/pam-configs"' in deb_builder,
            "Debian builder does not stage profiles in /usr/share/pam-configs")
    require('install_fic_pam_profiles "$package_root"' in fic_package,
            "Debian fic package does not install PAM profiles")
    require(deb_builder.count('install_fic_pam_profiles "$package_root"') == 1,
            "PAM profiles must be staged only in the Debian fic package")
    require('install_fic_pam_slots "$package_root"' in fic_package,
            "Debian fic package does not install PAM managed slots")
    require(deb_builder.count('install_fic_pam_slots "$package_root"') == 1,
            "PAM slots must be staged only in the Debian fic package")
    require('"libpam-runtime" "libpam-modules" "libpam-pwquality"' in fic_package,
            "Debian fic package lacks direct PAM dependencies")
    require('package_depends="$(join_depends "$binary_depends" "udev")"' in fic_dick_package,
            "Debian fic-dick package does not compose the udev runtime dependency")
    require('"$package_name" \\\n        "$package_depends" \\' in fic_dick_package,
            "Debian fic-dick control file does not use its composed runtime dependencies")
    require('"$package_root/DEBIAN/conffiles"' in deb_builder,
            "Debian builder does not protect mutable PAM slots as conffiles")
    for slot in (
        "fic-faillock-preauth",
        "fic-faillock-authfail",
        "fic-faillock-authsucc",
        "fic-faillock-account",
    ):
        require(f"/etc/pam.d/{slot}" in deb_builder,
                f"Debian conffiles contract misses PAM slot {slot}")
    require("pam-auth-update --package" in fic_postinst,
            "Debian postinst does not register package profiles")

    remove_start = fic_prerm.find("pam-auth-update --package --remove")
    remove_end = fic_prerm.find("\nfi", remove_start)
    require(remove_start >= 0 and remove_end > remove_start,
            "Debian prerm has no bounded PAM profile removal block")
    remove_block = fic_prerm[remove_start:remove_end]
    for name in expected:
        require(name in remove_block, f"Debian prerm does not remove {name}")

    # Lifecycle invariant: package removal first stops all FIC PAM writers
    # (the daemon can mutate PAM or re-activate infrastructure while alive)
    # and only then detaches the permanent hook profiles.
    stop_pos = fic_prerm.find("systemctl disable --now fic.service")
    remove_pos = fic_prerm.find("pam-auth-update --package --remove")
    require(stop_pos >= 0 and remove_pos > stop_pos,
            "Debian prerm must stop FIC services before pam-auth-update --remove")
    stop_block = fic_prerm[stop_pos:remove_pos]
    for unit in ("fic-notify.service", "fic-device.service"):
        require(unit in stop_block,
                f"Debian prerm must stop {unit} before detaching PAM hooks")
    require("daemon-reload" in stop_block,
            "Debian prerm must reload systemd units before detaching PAM hooks")
    require("is-active --quiet" in stop_block,
            "Debian prerm does not verify that FIC services stopped before "
            "detaching PAM hooks")
    # Final stop proof: after the bounded wait the prerm must POSITIVELY
    # prove every FIC PAM writer is inactive; a timeout is a package-removal
    # failure (exit 1), never permission to detach the hooks. The proof is a
    # plain is-active check (no `|| true`) followed by exit 1 with a unit
    # name in the diagnostic.
    require('if systemctl is-active --quiet "\\$unit"; then' in stop_block and
            "is still active after the bounded stop wait" in stop_block and
            "exit 1" in stop_block,
            "Debian prerm must abort hook detachment when a FIC service is "
            "still active after the bounded stop wait")

    # Lifecycle invariant: installation/reinstallation never attaches the
    # permanent fic-faillock-hook-* profiles until the existing
    # /etc/pam.d/fic-faillock-* state passed read-only pre-attach validation
    # (canonical neutral or journal-bound FIC-owned).
    validator_call = "fic --maintenance validate-pam-slots-before-attach"
    require(validator_call in fic_postinst,
            "Debian postinst never validates existing FIC PAM slots "
            "before attach")
    validate_pos = fic_postinst.find(validator_call)
    package_pos = fic_postinst.find("pam-auth-update --package")
    enable_pos = fic_postinst.find("pam-auth-update --enable")
    require(package_pos > validate_pos and enable_pos > validate_pos,
            "Debian postinst must attach FIC PAM hooks only after "
            "pre-attach slot validation")
    require("exit 1" in fic_postinst[validate_pos:package_pos],
            "Debian postinst must abort package configuration when slot "
            "validation fails")
    configure_pos = fic_postinst.find('\\${1:-}" = "configure"')
    require(configure_pos >= 0 and validate_pos > configure_pos,
            "pre-attach slot validation must run inside the postinst "
            "configure branch")

    # The daemon (a PAM writer) must not be started before the pre-attach
    # validation passed and the hooks were attached.
    start_pos = fic_postinst.find("systemctl enable --now fic.service")
    require(start_pos < 0 or start_pos > enable_pos,
            "postinst must not start the FIC daemon before pre-attach slot "
            "validation and hook attach")

    # Behavioral proof of the removal invariant: run the generated prerm
    # with fake systemctl/pam-auth-update and verify the actual call order.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        package_root = tmp_path / "pkg"
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True)
        (package_root / "DEBIAN").mkdir(parents=True)
        log = tmp_path / "calls.log"

        fake_systemctl = fake_bin / "systemctl"
        fake_systemctl.write_text(
            "#!/bin/sh\n"
            'printf "systemctl %s\\n" "$*" >> "$FAKE_LOG"\n'
            "for argument in \"$@\"; do\n"
            "  [ \"$argument\" = \"is-active\" ] && exit 1\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8")
        fake_systemctl.chmod(0o755)
        fake_pam = fake_bin / "pam-auth-update"
        fake_pam.write_text(
            "#!/bin/sh\n"
            'printf "pam-auth-update %s\\n" "$*" >> "$FAKE_LOG"\n'
            "exit 0\n",
            encoding="utf-8")
        fake_pam.chmod(0o755)

        generated = subprocess.run(
            ["bash", "-c",
             'pkg_root="$1"; '
             'set -- 0.1.0; '
             'source "$BUILDER" >/dev/null 2>&1; '
             'write_system_integration_symlink_prerm "$pkg_root" fic /opt/fic/bin/fic',
             "bash", str(package_root)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin",
                 "BUILDER": str(root / "packaging/deb/build-fic-debian12-deb.sh")},
            text=True,
            capture_output=True,
            check=False)
        prerm_path = package_root / "DEBIAN/prerm"
        require(generated.returncode == 0 and prerm_path.is_file(),
                "could not generate Debian prerm for the behavioral check: " +
                generated.stderr.strip())
        ran = subprocess.run(
            [str(prerm_path), "remove"],
            env={"PATH": f"{fake_bin}:/usr/bin:/bin", "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(ran.returncode == 0,
                "generated prerm failed under fake systemctl: " +
                ran.stderr.strip())
        calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        pam_calls = [index for index, line in enumerate(calls)
                     if line.startswith("pam-auth-update")]
        stop_calls = [index for index, line in enumerate(calls)
                      if "disable --now" in line]
        require(pam_calls and stop_calls and max(stop_calls) < min(pam_calls),
                "prerm ordering regression: pam-auth-update ran before the "
                "FIC services were stopped")
        require(any("--remove" in calls[index] for index in pam_calls),
                "prerm did not deselect the FIC PAM profiles on remove")

        # Timeout path: a FIC service that stays active after the bounded
        # wait must abort the removal BEFORE any pam-auth-update call and
        # name the offending unit in the diagnostic.
        fake_sleep = fake_bin / "sleep"
        fake_sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_sleep.chmod(0o755)
        fake_systemctl.write_text(
            "#!/bin/sh\n"
            'printf "systemctl %s\\n" "$*" >> "$FAKE_LOG"\n'
            "exit 0\n",
            encoding="utf-8")
        fake_systemctl.chmod(0o755)
        log.unlink(missing_ok=True)
        stuck = subprocess.run(
            [str(prerm_path), "remove"],
            env={"PATH": f"{fake_bin}:/usr/bin:/bin", "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(stuck.returncode != 0,
                "prerm remove must fail when a FIC service remains active "
                "after the bounded stop wait")
        stuck_calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(not any(line.startswith("pam-auth-update")
                        for line in stuck_calls),
                "pam-auth-update ran although a FIC service remained active")
        require("fic.service" in stuck.stderr,
                "stop-timeout diagnostic must name the unit that failed "
                "to stop: " + stuck.stderr.strip())



    # Behavioral proof of the attach invariant: run the configure tail of the
    # generated postinst with fake binaries and verify the actual order:
    # pre-attach validation → pam-auth-update --package → hook enable →
    # daemon start; on validator failure no pam-auth-update and no daemon
    # start may happen at all. /opt/fic paths are redirected to PATH fakes
    # so the host system is never touched.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        package_root = tmp_path / "pkg"
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True)
        (package_root / "DEBIAN").mkdir(parents=True)
        log = tmp_path / "postinst-calls.log"

        def fake_tool(name: str, exit_code: int) -> None:
            tool = fake_bin / name
            tool.write_text(
                "#!/bin/sh\n"
                f'printf "{name} %s\\n" "$*" >> "$FAKE_LOG"\n'
                f"exit {exit_code}\n",
                encoding="utf-8")
            tool.chmod(0o755)

        fake_tool("pam-auth-update", 0)
        fake_tool("systemctl", 0)
        fake_tool("fic", 0)
        fake_tool("fic-dick", 0)

        generated = subprocess.run(
            ["bash", "-c",
             'pkg_root="$1"; '
             'set -- 0.1.0; '
             'source "$BUILDER" >/dev/null 2>&1; '
             'write_system_integration_symlink_postinst "$pkg_root" fic '
             '"/opt/fic/bin/fic"',
             "bash", str(package_root)],
            cwd=root,
            env={"PATH": "/usr/bin:/bin",
                 "BUILDER": str(root / "packaging/deb/build-fic-debian12-deb.sh")},
            text=True,
            capture_output=True,
            check=False)
        require(generated.returncode == 0,
                "could not generate Debian postinst for the behavioral "
                "check: " + generated.stderr.strip())
        postinst_text = (package_root / "DEBIAN/postinst").read_text(
            encoding="utf-8")
        configure_start = postinst_text.find(
            'if [ "${1:-}" = "configure" ]; then')
        require(configure_start >= 0,
                "generated postinst lost its configure branch")
        configure_tail = postinst_text[configure_start:].replace(
            "/opt/fic/bin/fic-dick", "fic-dick").replace(
                "/opt/fic/bin/fic", "fic")
        tail_script = tmp_path / "configure-tail.sh"
        tail_script.write_text("#!/bin/sh\nset -e\n" + configure_tail,
                               encoding="utf-8")
        tail_script.chmod(0o755)

        # Success path: validation passes → hooks attach → daemon starts.
        ran = subprocess.run(
            [str(tail_script), "configure"],
            env={"PATH": str(fake_bin), "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(ran.returncode == 0,
                "postinst configure tail failed under fake binaries: " +
                ran.stderr.strip())
        calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        validate_calls = [index for index, line in enumerate(calls)
                          if "validate-pam-slots-before-attach" in line]
        pam_package_calls = [index for index, line in enumerate(calls)
                             if line.startswith("pam-auth-update --package")]
        pam_enable_calls = [index for index, line in enumerate(calls)
                            if line.startswith("pam-auth-update --enable")]
        daemon_start_calls = [index for index, line in enumerate(calls)
                              if "enable --now fic.service" in line]
        require(validate_calls and pam_package_calls and pam_enable_calls
                and daemon_start_calls
                and max(validate_calls) < min(pam_package_calls)
                and max(pam_package_calls) < min(pam_enable_calls)
                and max(pam_enable_calls) < min(daemon_start_calls),
                "postinst attach-order regression: validation, "
                "pam-auth-update and daemon start are out of order: " +
                "\n".join(calls))
        enable_call = calls[min(pam_enable_calls)]
        for hook in ("fic-faillock-hook-preauth", "fic-faillock-hook-authfail",
                     "fic-faillock-hook-authsucc", "fic-faillock-hook-account"):
            require(hook in enable_call,
                    f"postinst did not enable permanent hook {hook} "
                    "in the behavioral check")

        # Failure path: the pre-attach validator refuses → exit non-zero,
        # no pam-auth-update, no daemon start.
        log.unlink(missing_ok=True)
        fake_tool("fic", 1)
        refused = subprocess.run(
            [str(tail_script), "configure"],
            env={"PATH": str(fake_bin), "FAKE_LOG": str(log)},
            text=True,
            capture_output=True,
            check=False)
        require(refused.returncode != 0,
                "postinst must abort when pre-attach slot validation fails")
        refused_calls = log.read_text(encoding="utf-8").splitlines() \
            if log.is_file() else []
        require(not any(line.startswith("pam-auth-update")
                        for line in refused_calls),
                "pam-auth-update ran although pre-attach validation failed")
        require(not any("enable --now" in line for line in refused_calls),
                "daemon was started although pre-attach validation failed")
        require("pre-attach validation" in refused.stderr,
                "postinst failure diagnostic must mention pre-attach "
                "validation: " + refused.stderr.strip())


    require('if [ "\\$1" = "remove" ]; then' in fic_prerm,
            "PAM profile removal is not limited to package removal")
    require('if [ "\\${1:-}" = "configure" ]; then' in fic_postinst,
            "PAM profile registration is not limited to postinst configure")
    require("pam-auth-update" not in generic_prerm,
            "CLI/GUI package removal must not unregister fic PAM profiles")
    require("pam-auth-update --force" not in deb_builder,
            "maintainer scripts must not force PAM regeneration")
    require("pam-auth-update --enable" in fic_postinst,
            "Debian postinst does not enable permanent faillock hooks")
    for hook in (
        "fic-faillock-hook-preauth",
        "fic-faillock-hook-authfail",
        "fic-faillock-hook-authsucc",
        "fic-faillock-hook-account",
    ):
        require(hook in fic_postinst,
                f"Debian postinst does not enable permanent hook {hook}")
    for legacy_policy_profile in (
        "fic-faillock-notify",
        "fic-faillock-preauth-required",
        "fic-faillock-authsucc",
        "fic-pwquality",
        "fic-pwhistory",
    ):
        enable_pos = fic_postinst.find("pam-auth-update --enable")
        require(legacy_policy_profile not in fic_postinst[enable_pos:],
                f"postinst must not activate policy-owned legacy profile {legacy_policy_profile}")

    for forbidden in ("pam-auth-update", "libpam-runtime", "libpam-modules", "pam-configs/fic-"):
        require(forbidden not in rpm_builder, f"ALT packaging contains Debian PAM integration: {forbidden}")
        require(forbidden not in fic_cmake, f"generic CMake installs Debian PAM integration: {forbidden}")

    require(rpm_facility_path.is_file() and not rpm_facility_path.is_symlink(),
            "ALT fic-pam-faillock facility is missing")
    require(rpm_facility_path.stat().st_mode & 0o111,
            "ALT fic-pam-faillock facility is not executable")
    for operation in ("help", "list", "summary", "status", "enabled", "disabled"):
        require(operation in rpm_facility,
                f"ALT facility does not implement control operation: {operation}")
    require(". /etc/control.d/functions" in rpm_facility and
            "new_help enabled" in rpm_facility and
            "new_help disabled" in rpm_facility,
            "ALT facility does not use the native control protocol")
    require("--maintenance pam-alt-faillock" in rpm_facility,
            "ALT facility does not dispatch to the FIC PAM helper")
    for forbidden in ("sed ", "sed\t", "pam_faillock.so", "pam_tcb.so"):
        require(forbidden not in rpm_facility,
                f"ALT facility contains topology implementation: {forbidden}")

    require(rpm_history_facility_path.is_file() and
            not rpm_history_facility_path.is_symlink(),
            "ALT fic-pam-pwhistory facility is missing")
    require(rpm_history_facility_path.stat().st_mode & 0o111,
            "ALT fic-pam-pwhistory facility is not executable")
    for operation in ("help", "list", "summary", "status", "enabled", "disabled"):
        require(operation in rpm_history_facility,
                f"ALT password-history facility lacks operation: {operation}")
    require("--maintenance pam-alt-pwhistory" in rpm_history_facility,
            "ALT password-history facility does not dispatch to FIC")
    for forbidden in ("sed ", "sed\t", "pam_tcb.so"):
        require(forbidden not in rpm_history_facility,
                f"ALT password-history facility implements topology: {forbidden}")

    rpm_fic_package = function_body(rpm_builder, "build_fic_package")
    require('"$ROOT_DIR/packaging/rpm/fic-pam-faillock"' in rpm_fic_package and
            '"$package_root/etc/control.d/facilities/fic-pam-faillock"' in rpm_fic_package,
            "ALT fic package does not stage its control facility")
    require('"$ROOT_DIR/packaging/rpm/fic-pam-pwhistory"' in rpm_fic_package and
            '"$package_root/etc/control.d/facilities/fic-pam-pwhistory"' in rpm_fic_package,
            "ALT fic package does not stage its password-history facility")
    for dependency in ("control", "pam >= 1.7.1", "pam-config >= 1.10.0"):
        require(dependency in rpm_fic_package,
                f"ALT fic package lacks PAM facility dependency: {dependency}")
    for facility in ("fic-pam-faillock", "fic-pam-pwhistory"):
        require(f"control-dump {facility}" in rpm_builder and
                f"control-restore {facility}" in rpm_builder,
                f"ALT RPM upgrade does not preserve {facility} state")
    require('if [ "$1" -eq 0 ]; then' in
            function_body(rpm_builder, "fic_pam_facility_preun_script") and
            "control fic-pam-faillock disabled" in rpm_builder and
            "control fic-pam-pwhistory disabled" in rpm_builder,
            "ALT RPM final erase does not remove FIC-owned PAM topology")
    post_hook = function_body(rpm_builder, "fic_pam_facility_post_script")
    require("control fic-pam-faillock enabled" not in post_hook and
            "control fic-pam-pwhistory enabled" not in post_hook and
            "pam-alt-pwhistory prepare" in post_hook and
            "control-restore" in post_hook,
            "ALT RPM install must prepare storage without enabling PAM topology")
    require("%config(noreplace)" in rpm_builder and
            "/etc/security/fic-pwhistory.conf" in rpm_builder,
            "ALT pam_pwhistory config is not preserved across upgrades")
    require("pam_fic_pwtxn" in fic_cmake and
            "fic-pwhistory.conf" in fic_cmake,
            "ALT PAM transaction module/config are not installed by CMake")
    require("fic-pam-passwdqc" not in rpm_builder,
            "ALT RPM must not install unsupported PAM facilities")

    print("PAM packaging checks passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"PAM packaging checks failed: {error}", file=sys.stderr)
        sys.exit(1)
