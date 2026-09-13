#!/usr/bin/env python3

import re
import sys
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

    history = (profile_dir / "fic-pwhistory").read_text(encoding="utf-8")
    require(field(history, "Password-Type") == "Primary", "history profile Password-Type is not Primary")
    require("Password-Initial:" in history, "history profile has no Password-Initial stanza")

    deb_builder = (root / "packaging/deb/build-fic-debian12-deb.sh").read_text(encoding="utf-8")
    rpm_builder = (root / "packaging/rpm/build-fic-alt-p11-rpm.sh").read_text(encoding="utf-8")
    rpm_facility_path = root / "packaging/rpm/fic-pam-faillock"
    rpm_facility = rpm_facility_path.read_text(encoding="utf-8")
    rpm_history_facility_path = root / "packaging/rpm/fic-pam-pwhistory"
    rpm_history_facility = rpm_history_facility_path.read_text(encoding="utf-8")
    fic_cmake = (root / "fic/CMakeLists.txt").read_text(encoding="utf-8")

    fic_package = function_body(deb_builder, "build_fic_package")
    fic_dick_package = function_body(deb_builder, "build_fic_dick_package")
    fic_postinst = function_body(deb_builder, "write_system_integration_symlink_postinst")
    fic_prerm = function_body(deb_builder, "write_system_integration_symlink_prerm")
    generic_prerm = function_body(deb_builder, "write_symlink_prerm")

    require('local profile_dir="$package_root/usr/share/pam-configs"' in deb_builder,
            "Debian builder does not stage profiles in /usr/share/pam-configs")
    require('install_fic_pam_profiles "$package_root"' in fic_package,
            "Debian fic package does not install PAM profiles")
    require(deb_builder.count('install_fic_pam_profiles "$package_root"') == 1,
            "PAM profiles must be staged only in the Debian fic package")
    require('"libpam-runtime" "libpam-modules" "libpam-pwquality"' in fic_package,
            "Debian fic package lacks direct PAM dependencies")
    require('package_depends="$(join_depends "$binary_depends" "udev")"' in fic_dick_package,
            "Debian fic-dick package does not compose the udev runtime dependency")
    require('"$package_name" \\\n        "$package_depends" \\' in fic_dick_package,
            "Debian fic-dick control file does not use its composed runtime dependencies")
    require("DEBIAN/conffiles" not in deb_builder,
            "package-owned PAM declarations must not be conffiles")
    require("pam-auth-update --package" in fic_postinst,
            "Debian postinst does not register package profiles")

    remove_start = fic_prerm.find("pam-auth-update --package --remove")
    remove_end = fic_prerm.find("\nfi", remove_start)
    require(remove_start >= 0 and remove_end > remove_start,
            "Debian prerm has no bounded PAM profile removal block")
    remove_block = fic_prerm[remove_start:remove_end]
    for name in expected:
        require(name in remove_block, f"Debian prerm does not remove {name}")

    require('if [ "\\$1" = "remove" ]; then' in fic_prerm,
            "PAM profile removal is not limited to package removal")
    require('if [ "\\${1:-}" = "configure" ]; then' in fic_postinst,
            "PAM profile registration is not limited to postinst configure")
    require("pam-auth-update" not in generic_prerm,
            "CLI/GUI package removal must not unregister fic PAM profiles")
    require("pam-auth-update --force" not in deb_builder,
            "maintainer scripts must not force PAM regeneration")
    require("pam-auth-update --enable" not in deb_builder,
            "maintainer scripts must not activate FIC PAM profiles")

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
