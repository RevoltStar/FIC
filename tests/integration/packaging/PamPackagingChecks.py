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
        "fic-faillock": {
            "Name": "FIC PAM faillock failed authentication counter",
            "Priority": "0",
            "rules": ("[default=die]\t\t\tpam_faillock.so authfail",),
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

    authfail = (profile_dir / "fic-faillock").read_text(encoding="utf-8")
    require(field(authfail, "Auth-Type") == "Primary", "authfail profile Auth-Type is not Primary")

    history = (profile_dir / "fic-pwhistory").read_text(encoding="utf-8")
    require(field(history, "Password-Type") == "Primary", "history profile Password-Type is not Primary")
    require("Password-Initial:" in history, "history profile has no Password-Initial stanza")

    deb_builder = (root / "packaging/deb/build-fic-debian12-deb.sh").read_text(encoding="utf-8")
    rpm_builder = (root / "packaging/rpm/build-fic-alt-p11-rpm.sh").read_text(encoding="utf-8")
    rpm_facility_path = root / "packaging/rpm/fic-pam-faillock"
    rpm_facility = rpm_facility_path.read_text(encoding="utf-8")
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
    require('"libpam-runtime" "libpam-modules"' in fic_package,
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

    rpm_fic_package = function_body(rpm_builder, "build_fic_package")
    require('"$ROOT_DIR/packaging/rpm/fic-pam-faillock"' in rpm_fic_package and
            '"$package_root/etc/control.d/facilities/fic-pam-faillock"' in rpm_fic_package,
            "ALT fic package does not stage its control facility")
    for dependency in ("control", "pam >= 1.7.1", "pam-config >= 1.10.0"):
        require(dependency in rpm_fic_package,
                f"ALT fic package lacks PAM facility dependency: {dependency}")
    require("control-dump fic-pam-faillock" in rpm_builder and
            "control-restore fic-pam-faillock" in rpm_builder,
            "ALT RPM upgrade does not preserve control facility state")
    require('if [ "$1" -eq 0 ]; then' in
            function_body(rpm_builder, "fic_pam_facility_preun_script") and
            "control fic-pam-faillock disabled" in rpm_builder,
            "ALT RPM final erase does not remove FIC-owned PAM topology")
    post_hook = function_body(rpm_builder, "fic_pam_facility_post_script")
    require("control fic-pam-faillock enabled" not in post_hook and
            "control-restore" in post_hook,
            "ALT RPM install must not automatically enable pam_faillock")
    require("fic-pam-pwhistory" not in rpm_builder and
            "fic-pam-passwdqc" not in rpm_builder,
            "ALT RPM must not install unsupported PAM facilities")

    print("PAM packaging checks passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"PAM packaging checks failed: {error}", file=sys.stderr)
        sys.exit(1)
