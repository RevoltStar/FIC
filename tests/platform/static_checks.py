#!/usr/bin/env python3
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    if len(sys.argv) != 2:
        print("usage: static_checks.py <repo-root>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    cmake = (root / "cmake/FicTargetPlatform.cmake").read_text(encoding="utf-8")
    for profile in ("debian-12", "ubuntu-24.04", "alt-p11"):
        require(profile in cmake, f"CMake does not support platform {profile}")
    require(
        "message(FATAL_ERROR" in cmake,
        "an unspecified target platform must fail during CMake configuration",
    )

    ssh = (root / "fic/src/modules/net/submodules/Ssh.cpp").read_text(
        encoding="utf-8"
    )
    runtime = (root / "fic/src/modules/net/submodules/SshRuntime.h").read_text(
        encoding="utf-8"
    )
    require("/etc/ssh/sshd_config" not in ssh, "Ssh.cpp contains a platform path")
    require(
        "/etc/ssh/sshd_config" not in runtime,
        "SshRuntime.h contains a platform path",
    )

    platform_consumers = {
        "fic/src/core/main_function.cpp": (
            "/usr/bin/loginctl",
            "/bin/loginctl",
        ),
        "fic/src/session/SessionLocator.cpp": (
            "/usr/bin/loginctl",
            "/bin/loginctl",
        ),
        "fic/src/modules/dac/submodules/Sudo.cpp": (
            "/etc/sudoers",
            "/usr/sbin/visudo",
        ),
        "fic/src/modules/dac/submodules/sudo/SudoersConfiguration.h": (
            "/etc/sudoers",
            "/etc/sudoers.d/zzzz-fic",
        ),
        "fic/src/modules/dac/submodules/modeandowner/"
        "DAC_blocking_user_access_to_system_files.cpp": (
            "/etc/bashrc",
            "/etc/bash.bashrc",
            "/etc/grub.cfg",
            "/boot/grub/grub.cfg",
            "/etc/securetty",
        ),
        "fic/src/modules/dac/submodules/modeandowner/"
        "DAC_systemcommandlock.cpp": (
            "/bin/df",
            "/usr/bin/chattr",
            "/sbin/ip",
        ),
        "fic/src/modules/oss/submodules/DisplayManager.cpp": (
            "/usr/bin/systemctl",
            "/bin/systemctl",
        ),
        "fic/src/modules/oss/submodules/DisplayManager/backends/"
        "GdmBackend.cpp": (
            "/etc/gdm/custom.conf",
            "/etc/gdm3/daemon.conf",
        ),
        "fic/src/modules/oss/submodules/DisplayManager/backends/"
        "SddmBackend.cpp": ("/etc/sddm.conf",),
        "fic/src/modules/oss/submodules/DisplayManager/backends/"
        "LightDmBackend.cpp": ("/etc/lightdm/lightdm.conf",),
    }
    for relative_path, forbidden_paths in platform_consumers.items():
        source = (root / relative_path).read_text(encoding="utf-8")
        for forbidden_path in forbidden_paths:
            require(
                forbidden_path not in source,
                f"{relative_path} contains platform path {forbidden_path}",
            )

    profiles = {
        name: (
            root / f"fic/src/platform/profiles/{filename}"
        ).read_text(encoding="utf-8")
        for name, filename in {
            "debian-12": "Debian12Profile.cpp",
            "ubuntu-24.04": "Ubuntu2404Profile.cpp",
            "alt-p11": "AltP11Profile.cpp",
        }.items()
    }
    required_profile_sections = (
        "systemTools.systemctlCandidates",
        "systemTools.loginctlCandidates",
        "sudo.mainConfigPath",
        "sudo.visudoCandidates",
        "displayManager.sddmConfigPath",
        "displayManager.gdmConfigCandidates",
        "dac.protectedSystemFiles",
        "dac.protectedSystemCommands",
    )
    for name, source in profiles.items():
        for section in required_profile_sections:
            require(
                section in source,
                f"platform profile {name} does not define {section}",
            )

    for language in ("ru", "en"):
        localization = (
            root / f"fic/src/scripts/lang/{language}.lang"
        ).read_text(encoding="utf-8")
        require(
            "/etc/sysconfig/securetty" not in localization,
            f"{language} localization contains a stale platform-specific DAC path",
        )
        require(
            "[module:DAC][message:platform_access_rules]" in localization,
            f"{language} localization does not describe profile-derived DAC rules",
        )

    registry = (root / "fic/src/core/main_function.cpp").read_text(encoding="utf-8")
    require(
        "init_policyMap(const fic::platform::PlatformProfile& platform)" in registry,
        "PolicyMap must receive the selected platform profile",
    )

    deb_builder = (
        root / "packaging/deb/build-fic-debian12-deb.sh"
    ).read_text(encoding="utf-8")
    rpm_builder = (
        root / "packaging/rpm/build-fic-alt-p11-rpm.sh"
    ).read_text(encoding="utf-8")
    ubuntu_builder = (
        root / "packaging/deb/build-fic-ubuntu2404-deb.sh"
    ).read_text(encoding="utf-8")
    require(
        "-DFIC_TARGET_PLATFORM=$FIC_PACKAGING_TARGET_PLATFORM" in deb_builder,
        "Debian-family packaging does not pass its compile-time profile",
    )
    require(
        "-DFIC_TARGET_PLATFORM=alt-p11" in rpm_builder,
        "ALT p11 packaging does not fix its compile-time profile",
    )
    require(
        'FIC_PACKAGING_TARGET_PLATFORM="ubuntu-24.04"' in ubuntu_builder,
        "Ubuntu package entry point does not fix the Ubuntu profile",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
