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
    for profile in ("debian-12", "debian-13", "ubuntu-24.04", "alt-p11"):
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
            "debian-13": "Debian13Profile.cpp",
            "ubuntu-24.04": "Ubuntu2404Profile.cpp",
            "alt-p11": "AltP11Profile.cpp",
        }.items()
    }
    required_profile_sections = (
        "profile.executables.entries",
        "ExecutableId::Sshd",
        "ExecutableId::Systemctl",
        "ExecutableId::Loginctl",
        "ExecutableId::Visudo",
        "ExecutableId::Lscpu",
        "ExecutableId::Dmidecode",
        "ExecutableId::Udevadm",
        "packageManager.queryCandidates",
        "sudo.mainConfigPath",
        "pam.configDirectories",
        "pam.moduleDirectories",
        "pam.authenticationServices",
        "pam.passwordServices",
        "pam.faillockConfigPath",
        "pam.passwordQualityConfigPath",
        "pam.passwordHistoryConfigPath",
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
        "const fic::platform::PlatformExecutableResolver& executables" in registry,
        "PolicyMap and lock operations must receive the platform executable resolver",
    )
    for policy_class in (
        "PamPasswordMinLengthPolicy",
        "PamPasswordMinClassesPolicy",
        "PamPasswordHistoryDepthPolicy",
        "PamFailedAuthenticationAttemptsPolicy",
        "PamFailedAuthenticationUnlockTimePolicy",
        "SssdOfflineCredentialsExpirationPolicy",
        "KerberosTicketLifetimePolicy",
    ):
        require(
            policy_class in registry,
            f"identity-access policy {policy_class} is not registered in PolicyMap",
        )
    identity_config = (
        root / "fic/src/scripts/config/IDENTITY_ACCESS.conf"
    ).read_text(encoding="utf-8")
    for policy_name in (
        "password_min_length",
        "password_min_classes",
        "password_history_depth",
        "failed_authentication_attempts",
        "failed_authentication_unlock_time",
        "sssd_offline_credentials_expiration",
        "kerberos_ticket_lifetime",
    ):
        require(
            f"{policy_name}.value=" in identity_config
            and f"{policy_name}.status=" in identity_config,
            f"IDENTITY_ACCESS.conf does not define {policy_name}",
        )
        for language in ("ru", "en"):
            localization = (
                root / f"fic/src/scripts/lang/{language}.lang"
            ).read_text(encoding="utf-8")
            require(
                f"[module:IDENTITY_ACCESS][policy:{policy_name}]" in localization,
                f"{language} localization does not define "
                f"IDENTITY_ACCESS/{policy_name}",
            )
            for submodule in ("PAM", "SSSD", "KERBEROS", "NSS", "COMPOSITE"):
                require(
                    f"[module:IDENTITY_ACCESS][submodule:{submodule}]"
                    in localization,
                    f"{language} localization does not define identity "
                    f"submodule {submodule}",
                )

    identity_root = root / "fic/src/modules/identity_access"
    identity_base = (
        identity_root / "IdentityAccessPolicy.cpp"
    ).read_text(encoding="utf-8")
    pam_policy = (
        identity_root / "submodules/pam/PamPolicy.cpp"
    ).read_text(encoding="utf-8")
    composite_header = (
        identity_root / "submodules/composite/CompositePolicy.h"
    ).read_text(encoding="utf-8")
    require(
        'moduleName = "IDENTITY_ACCESS"' in identity_base,
        "identity policy base does not own the IDENTITY_ACCESS module",
    )
    require(
        'IdentityAccessPolicy("PAM")' in pam_policy,
        "PAM policy base does not own the PAM submodule",
    )
    for relative_path, class_name, submodule_name in (
        ("submodules/sssd/SssdPolicy.cpp", "SssdPolicy", "SSSD"),
        ("submodules/kerberos/KerberosPolicy.cpp", "KerberosPolicy", "KERBEROS"),
        ("submodules/nss/NssPolicy.cpp", "NssPolicy", "NSS"),
    ):
        source = (identity_root / relative_path).read_text(encoding="utf-8")
        require(
            f'{class_name}::{class_name}(' in source
            and f'IdentityAccessPolicy("{submodule_name}")' in source,
            f"{class_name} does not own submodule {submodule_name}",
    )
    for relative_path, editor_name in (
        ("submodules/sssd/SssdPolicy.h", "SssdConfiguration"),
        ("submodules/kerberos/KerberosPolicy.h", "KerberosConfiguration"),
        ("submodules/nss/NssPolicy.h", "NssConfiguration"),
    ):
        header = (identity_root / relative_path).read_text(encoding="utf-8")
        require(
            editor_name in header,
            f"{relative_path} does not expose its configuration editor",
        )
    require(
        "ConfigurationParticipant" in composite_header
        and "unique_ptr<IdentityAccessPolicy>" not in composite_header,
        "CompositePolicy must compose configuration participants, not nested "
        "policies",
    )
    require(
        not (root / "fic/src/modules/auth").exists()
        and not (root / "fic/src/scripts/config/AUTH.conf").exists(),
        "obsolete AUTH module files remain after the identity-access rename",
    )
    resolver = (
        root / "fic/src/platform/PlatformExecutableResolver.cpp"
    ).read_text(encoding="utf-8")
    daemon_main = (root / "fic/src/main.cpp").read_text(encoding="utf-8")
    require(
        "--trust-list-platform-paths" in daemon_main
        and "--trust-sync-platform-affected" in daemon_main
        and daemon_main.index("selectAffectedExecutableIds")
        < daemon_main.index("FicRuntimePaths::initializeProduction"),
        "affected trust sync must filter profile paths before runtime initialization",
    )
    for executable_id in (
        "Sshd",
        "Systemctl",
        "Loginctl",
        "Visudo",
        "Lscpu",
        "Dmidecode",
        "Udevadm",
    ):
        require(
            f"ExecutableId::{executable_id}" in resolver,
            f"the resolver does not support logical executable {executable_id}",
        )
    require(
        "S_ISLNK" in resolver
        and "S_ISREG" in resolver
        and "S_IWGRP | S_IWOTH" in resolver,
        "the resolver must reject symlinks, non-files and writable executables",
    )

    obsolete_candidate_fields = (
        "sshdCandidates",
        "systemctlCandidates",
        "loginctlCandidates",
        "visudoCandidates",
        "SystemToolsPlatformConfig",
    )
    consumer_roots = (
        root / "fic/src/core",
        root / "fic/src/modules",
        root / "fic/src/session",
    )
    for consumer_root in consumer_roots:
        for source_path in consumer_root.rglob("*"):
            if source_path.suffix not in (".cpp", ".h"):
                continue
            source = source_path.read_text(encoding="utf-8")
            for obsolete in obsolete_candidate_fields:
                require(
                    obsolete not in source,
                    f"{source_path.relative_to(root)} still selects {obsolete} locally",
                )

    deb_builder = (
        root / "packaging/deb/build-fic-debian12-deb.sh"
    ).read_text(encoding="utf-8")
    rpm_builder = (
        root / "packaging/rpm/build-fic-alt-p11-rpm.sh"
    ).read_text(encoding="utf-8")
    rpm_file_trigger = (
        root / "packaging/rpm/fic-trust-sync.filetrigger"
    ).read_text(encoding="utf-8")
    ubuntu_builder = (
        root / "packaging/deb/build-fic-ubuntu2404-deb.sh"
    ).read_text(encoding="utf-8")
    debian13_builder = (
        root / "packaging/deb/build-fic-debian13-deb.sh"
    ).read_text(encoding="utf-8")
    debian13_docker_builder = (
        root / "packaging/deb/build-fic-debian13-deb-docker.sh"
    ).read_text(encoding="utf-8")
    debian13_dockerfile = (
        root / "packaging/deb/Dockerfile.debian13"
    ).read_text(encoding="utf-8")
    require(
        "-DFIC_TARGET_PLATFORM=$FIC_PACKAGING_TARGET_PLATFORM" in deb_builder,
        "Debian-family packaging does not pass its compile-time profile",
    )
    require(
        "/opt/fic/config/IDENTITY_ACCESS.conf" in deb_builder
        and "/opt/fic/config/AUTH.conf" not in deb_builder,
        "Debian-family packaging does not preserve IDENTITY_ACCESS.conf",
    )
    require(
        "-DFIC_TARGET_PLATFORM=alt-p11" in rpm_builder,
        "ALT p11 packaging does not fix its compile-time profile",
    )
    require(
        "/opt/fic/config/IDENTITY_ACCESS.conf" in rpm_builder
        and "/opt/fic/config/AUTH.conf" not in rpm_builder,
        "ALT p11 packaging does not preserve IDENTITY_ACCESS.conf",
    )
    require(
        'FIC_PACKAGING_TARGET_PLATFORM="ubuntu-24.04"' in ubuntu_builder,
        "Ubuntu package entry point does not fix the Ubuntu profile",
    )
    require(
        "debian-13)" in deb_builder,
        "Debian-family packaging does not accept the Debian 13 profile",
    )
    require(
        'FIC_PACKAGING_TARGET_PLATFORM="debian-13"' in debian13_builder,
        "Debian 13 package entry point does not fix the Debian 13 profile",
    )
    require(
        "./build-fic-debian13-deb.sh" in debian13_docker_builder,
        "Debian 13 container entry point does not use the Debian 13 builder",
    )
    require(
        "FROM debian:13" in debian13_dockerfile,
        "Debian 13 packages must be built in a Debian 13 container",
    )

    primary_package_builders = (
        root / "packaging/deb/build-fic-debian10-deb.sh",
        root / "packaging/deb/build-fic-debian11-deb.sh",
        root / "packaging/deb/build-fic-debian12-deb.sh",
        root / "packaging/rpm/build-fic-alt-p11-rpm.sh",
    )
    native_package_builders = tuple(
        path
        for path in (root / "packaging").glob("*/build-fic-*.sh")
        if not path.name.endswith("-docker.sh")
    )
    require(native_package_builders, "no native package builders found")
    for builder_path in native_package_builders:
        builder = builder_path.read_text(encoding="utf-8")
        require(
            "packaging/lib/build-resources.sh" in builder,
            f"{builder_path.relative_to(root)} bypasses the shared resource policy",
        )

    for builder_path in primary_package_builders:
        builder = builder_path.read_text(encoding="utf-8")
        require(
            "packaging/lib/build-resources.sh" in builder
            and '--parallel "$BUILD_JOBS"' in builder,
            f"{builder_path.relative_to(root)} bypasses adaptive build parallelism",
        )

    container_builders = tuple(
        (root / "packaging").glob("*/build-fic-*-docker.sh")
    )
    require(container_builders, "no container package builders found")
    for builder_path in container_builders:
        builder = builder_path.read_text(encoding="utf-8")
        require(
            "fic_configure_container_resources" in builder
            and '"${FIC_CONTAINER_BUILD_ARGS[@]}"' in builder
            and '"${FIC_CONTAINER_RUN_ARGS[@]}"' in builder
            and '-e BUILD_JOBS="$BUILD_JOBS"' in builder,
            f"{builder_path.relative_to(root)} bypasses container resource limits",
        )

    require(
        "--trust-list-platform-paths" in deb_builder
        and "interest-noawait $candidate_path" in deb_builder
        and "--trust-sync-platform-affected" in deb_builder,
        "Debian package does not generate exact profile trust triggers",
    )
    require(
        "--trust-sync-platform" in deb_builder,
        "Debian package does not run package trust sync",
    )
    require(
        "fic-trust-sync.filetrigger" in rpm_builder
        and "--trust-sync-platform-affected" in rpm_file_trigger
        and "while IFS= read" not in rpm_file_trigger
        and "%transfiletriggerin" not in rpm_builder,
        "ALT package does not pass the complete affected path list to FIC",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
