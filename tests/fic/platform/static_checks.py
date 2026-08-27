#!/usr/bin/env python3
from pathlib import Path
import re
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
    for profile in ("debian-12", "debian-13", "ubuntu-24.04", "ubuntu-26.04", "alt-p11"):
        require(profile in cmake, f"CMake does not support platform {profile}")
    require(
        "message(FATAL_ERROR" in cmake,
        "an unspecified target platform must fail during CMake configuration",
    )

    daemon_main = (root / "fic/src/main.cpp").read_text(encoding="utf-8")
    require(
        "bool should_audit_ipc_request(const json& request)" in daemon_main
        and 'command != "boot_id" && command != "log_records"' in daemon_main
        and "if (should_audit_ipc_request(request))" in daemon_main,
        "log polling IPC commands must not write audit records into the paginated log stream",
    )
    platform_profile = (root / "fic/src/platform/PlatformProfile.h").read_text(
        encoding="utf-8"
    )
    require(
        "enum class SysctlLoaderKind" in platform_profile
        and "struct SysctlPlatformConfig" in platform_profile
        and "SysctlPlatformConfig sysctl" in platform_profile,
        "PlatformProfile must carry platform-specific SYSCTL loader configuration",
    )
    for profile_path in (root / "fic/src/platform/profiles").glob("*.cpp"):
        profile_source = profile_path.read_text(encoding="utf-8")
        require(
            "profile.sysctl.loader = SysctlLoaderKind::SystemdSysctl" in profile_source
            and 'profile.sysctl.managedConfigPath = "/etc/sysctl.d/zzzz-fic.conf"'
            in profile_source,
            f"{profile_path.relative_to(root)} does not configure systemd-sysctl managed path",
        )
    sysctl_configuration = (
        root / "fic/src/modules/sysctl/SysctlConfiguration.cpp"
    ).read_text(encoding="utf-8")
    require(
        "writeManaged(" in sysctl_configuration
        and "writeMain(" not in sysctl_configuration
        and "restoreMain(" not in sysctl_configuration
        and "options_.platform.managedConfigPath" in sysctl_configuration,
        "SYSCTL remediation must write only the platform managed sysctl file",
    )

    deprecated_exec_shield_tokens = (
        "kernel.exec-shield",
        "kernel_exec_shield_enable",
        "SYSCTL_buffer_overflow_protection",
    )
    policy_source_suffixes = {".cpp", ".h", ".conf", ".lang"}
    for source_path in (root / "fic").rglob("*"):
        if not source_path.is_file() or source_path.suffix not in policy_source_suffixes:
            continue
        source = source_path.read_text(encoding="utf-8")
        for token in deprecated_exec_shield_tokens:
            require(
                token not in source,
                f"removed exec-shield policy remains in {source_path.relative_to(root)}",
            )

    sysrq_policy = (
        root
        / "fic/src/modules/sysctl/global_kernel/policies/"
        "SYSCTL_sysrq_disable.cpp"
    ).read_text(encoding="utf-8")
    for token in (
        'sysctlParameter = "kernel.sysrq"',
        'sysctlParameterValue = "0"',
        'policyName = "kernel_sysrq_disable"',
        "FixedPolicyTypeValue",
    ):
        require(
            token in sysrq_policy,
            f"kernel SysRq policy is missing contract token {token}",
        )
    policy_registry = (
        root / "fic/src/daemon/main_function.cpp"
    ).read_text(encoding="utf-8")
    require(
        "SYSCTL_sysrq_disable" in policy_registry,
        "kernel SysRq policy is not registered in PolicyRegistry",
    )
    sysctl_config = (
        root / "fic/src/resources/config/SYSCTL.conf"
    ).read_text(encoding="utf-8")
    require(
        "kernel_sysrq_disable.status=DISABLE" in sysctl_config
        and "kernel_sysrq_disable.value=ENABLE" in sysctl_config,
        "SYSCTL.conf does not define kernel_sysrq_disable",
    )
    required_sysrq_descriptions = {
        "ru": (
            "При наличии параметра sysrq_always_enabled в загруженном ядре "
            "данная политика не имеет эффекта."
        ),
        "en": (
            "This policy has no effect when the loaded kernel has the "
            "sysrq_always_enabled parameter."
        ),
    }
    for language, required_text in required_sysrq_descriptions.items():
        localization = (
            root / f"fic/src/resources/lang/{language}.lang"
        ).read_text(encoding="utf-8")
        require(
            "[module:SYSCTL][policy:kernel_sysrq_disable]" in localization
            and required_text in localization,
            f"{language} localization does not fully describe kernel SysRq policy",
        )

    ssh = (root / "fic/src/modules/net/ssh/Ssh.cpp").read_text(
        encoding="utf-8"
    )
    runtime = (root / "fic/src/modules/net/ssh/SshRuntime.h").read_text(
        encoding="utf-8"
    )
    require("/etc/ssh/sshd_config" not in ssh, "Ssh.cpp contains a platform path")
    require(
        "/etc/ssh/sshd_config" not in runtime,
        "SshRuntime.h contains a platform path",
    )

    platform_consumers = {
        "fic/src/daemon/main_function.cpp": (
            "/usr/bin/loginctl",
            "/bin/loginctl",
        ),
        "fic/src/session/SessionLocator.cpp": (
            "/usr/bin/loginctl",
            "/bin/loginctl",
        ),
        "fic/src/modules/dac/sudo/Sudo.cpp": (
            "/etc/sudoers",
            "/usr/sbin/visudo",
        ),
        "fic/src/modules/dac/sudo/SudoersConfiguration.h": (
            "/etc/sudoers",
            "/etc/sudoers.d/zzzz-fic",
        ),
        "fic/src/modules/dac/mode_and_owner/policies/"
        "DAC_blocking_user_access_to_system_files.cpp": (
            "/etc/bashrc",
            "/etc/bash.bashrc",
            "/etc/grub.cfg",
            "/boot/grub/grub.cfg",
            "/etc/securetty",
        ),
        "fic/src/modules/dac/mode_and_owner/policies/"
        "DAC_systemcommandlock.cpp": (
            "/bin/df",
            "/usr/bin/chattr",
            "/sbin/ip",
        ),
        "fic/src/modules/oss/display_manager/DisplayManager.cpp": (
            "/usr/bin/systemctl",
            "/bin/systemctl",
        ),
        "fic/src/modules/oss/display_manager/backends/"
        "GdmBackend.cpp": (
            "/etc/gdm/custom.conf",
            "/etc/gdm3/daemon.conf",
        ),
        "fic/src/modules/oss/display_manager/backends/"
        "SddmBackend.cpp": ("/etc/sddm.conf",),
        "fic/src/modules/oss/display_manager/backends/"
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
            "ubuntu-26.04": "Ubuntu2604Profile.cpp",
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
        "ExecutableId::UpdateGrub",
        "ExecutableId::Nft",
        "ExecutableId::Chage",
        "packageManager.queryCandidates",
        "sudo.mainConfigPath",
        "pam.configDirectories",
        "pam.moduleDirectories",
        "pam.authenticationServices",
        "pam.passwordServices",
        "pam.trustedAuthenticationBypasses",
        "pam.faillockConfigPath",
        "pam.passwordQualityConfigPath",
        "pam.passwordHistoryConfigPath",
        "displayManager.sddmConfigPath",
        "displayManager.gdmConfigCandidates",
        "grub.defaultsPath",
        "grub.rebuildArguments",
        "dac.protectedSystemFiles",
        "dac.protectedSystemCommands",
    )
    for name, source in profiles.items():
        for section in required_profile_sections:
            require(
                section in source,
                f"platform profile {name} does not define {section}",
            )
        require(
            "ExecutableId::Chage" in source
            and '"/usr/bin/chage"' in source,
            f"{name} profile does not map the trusted chage executable",
        )
        require(
            "passwordAging.policyDefaults" not in source,
            f"{name} profile duplicates generated password-aging policy defaults",
        )

    require(
        "LocalShadowKind::TcbDirectory" in profiles["alt-p11"],
        "ALT p11 profile does not select the TCB backend",
    )
    require(
        'pam.localAuthenticationStackPath =\n        "/etc/pam.d/system-auth-local-only"'
        in profiles["alt-p11"]
        and "localAuthenticationStackPath" in platform_profile,
        "ALT p11 profile does not declare its native local PAM topology target",
    )

    platform_cmake = (
        root / "cmake/FicTargetPlatform.cmake"
    ).read_text(encoding="utf-8")
    generated_defaults = (
        root / "fic/src/platform/generated/PasswordAgingPolicyDefaultsGenerated.h.in"
    ).read_text(encoding="utf-8")
    user_creation_defaults = (
        root / "fic/src/platform/generated/UserCreationPolicyDefaultsGenerated.h.in"
    ).read_text(encoding="utf-8")
    required_pam_defaults = (
        root / "fic/src/platform/generated/RequiredPamEnforcementDefaultsGenerated.h.in"
    ).read_text(encoding="utf-8")
    identity_template = (
        root / "fic/src/resources/config/IDENTITY_ACCESS.conf.in"
    ).read_text(encoding="utf-8")
    oss_config = (
        root / "fic/src/resources/config/OSS.conf"
    ).read_text(encoding="utf-8")
    session_locator = (
        root / "fic/src/session/SessionLocator.cpp"
    ).read_text(encoding="utf-8")
    session_selection = (
        root / "fic/src/session/SessionSelection.cpp"
    ).read_text(encoding="utf-8")
    session_agent_client = (
        root / "fic/src/session/SessionAgentClient.cpp"
    ).read_text(encoding="utf-8")
    session_command_executor = (
        root / "fic/src/session/SessionCommandExecutor.cpp"
    ).read_text(encoding="utf-8")
    upgrade_contract = (
        root / "docs/upgrade-contract.md"
    ).read_text(encoding="utf-8")
    kde_media_policy_source = (
        root / "fic/src/modules/oss/desktop_environment/policies/"
        "OSS_disable_kde_lock_screen_media_controls.cpp"
    ).read_text(encoding="utf-8")
    for default_name in (
        "MIN_DAYS",
        "MAX_DAYS",
        "WARNING_DAYS",
        "UID_MIN",
        "UID_MAX",
    ):
        cmake_name = f"FIC_PASSWORD_AGING_POLICY_{default_name}_DEFAULT"
        require(cmake_name in platform_cmake, f"missing {cmake_name}")
        require(f"@{cmake_name}@" in generated_defaults,
                f"generated C++ defaults omit {cmake_name}")
        require(f"@{cmake_name}@" in identity_template,
                f"generated policy config omits {cmake_name}")
    for default_name in (
        "HOME_BASE", "CREATE_HOME", "SKEL", "SHELL", "PRIVATE_GROUP",
        "PRIMARY_GROUP",
    ):
        cmake_name = f"FIC_USER_CREATION_{default_name}_DEFAULT"
        require(cmake_name in platform_cmake, f"missing {cmake_name}")
        require(f"@{cmake_name}@" in user_creation_defaults,
                f"generated C++ defaults omit {cmake_name}")
        require(f"@{cmake_name}@" in identity_template,
                f"generated policy config omits {cmake_name}")
    require(
        'set(FIC_USER_CREATION_CREATE_HOME_DEFAULT "yes")' in platform_cmake,
        "ALT p11 CREATE_HOME default is not represented",
    )
    require(
        'set(FIC_USER_CREATION_SHELL_DEFAULT "/bin/bash")' in platform_cmake,
        "ALT p11 useradd shell default is not represented",
    )
    required_pam_name = "FIC_REQUIRED_PAM_ENFORCEMENT_DEFAULT"
    require(
        f"@{required_pam_name}@" in required_pam_defaults and
        f"@{required_pam_name}@" in identity_template,
        "required-PAM C++ and generated config defaults do not share the "
        "platform value",
    )
    require(
        '"pam_faillock,pam_pwquality,pam_pwhistory"' in platform_cmake and
        '"pam_faillock,pam_passwdqc"' in platform_cmake,
        "required-PAM platform defaults are incomplete",
    )
    require(
        "required_pam_enforcement.value=" +
        f"@{required_pam_name}@" in identity_template,
        "IDENTITY_ACCESS template hardcodes required-PAM providers",
    )
    kde_media_policy = "disable_kde_lock_screen_media_controls"
    require(
        f"{kde_media_policy}.status=DISABLE" in oss_config and
        f"{kde_media_policy}.value=ENABLE" in oss_config and
        f'policyName = "{kde_media_policy}"' in kde_media_policy_source and
        "OSS_disable_kde_lock_screen_media_controls" in policy_registry,
        "KDE lock-screen media-controls policy registration/config is incomplete",
    )
    for language in ("ru", "en"):
        localization = (
            root / f"fic/src/resources/lang/{language}.lang"
        ).read_text(encoding="utf-8")
        require(
            f"[module:OSS][policy:{kde_media_policy}]" in localization and
            f"[module:OSS][policy:{kde_media_policy}][description]" in localization,
            f"{language} localization omits the KDE media-controls policy",
        )
    require(
        "disable_videodisplay_when_locked" not in policy_registry + oss_config and
        "disable_videodisplay_when_locked" in upgrade_contract and
        "kdeMediaControlsCandidates" in kde_media_policy_source and
        "SelectionMode::ActiveGraphical" in session_locator and
        "SelectionMode::KdeMediaControls" in session_locator and
        "agentEndpointPresent" in session_selection and
        'properties.state == "closing"' in session_selection and
        'properties.state == "dead"' in session_selection and
        '"--property=Active"' not in session_locator,
        "KDE media-controls policy still has legacy naming/session filtering",
    )
    require(
        "safeEndpointPresent" in session_locator and
        "S_ISSOCK(info.st_mode)" in session_agent_client and
        "info.st_uid == expectedUid" in session_agent_client,
        "TTY discovery does not require an owned session-agent socket",
    )
    require(
        '{"XDG_SESSION_TYPE", context.sessionType}' in session_command_executor,
        "session commands do not use the canonical agent session type",
    )

    alt_profile = profiles["alt-p11"]
    require(
        'profile.grub.defaultsPath = "/etc/sysconfig/grub2";' in alt_profile,
        "ALT p11 GRUB policies do not use the canonical regular defaults file",
    )
    require(
        'profile.grub.rebuildArguments = {"-o", "/etc/grub.cfg"};'
        in alt_profile,
        "ALT p11 grub-mkconfig does not target /etc/grub.cfg",
    )
    require(
        '"/usr/sbin/grub-mkconfig", "/usr/bin/grub-mkconfig"'
        in alt_profile,
        "ALT p11 GRUB generator candidates are incorrect",
    )
    require(
        "update-grub" not in alt_profile,
        "ALT p11 mixes incompatible GRUB generator interfaces",
    )
    for path, target, mode in (
        ("/etc/sysctl.conf", "/etc/sysctl.d/99-sysctl.conf", "0644"),
        ("/etc/grub.cfg", "/boot/grub/grub.cfg", "0600"),
    ):
        pattern = (
            rf'\{{"{re.escape(path)}", "root", "root", {mode},\s*'
            rf'\{{\s*"{re.escape(target)}"\s*\}}\}}'
        )
        require(
            re.search(pattern, alt_profile) is not None,
            f"ALT p11 does not allow the package-owned target of {path}",
        )
    for name in ("debian-12", "debian-13", "ubuntu-24.04", "ubuntu-26.04"):
        require(
            "profile.grub.rebuildArguments = {};" in profiles[name],
            f"{name} update-grub must not receive arguments",
        )
        require(
            '"/usr/sbin/update-grub", "/usr/bin/update-grub"'
            in profiles[name],
            f"{name} update-grub candidates are incorrect",
        )
        require(
            '"/etc/resolv.conf", "root", "root", 0644, {' in profiles[name]
            and '"/run/systemd/resolve/stub-resolv.conf"' in profiles[name]
            and '"/run/systemd/resolve/resolv.conf"' in profiles[name]
            and '"/usr/lib/systemd/resolv.conf"' in profiles[name],
            f"{name} does not declare the expected systemd-resolved targets",
        )

    require(
        '"/etc/resolv.conf", "root", "root", 0644, {' not in alt_profile
        and "/run/systemd/resolve/" not in alt_profile,
        "ALT p11 unexpectedly permits systemd-resolved symlink targets",
    )

    for language in ("ru", "en"):
        localization = (
            root / f"fic/src/resources/lang/{language}.lang"
        ).read_text(encoding="utf-8")
        require(
            "/etc/sysconfig/securetty" not in localization,
            f"{language} localization contains a stale platform-specific DAC path",
        )
        require(
            "[module:DAC][message:platform_access_rules]" in localization,
            f"{language} localization does not describe profile-derived DAC rules",
        )

    registry = (root / "fic/src/daemon/main_function.cpp").read_text(encoding="utf-8")
    require(
        "const fic::platform::PlatformExecutableResolver& executables" in registry,
        "PolicyRegistry and lock operations must receive the platform executable resolver",
    )
    for policy_class in (
        "PamPasswordMinLengthPolicy",
        "PamPasswordMinClassesPolicy",
        "PamPasswordCheckUsernamePolicy",
        "PamPasswordCheckGecosPolicy",
        "PamPasswordQualityEnforceForRootPolicy",
        "PamPasswordMinChangedCharactersPolicy",
        "PamPasswordMinLowercasePolicy",
        "PamPasswordMinUppercasePolicy",
        "PamPasswordMinDigitsPolicy",
        "PamPasswordMinOtherPolicy",
        "PamPasswordHistoryDepthPolicy",
        "PamPasswordHistoryEnforceForRootPolicy",
        "PamFailedAuthenticationAttemptsPolicy",
        "PamFailedAuthenticationCountingPeriodPolicy",
        "PamFailedAuthenticationEnforceForRootPolicy",
        "PamFailedAuthenticationUnlockTimePolicy",
        "RequiredPamEnforcementPolicy",
        "SssdOfflineCredentialsExpirationPolicy",
        "KerberosTicketLifetimePolicy",
        "PasswordMinAgeDaysPolicy",
        "PasswordMaxAgeDaysPolicy",
        "PasswordExpirationWarningDaysPolicy",
        "RegularUserUidMinPolicy",
        "RegularUserUidMaxPolicy",
        "PasswordAgingApplyToExistingAccountsPolicy",
        "PasswordAgingEnforceForRootPolicy",
        "UserHomeBaseDirectoryPolicy",
        "UserCreateHomePolicy",
        "UserSkeletonDirectoryPolicy",
        "UserDefaultShellPolicy",
        "UserCreatePrivateGroupPolicy",
        "UserDefaultPrimaryGroupPolicy",
        "UserDefaultSupplementaryGroupsPolicy",
    ):
        require(
            policy_class in registry,
            f"identity-access policy {policy_class} is not registered in PolicyRegistry",
        )
    identity_config = (
        root / "fic/src/resources/config/IDENTITY_ACCESS.conf.in"
    ).read_text(encoding="utf-8")
    for policy_name in (
        "password_min_length",
        "password_min_classes",
        "password_check_username",
        "password_check_gecos",
        "password_quality_enforce_for_root",
        "password_min_changed_characters",
        "password_min_lowercase",
        "password_min_uppercase",
        "password_min_digits",
        "password_min_other",
        "password_history_depth",
        "password_history_enforce_for_root",
        "failed_authentication_attempts",
        "failed_authentication_counting_period",
        "failed_authentication_enforce_for_root",
        "failed_authentication_unlock_time",
        "required_pam_enforcement",
        "sssd_offline_credentials_expiration",
        "kerberos_ticket_lifetime",
        "password_min_age_days",
        "password_max_age_days",
        "password_expiration_warning_days",
        "regular_user_uid_min",
        "regular_user_uid_max",
        "password_aging_apply_to_existing_accounts",
        "password_aging_enforce_for_root",
        "user_home_base_directory",
        "user_create_home",
        "user_skeleton_directory",
        "user_default_shell",
        "user_create_private_group",
        "user_default_primary_group",
        "user_default_supplementary_groups",
    ):
        require(
            f"{policy_name}.value=" in identity_config
            and f"{policy_name}.status=" in identity_config,
            f"IDENTITY_ACCESS.conf does not define {policy_name}",
        )
        for language in ("ru", "en"):
            localization = (
                root / f"fic/src/resources/lang/{language}.lang"
            ).read_text(encoding="utf-8")
            require(
                f"[module:IDENTITY_ACCESS][policy:{policy_name}]" in localization,
                f"{language} localization does not define "
                f"IDENTITY_ACCESS/{policy_name}",
            )
            for submodule in (
                "PAM", "SSSD", "KERBEROS", "NSS", "COMPOSITE",
                "PASSWORD_AGING",
                "USER_CREATION",
            ):
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
        identity_root / "pam/PamPolicy.cpp"
    ).read_text(encoding="utf-8")
    composite_header = (
        identity_root / "composite/CompositePolicy.h"
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
        ("sssd/SssdPolicy.cpp", "SssdPolicy", "SSSD"),
        ("kerberos/KerberosPolicy.cpp", "KerberosPolicy", "KERBEROS"),
        ("nss/NssPolicy.cpp", "NssPolicy", "NSS"),
    ):
        source = (identity_root / relative_path).read_text(encoding="utf-8")
        require(
            f'{class_name}::{class_name}(' in source
            and f'IdentityAccessPolicy("{submodule_name}")' in source,
            f"{class_name} does not own submodule {submodule_name}",
    )
    for relative_path, editor_name in (
        ("sssd/SssdPolicy.h", "SssdConfiguration"),
        ("kerberos/KerberosPolicy.h", "KerberosConfiguration"),
        ("nss/NssPolicy.h", "NssConfiguration"),
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
        and not (root / "fic/src/resources/config/AUTH.conf").exists(),
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
        "Nft",
        "Chage",
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
    consumer_roots = (root / "fic/src",)
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
        "write_conffiles" not in deb_builder
        and "DEBIAN/conffiles" not in deb_builder,
        "Debian-family packaging still registers working configs as conffiles",
    )
    require(
        "-DFIC_TARGET_PLATFORM=alt-p11" in rpm_builder,
        "ALT p11 packaging does not fix its compile-time profile",
    )
    require(
        "/etc/control.d/facilities/fic-pam-faillock" in rpm_builder
        and "control-dump fic-pam-faillock" in rpm_builder
        and "control-restore fic-pam-faillock" in rpm_builder,
        "ALT p11 packaging does not preserve the native PAM facility lifecycle",
    )
    require(
        "%config" not in rpm_builder,
        "ALT p11 packaging still registers working configs as RPM configs",
    )
    fic_cmake = (root / "fic/CMakeLists.txt").read_text(encoding="utf-8")
    require(
        'src/resources/config/ DESTINATION "${FIC_DEFAULT_CONFIG_DIR}"' in fic_cmake
        and 'src/resources/config/ DESTINATION "${FIC_CONFIG_DIR}"' not in fic_cmake,
        "CMake does not install policy templates exclusively as immutable defaults",
    )
    install_layout = (root / "cmake/FicInstallLayout.cmake").read_text(
        encoding="utf-8"
    )
    require(
        'FIC_DEFAULT_CONFIG_DIR "${FIC_SHARE_DIR}/default-config"' in install_layout,
        "install layout has no centralized default configuration directory",
    )
    bootstrap_steps = (
        "--maintenance ensure-config",
        "--maintenance initialize-db",
        "--maintenance check-config",
        "--maintenance check-db",
        "--trust-sync-platform",
        "--maintenance wait-daemon ",
        "fic-dick wait-daemon 10",
    )
    for builder_name, builder in (
        ("Debian-family", deb_builder),
        ("ALT p11", rpm_builder),
    ):
        require(
            "-DFIC_PRODUCT_VERSION=$FIC_PRODUCT_VERSION" in builder
            and "-DFIC_BUILD_COMMIT=$FIC_BUILD_COMMIT" in builder
            and "-DFIC_RELEASE_TAG=$FIC_RELEASE_TAG" in builder
            and "-DFIC_RELEASE_BUILD=$FIC_RELEASE_BUILD" in builder,
            f"{builder_name} packaging does not embed its product version",
        )
        require(
            "packaging/lib/version-contract.sh" in builder
            and 'fic_configure_product_version "$@"' in builder
            and 'PACKAGE_VERSION="$FIC_PACKAGE_VERSION"' in builder,
            f"{builder_name} packaging bypasses the native version mapping",
        )
        cursor = 0
        for step in bootstrap_steps:
            position = builder.find(step, cursor)
            require(
                position >= 0,
                f"{builder_name} packaging omits bootstrap step: {step}",
            )
            cursor = position + len(step)
        require(
            "is-active --quiet fic.service" in builder,
            f"{builder_name} packaging omits daemon health checks",
        )
        require(
            "/opt/fic/state" not in builder,
            f"{builder_name} packaging retains the removed upgrade state directory",
        )
        require(
            "devices.seed.db" not in builder,
            f"{builder_name} packaging still ships the pre-contract database as a seed",
        )
        for obsolete in (
            "begin-upgrade", "migrate-config", "migrate-db", "commit-upgrade"
        ):
            require(
                obsolete not in builder,
                f"{builder_name} packaging retains obsolete state handling: {obsolete}",
            )
        require(
            "rm -rf /opt/fic" not in builder and "rm -r /opt/fic" not in builder,
            f"{builder_name} removal can recursively destroy persistent FIC state",
        )
    require(
        deb_builder.count('write_fic_preinst "$package_root"') >= 2,
        "Debian-family daemon packages do not stop services before payload replacement",
    )
    require(
        rpm_builder.count('"$(system_integration_pre_script') >= 2,
        "ALT p11 daemon packages do not stop services before payload replacement",
    )

    version_contract = (
        root / "fic-common/fic-version/include/fic/version/ProductVersion.h.in"
    ).read_text(encoding="utf-8")
    for constant in (
        "PRODUCT_VERSION", "BUILD_KIND", "BUILD_COMMIT", "RELEASE_TAG",
        "IPC_API_VERSION", "CONFIG_SCHEMA_VERSION", "DEVICE_DB_SCHEMA_VERSION",
        "DEVICE_DB_APPLICATION_ID",
    ):
        require(
            constant in version_contract,
            f"compiled version contract omits {constant}",
        )

    for config_name in (
        "AUDIT", "DAC", "DC", "FIREWALL", "GLOBAL", "IDENTITY_ACCESS", "NET", "OSS", "SYSCTL"
    ):
        suffix = ".conf.in" if config_name == "IDENTITY_ACCESS" else ".conf"
        config = (root / f"fic/src/resources/config/{config_name}{suffix}").read_text(
            encoding="utf-8"
        )
        require(
            config.startswith("_schema_version=1\n")
            and config.count("_schema_version=") == 1,
            f"{config_name}.conf does not declare exactly one schema version",
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
        require(
            "chmod 2750" in builder
            and "chmod 0640" in builder
            and "chmod 0750" in builder
            and "chmod 2770" not in builder
            and "chmod 0660" not in builder
            and "chmod 0770" not in builder,
            f"{builder_path.relative_to(root)} does not keep /opt/fic "
            "read-only for group fic",
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
            "packaging/lib/version-contract.sh" in builder
            and 'fic_configure_product_version "$@"' in builder
            and "0.1.0" not in builder,
            f"{builder_path.relative_to(root)} permits an implicit package version",
        )

    for unsupported_path in (
        "packaging/deb/Dockerfile.debian10",
        "packaging/deb/Dockerfile.debian11",
        "packaging/deb/build-fic-debian10-deb-docker.sh",
        "packaging/deb/build-fic-debian10-deb.sh",
        "packaging/deb/build-fic-debian11-deb-docker.sh",
        "packaging/deb/build-fic-debian11-deb.sh",
    ):
        require(
            not (root / unsupported_path).exists(),
            f"unsupported package entry point still exists: {unsupported_path}",
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

    command_hash_store = (
        root / "fic-common/fic-core/src/integrity/CommandHashStore.cpp"
    ).read_text(encoding="utf-8")
    exclusive_lock = (
        root / "fic-common/fic-core/include/fic/core/process/ExclusivePidLock.h"
    ).read_text(encoding="utf-8")
    notify_user = (
        root / "fic-common/fic-core/src/notification/NotifyUser.cpp"
    ).read_text(encoding="utf-8")
    require(
        "fileMode = 0640" in command_hash_store
        and "fileMode = 0660" not in command_hash_store,
        "command hash runtime writes must preserve group read-only access",
    )
    require(
        "S_IRGRP | S_IWGRP" not in exclusive_lock,
        "runtime lock files must not be group-writable",
    )
    require(
        "02750" in notify_user
        and "0640" in notify_user
        and "02770" not in notify_user
        and "0660" not in notify_user,
        "notification spool must remain group read-only",
    )

    for service_name in (
        "fic.service.in",
        "fic-device.service.in",
        "fic-notify.service.in",
        "fic_get_device_info.service.in",
        "fic_get_device_udev_info.service.in",
    ):
        service = (
            root / "fic/src/resources/service" / service_name
        ).read_text(encoding="utf-8")
        require(
            "UMask=0027" in service,
            f"{service_name} does not protect newly created runtime files",
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
