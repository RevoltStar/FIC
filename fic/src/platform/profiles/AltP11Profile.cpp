#include "platform/PlatformProfile.h"

namespace fic::platform {

namespace {

PamProviderConfigTopology ficPwhistoryConfigTopology() {
    PamProviderConfigTopology topology;
    topology.primaryPath = "/etc/security/fic-pwhistory.conf";
    topology.explicitConfig =
        PamExplicitConfigSemantics::ReplacesNativeTopology;
    return topology;
}

} // namespace

PlatformProfile makeBuildPlatformProfile() {
    PlatformProfile profile;
    profile.id = "alt-p11";
    profile.displayName = "ALT Linux p11";
    profile.hostCompatibility.osIds = {"altlinux"};
    profile.hostCompatibility.altBranchIds = {"p11"};
    profile.userCreation.supplementaryGroupsProvider =
        UserSupplementaryGroupsProviderKind::Unsupported;
    // Conservative verified contract for ALT p11: keep the legacy prefix
    // parser model. Exact-key behavior must not be assumed without distro
    // source evidence; EOF overrides are safe under this stricter model.
    profile.userCreation.useraddDefaultsLookup =
        UseraddDefaultsLookupSemantics::LegacyPrefixMatch;
    profile.userCreation.adduserConfigPath.clear();
    profile.executables.entries = {
        {
            ExecutableId::Sshd,
            {"/usr/sbin/sshd"}
        },
        {
            ExecutableId::Systemctl,
            {"/usr/bin/systemctl", "/bin/systemctl"}
        },
        {
            ExecutableId::Loginctl,
            {"/usr/bin/loginctl", "/bin/loginctl"}
        },
        {
            ExecutableId::Visudo,
            {"/usr/sbin/visudo"}
        },
        {
            ExecutableId::Lscpu,
            {"/usr/bin/lscpu", "/bin/lscpu"}
        },
        {
            ExecutableId::Dmidecode,
            {"/usr/sbin/dmidecode", "/sbin/dmidecode"}
        },
        {
            ExecutableId::Udevadm,
            {"/usr/bin/udevadm", "/usr/sbin/udevadm", "/bin/udevadm", "/sbin/udevadm"}
        },
        {
            ExecutableId::UpdateGrub,
            {"/usr/sbin/grub-mkconfig", "/usr/bin/grub-mkconfig"}
        },
        {
            ExecutableId::Nft,
            {"/usr/sbin/nft"}
        },
        {
            ExecutableId::Chage,
            {"/usr/bin/chage"}
        },
        {
            ExecutableId::Gpasswd,
            {"/usr/bin/gpasswd", "/usr/sbin/gpasswd"}
        },
        {
            ExecutableId::Dconf,
            {"/usr/bin/dconf"},
            false
        },
        {
            ExecutableId::Gsettings,
            {"/usr/bin/gsettings"},
            false
        }
    };
    profile.packageManager.kind = PackageManagerKind::Rpm;
    profile.packageManager.queryCandidates = {"/bin/rpm", "/usr/bin/rpm"};
    profile.ssh.configPath = "/etc/openssh/sshd_config";
    profile.ssh.includeBasePath = "/etc/openssh";
    profile.ssh.serviceUnits = {"sshd.service"};
    profile.sudo.mainConfigPath = "/etc/sudoers";
    profile.sudo.managedConfigPath = "/etc/sudoers.d/zzzz-fic";
    profile.sysctl.loader = SysctlLoaderKind::SystemdSysctl;
    profile.sysctl.managedConfigPath = "/etc/sysctl.d/zzzz-fic.conf";
    profile.pam.configDirectories = {
        "/etc/pam.d",
        "/usr/lib/pam.d",
        "/usr/share/pam/pam.d"
    };
    profile.pam.moduleDirectories = {
        "/lib/security", "/lib64/security",
        "/usr/lib/security", "/usr/lib64/security"
    };
#ifdef FIC_LIBRARY_ARCHITECTURE
    profile.pam.moduleDirectories.push_back(
        std::filesystem::path("/lib") / FIC_LIBRARY_ARCHITECTURE / "security");
    profile.pam.moduleDirectories.push_back(
        std::filesystem::path("/usr/lib") / FIC_LIBRARY_ARCHITECTURE / "security");
#endif
    profile.pam.scopes = {
        {PamScope::EffectiveAuthenticationStack,
         {"login", "sshd", "sudo", "su", "sddm", "gdm-password",
          "lightdm", "system-auth"}},
        {PamScope::EffectivePasswordStack, {"passwd", "system-auth"}},
        {PamScope::LocalPasswordChange, {"system-auth-local-only"}}
    };
    profile.pam.trustedAuthenticationBypasses = {
        {"su", "pam_rootok.so",
         PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller},
        {"gdm-password", "pam_succeed_if.so",
         PamTrustedAuthenticationBypassReason::ExplicitPasswordlessLogin,
         "sufficient", {"user", "ingroup", "nopasswdlogin"},
         "/etc/pam.d/gdm-password"},
        {"lightdm", "pam_succeed_if.so",
         PamTrustedAuthenticationBypassReason::ExplicitPasswordlessLogin,
         "sufficient", {"user", "ingroup", "nopasswdlogin"},
         "/etc/pam.d/lightdm"}
    };
    profile.pam.trustedServiceAliases = {
        {"/etc/pam.d/system-auth",
         {"/etc/pam.d/system-auth-local",
          "/etc/pam.d/system-auth-sss",
          "/etc/pam.d/system-auth-ldap",
          "/etc/pam.d/system-auth-krb5",
          "/etc/pam.d/system-auth-krb5_ccreds",
          "/etc/pam.d/system-auth-winbind",
          "/etc/pam.d/system-auth-multi",
          "/etc/pam.d/system-auth-pkcs11"}},
        {"/etc/pam.d/system-auth-use_first_pass",
         {"/etc/pam.d/system-auth-use_first_pass-local",
          "/etc/pam.d/system-auth-use_first_pass-sss",
          "/etc/pam.d/system-auth-use_first_pass-ldap",
          "/etc/pam.d/system-auth-use_first_pass-krb5",
          "/etc/pam.d/system-auth-use_first_pass-krb5_ccreds",
          "/etc/pam.d/system-auth-use_first_pass-winbind",
          "/etc/pam.d/system-auth-use_first_pass-multi",
          "/etc/pam.d/system-auth-use_first_pass-pkcs11"}},
        {"/etc/pam.d/system-policy",
         {"/etc/pam.d/system-policy-local",
          "/etc/pam.d/system-policy-remote"}},
        {"/etc/pam.d/system-check-localuser",
         {"/etc/pam.d/system-check-localuser-legacy",
          "/etc/pam.d/system-check-localuser-systemd"}}
    };
    profile.pam.capabilities = {
        {PamCapability::AuthenticationLockout, PamProviderKind::PamFaillock,
         PamScope::EffectiveAuthenticationStack,
         "/etc/security/faillock.conf",
         PamTopologyStrategyKind::AltTcbManaged,
         {}, std::nullopt, PamIdentitySubjectScope::LocalUsersOnly},
        {PamCapability::PasswordQuality, PamProviderKind::PamPasswdqc,
         PamScope::LocalPasswordChange,
         "/etc/passwdqc.conf",
         PamTopologyStrategyKind::StaticVerifyOnly, {}, std::nullopt,
         PamIdentitySubjectScope::LocalUsersOnly},
        {PamCapability::PasswordHistory, PamProviderKind::PamPwhistory,
         PamScope::LocalPasswordChange,
         "/etc/security/fic-pwhistory.conf",
         PamTopologyStrategyKind::AltTcbManaged,
         "/etc/pam.d/system-auth-local-only",
         ficPwhistoryConfigTopology()}
    };
    profile.pam.capabilities.front().managedTopologyTargets = {
        {"/etc/pam.d/system-auth-local-only",
         PamManagedTopologyTargetRole::AuthenticationAndAccount},
        {"/etc/pam.d/system-auth-use_first_pass-local-only",
         PamManagedTopologyTargetRole::Authentication}
    };
    profile.pam.capabilities.front().supportedFaillockStrategies = {
        PamFaillockStrategy::PreauthRequired,
        PamFaillockStrategy::PreauthRequisite};
    profile.pam.capabilities.front().defaultFaillockStrategy =
        PamFaillockStrategy::PreauthRequired;
    profile.pam.passwordlessLoginControl = {
        "nopasswdlogin", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
        {
            {{"files"}, {"files", "systemd"}},
            {{"files"}, {"files", "systemd"}, {"files", "role"},
             {"files", "systemd", "role"}},
            {{"files"}, {"files", "systemd"}, {"files", "role"},
             {"files", "systemd", "role"}}
        },
        {"sss"}};
    profile.passwordAging.shadowKind = LocalShadowKind::TcbDirectory;
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {"/etc/gdm/custom.conf"};
    profile.grub.topology = GrubConfigTopology::SharedDefaultsFile;
    profile.grub.sharedDefaultsPath = "/etc/sysconfig/grub2";
    profile.grub.rebuildArguments = {"-o", "/etc/grub.cfg"};
    std::vector<ModeAndOwnerPathProfiles> modeAndOwnerPaths = {
        {"/etc/bashrc", {"root", "root", 0644}, {"root", "root", 0644}, true},
        // NOTE (baseline verification): the ALT p11 RPM metadata could not be
        // queried from this environment (packages.altlinux.org and
        // rdb.altlinux.org are bot-gated). ALT vixie-cron historically ships
        // /etc/crontab as 0600 root:root, so the baseline deliberately stays
        // 0600 instead of copying the Debian 0644. Re-verify with
        // `rpm -q --dump cron` before ever changing this value.
        {"/etc/crontab", {"root", "root", 0600}, {"root", "root", 0600}, true},
        {"/etc/fstab", {"root", "root", 0644}, {"root", "root", 0644}, false},
        {"/etc/hostname", {"root", "root", 0644}, {"root", "root", 0644}, true},
        {"/etc/hosts", {"root", "root", 0644}, {"root", "root", 0644}, true},
        {"/etc/hosts.allow", {"root", "root", 0644}, {"root", "root", 0644}, true},
        {"/etc/hosts.deny", {"root", "root", 0644}, {"root", "root", 0644}, true},
        {"/etc/group", {"root", "root", 0644}, {"root", "root", 0644}, false},
        {"/etc/resolv.conf", {"root", "root", 0644}, {"root", "root", 0644}, true, {}, {
            // Provider metadata is the штатное provider state: baseline ==
            // enforced for every provider-managed final target.
            {"/run/NetworkManager/resolv.conf",
             ManagedFileProvider::NetworkManager,
             {"root", "root", 0644}, {"root", "root", 0644}}
        }},
        {"/etc/sysctl.conf", {"root", "root", 0644}, {"root", "root", 0644}, true, {
            "/etc/sysctl.d/99-sysctl.conf"
        }},
        {"/etc/logrotate.conf", {"root", "root", 0644}, {"root", "root", 0644}, true},
        {"/etc/inittab", {"root", "root", 0644}, {"root", "root", 0644}, true},
        {"/etc/passwd", {"root", "root", 0644}, {"root", "root", 0644}, false},
        // ALT native shadow state: root:root 0400 (ALT shadow topology, not
        // the Debian root:shadow 0640).
        {"/etc/shadow", {"root", "root", 0400}, {"root", "root", 0400}, false},
        {"/etc/grub.cfg", {"root", "root", 0600}, {"root", "root", 0600}, true, {
            "/boot/grub/grub.cfg"
        }},
        {"/etc/securetty", {"root", "root", 0600}, {"root", "root", 0600}, true}
    };
    modeAndOwnerPaths.push_back(
        {profile.sudo.mainConfigPath, {"root", "root", 0440}, {"root", "root", 0440}, false});
    // ALT p11 TCB storage is the native ALT credential topology (not the
    // Debian /etc/shadow model): the profile values are simultaneously the
    // hardening state and the ALT-native baseline, declared explicitly.
    std::optional<TcbCredentialStorageConfig> modeAndOwnerTcb = TcbCredentialStorageConfig{
        "/etc/tcb", "root", "shadow", 0710, 0710, "auth", 02710, 02710,
        {{"shadow", 0640, 0640, true},
         {"shadow-", 0640, 0640, false},
         {"shadow.lock", 0600, 0600, false}}};
    // Packaged executable metadata is root:root 0755 (RPM %defattr defaults
    // for coreutils, e2fsprogs, net-tools, iproute2); FIC hardens to 0750 and
    // exposes packaged 0755 as system and 0750 as strict. ALT keeps its topology:
    // /bin/df and /sbin/ip are not merged-/usr paths.
    std::vector<ModeAndOwnerPathProfiles> modeAndOwnerCommands = {
        {"/bin/df", {"root", "root", 0750}, {"root", "root", 0755}, false},
        {"/usr/bin/chattr", {"root", "root", 0750}, {"root", "root", 0755}, false},
        {"/usr/sbin/arp", {"root", "root", 0750}, {"root", "root", 0755}, true},
        {"/sbin/ip", {"root", "root", 0750}, {"root", "root", 0755}, false}
    };
    appendModeAndOwnerObjects(profile.dac, modeAndOwnerPaths, {
        "bashrc", "crontab", "fstab", "hostname", "hosts", "hosts_allow",
        "hosts_deny", "group", "resolv", "sysctl_config",
        "logrotate_config", "inittab", "passwd", "shadow", "grub_config",
        "securetty", "sudoers"}, modeAndOwnerCommands, {"df", "chattr", "arp", "ip"}, modeAndOwnerTcb);
    return profile;
}

} // namespace fic::platform
