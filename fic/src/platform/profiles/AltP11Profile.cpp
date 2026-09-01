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
         PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller}
    };
    profile.pam.trustedServiceAliases = {
        {"/etc/pam.d/system-auth",
         {"/etc/pam.d/system-auth-local",
          "/etc/pam.d/system-auth-ldap",
          "/etc/pam.d/system-auth-krb5",
          "/etc/pam.d/system-auth-krb5_ccreds",
          "/etc/pam.d/system-auth-winbind",
          "/etc/pam.d/system-auth-multi",
          "/etc/pam.d/system-auth-pkcs11"}},
        {"/etc/pam.d/system-auth-use_first_pass",
         {"/etc/pam.d/system-auth-use_first_pass-local",
          "/etc/pam.d/system-auth-use_first_pass-ldap",
          "/etc/pam.d/system-auth-use_first_pass-krb5",
          "/etc/pam.d/system-auth-use_first_pass-krb5_ccreds",
          "/etc/pam.d/system-auth-use_first_pass-winbind",
          "/etc/pam.d/system-auth-use_first_pass-multi",
          "/etc/pam.d/system-auth-use_first_pass-pkcs11"}},
        {"/etc/pam.d/system-policy",
         {"/etc/pam.d/system-policy-local",
          "/etc/pam.d/system-policy-remote"}}
    };
    profile.pam.capabilities = {
        {PamCapability::AuthenticationLockout, PamProviderKind::PamFaillock,
         PamScope::EffectiveAuthenticationStack,
         "/etc/security/faillock.conf",
         PamTopologyStrategyKind::AltTcbManaged,
         "/etc/pam.d/system-auth-local-only"},
        {PamCapability::PasswordQuality, PamProviderKind::PamPasswdqc,
         PamScope::EffectivePasswordStack,
         "/etc/passwdqc.conf",
         PamTopologyStrategyKind::StaticReadOnly, {}, std::nullopt,
         PamIdentitySubjectScope::AllPamSubjects},
        {PamCapability::PasswordHistory, PamProviderKind::PamPwhistory,
         PamScope::LocalPasswordChange,
         "/etc/security/fic-pwhistory.conf",
         PamTopologyStrategyKind::AltTcbManaged,
         "/etc/pam.d/system-auth-local-only",
         ficPwhistoryConfigTopology()}
    };
    profile.passwordAging.shadowKind = LocalShadowKind::TcbDirectory;
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {"/etc/gdm/custom.conf"};
    profile.grub.defaultsPath = "/etc/sysconfig/grub2";
    profile.grub.rebuildArguments = {"-o", "/etc/grub.cfg"};
    profile.dac.protectedSystemFiles = {
        {"/etc/bashrc", "root", "root", 0644},
        {"/etc/crontab", "root", "root", 0600},
        {"/etc/fstab", "root", "root", 0644},
        {"/etc/hostname", "root", "root", 0644},
        {"/etc/hosts", "root", "root", 0644},
        {"/etc/hosts.allow", "root", "root", 0644},
        {"/etc/hosts.deny", "root", "root", 0644},
        {"/etc/group", "root", "root", 0644},
        {"/etc/resolv.conf", "root", "root", 0644},
        {"/etc/sysctl.conf", "root", "root", 0644, {
            "/etc/sysctl.d/99-sysctl.conf"
        }},
        {"/etc/logrotate.conf", "root", "root", 0644},
        {"/etc/inittab", "root", "root", 0644},
        {"/etc/passwd", "root", "root", 0644},
        {"/etc/shadow", "root", "shadow", 0640},
        {"/etc/grub.cfg", "root", "root", 0600, {
            "/boot/grub/grub.cfg"
        }},
        {"/etc/securetty", "root", "root", 0600}
    };
    profile.dac.protectedSystemFiles.push_back(
        {profile.sudo.mainConfigPath, "root", "root", 0440});
    profile.dac.protectedSystemCommands = {
        {"/bin/df", "root", "root", 0750},
        {"/usr/bin/chattr", "root", "root", 0750},
        {"/usr/sbin/arp", "root", "root", 0750},
        {"/sbin/ip", "root", "root", 0750}
    };
    return profile;
}

} // namespace fic::platform
