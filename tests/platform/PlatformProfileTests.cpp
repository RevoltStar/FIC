#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TemporaryOsRelease {
public:
    TemporaryOsRelease() {
        char pattern[] = "/tmp/fic-platform-os-release-XXXXXX";
        const int descriptor = ::mkstemp(pattern);
        if (descriptor < 0) {
            throw std::runtime_error("cannot create temporary os-release");
        }
        ::close(descriptor);
        path = pattern;
    }

    ~TemporaryOsRelease() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    std::filesystem::path path;
};

fic::platform::OsReleaseValues compatibleValues(
    const fic::platform::PlatformProfile& profile) {
    fic::platform::OsReleaseValues values;
    values["ID"] = profile.hostCompatibility.osIds.front();
    if (!profile.hostCompatibility.versionIds.empty()) {
        values["VERSION_ID"] = profile.hostCompatibility.versionIds.front();
    }
    if (!profile.hostCompatibility.altBranchIds.empty()) {
        values["ALT_BRANCH_ID"] = profile.hostCompatibility.altBranchIds.front();
    }
    return values;
}

bool hasRule(const std::vector<fic::platform::FileAccessRule>& rules,
             const std::filesystem::path& path) {
    return std::any_of(
        rules.begin(), rules.end(),
        [&path](const fic::platform::FileAccessRule& rule) {
            return rule.path == path;
        });
}

const fic::platform::PlatformExecutableSpec& executableSpec(
    const fic::platform::PlatformProfile& profile,
    fic::platform::ExecutableId id) {
    const auto* spec =
        fic::platform::findExecutableSpec(profile.executables, id);
    if (spec == nullptr) {
        throw std::runtime_error(
            std::string("missing executable spec: ") +
            fic::platform::executableIdName(id));
    }
    return *spec;
}

fic::platform::PlatformExecutableSpec& executableSpec(
    fic::platform::PlatformProfile& profile,
    fic::platform::ExecutableId id) {
    for (auto& spec : profile.executables.entries) {
        if (spec.id == id) {
            return spec;
        }
    }
    throw std::runtime_error(
        std::string("missing executable spec: ") +
        fic::platform::executableIdName(id));
}

void testSelectedProfile() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    std::string error;
    require(fic::platform::validatePlatformProfile(profile, error), error);
    require(profile.sudo.mainConfigPath == "/etc/sudoers",
            "sudoers main configuration path is incorrect");
    require(profile.sudo.managedConfigPath == "/etc/sudoers.d/zzzz-fic",
            "managed sudoers path is incorrect");
    require(profile.sysctl.loader == fic::platform::SysctlLoaderKind::SystemdSysctl,
            "SYSCTL loader kind is incorrect");
    require(profile.sysctl.managedConfigPath == "/etc/sysctl.d/zzzz-fic.conf",
            "managed sysctl path is incorrect");
    require(executableSpec(profile, fic::platform::ExecutableId::Visudo).candidates ==
                std::vector<std::filesystem::path>({"/usr/sbin/visudo"}),
            "visudo candidates are incorrect");
    require(profile.executables.entries.size() ==
                fic::platform::allExecutableIds().size(),
            "the executable registry must contain every supported logical command");
    require(!profile.packageManager.queryCandidates.empty(),
            "package manager query candidates are missing");
    require(profile.displayManager.sddmConfigPath == "/etc/sddm.conf",
            "SDDM configuration path is incorrect");
    require(profile.displayManager.lightDmConfigPath ==
                "/etc/lightdm/lightdm.conf",
            "LightDM configuration path is incorrect");
    require(!profile.pam.configDirectories.empty(),
            "PAM configuration directories are missing");
    require(!profile.pam.moduleDirectories.empty(),
            "PAM module directories are missing");
    require(!profile.pam.authenticationServices.empty(),
            "PAM authentication services are missing");
    require(!profile.pam.passwordServices.empty(),
            "PAM password services are missing");
    require(profile.pam.faillockConfigPath == "/etc/security/faillock.conf",
            "pam_faillock configuration path is incorrect");
    require(profile.pam.passwordQualityConfigPath ==
                "/etc/security/pwquality.conf",
            "pam_pwquality configuration path is incorrect");
    require(profile.pam.passwordHistoryConfigPath ==
                "/etc/security/pwhistory.conf",
            "pam_pwhistory configuration path is incorrect");
    require(profile.grub.defaultsPath == "/etc/default/grub",
            "GRUB defaults path is incorrect");
    require(hasRule(profile.dac.protectedSystemFiles,
                    profile.sudo.mainConfigPath),
            "the selected sudoers configuration must be protected by DAC policy");

    if (profile.id == "alt-p11") {
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Rpm,
                "ALT p11 must use the RPM package database");
        require(profile.ssh.configPath == "/etc/openssh/sshd_config",
                "ALT p11 must use the OpenSSH configuration path");
        require(profile.ssh.serviceUnits ==
                    std::vector<std::string>({"sshd.service"}),
                "ALT p11 must use sshd.service");
        require(profile.displayManager.gdmConfigCandidates ==
                    std::vector<std::filesystem::path>({
                        "/etc/gdm/custom.conf"
                    }),
                "ALT p11 GDM configuration paths are incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bashrc"),
                "ALT p11 must protect /etc/bashrc");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/securetty"),
                "ALT p11 must protect /etc/securetty");
        require(!hasRule(profile.dac.protectedSystemFiles,
                         "/etc/sysconfig/securetty"),
                "ALT p11 must not use the obsolete securetty path");
        require(hasRule(profile.dac.protectedSystemCommands, "/sbin/ip"),
                "ALT p11 ip command path is incorrect");
        require(executableSpec(
                    profile,
                    fic::platform::ExecutableId::UpdateGrub).candidates ==
                    std::vector<std::filesystem::path>({
                        "/usr/sbin/grub-mkconfig",
                        "/usr/bin/grub-mkconfig"
                    }),
                "ALT p11 GRUB generator candidates are incorrect");
        require(profile.grub.rebuildArguments ==
                    std::vector<std::string>({"-o", "/etc/grub.cfg"}),
                "ALT p11 grub-mkconfig must write /etc/grub.cfg");
    } else if (profile.id == "debian-12") {
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Debian 12 must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Debian 12 SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/daemon.conf",
                "Debian 12 primary GDM configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Debian 12 must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemFiles,
                        "/boot/grub/grub.cfg"),
                "Debian 12 GRUB configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/sbin/ip"),
                "Debian 12 ip command path is incorrect");
        require(executableSpec(
                    profile,
                    fic::platform::ExecutableId::UpdateGrub).candidates ==
                    std::vector<std::filesystem::path>({
                        "/usr/sbin/update-grub",
                        "/usr/bin/update-grub"
                    }),
                "Debian 12 update-grub candidates are incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Debian 12 update-grub must not receive arguments");
    } else if (profile.id == "debian-13") {
        require(profile.hostCompatibility.versionIds ==
                    std::vector<std::string>({"13"}),
                "Debian 13 must accept only VERSION_ID=13");
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Debian 13 must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Debian 13 SSH configuration path is incorrect");
        require(profile.ssh.serviceUnits ==
                    std::vector<std::string>({"ssh.service", "sshd.service"}),
                "Debian 13 SSH service units are incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/daemon.conf",
                "Debian 13 primary GDM configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Debian 13 must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemFiles,
                        "/boot/grub/grub.cfg"),
                "Debian 13 GRUB configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/bin/df"),
                "Debian 13 df command path must use the merged-/usr location");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/sbin/ip"),
                "Debian 13 ip command path is incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Debian 13 update-grub must not receive arguments");
    } else if (profile.id == "ubuntu-24.04") {
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Ubuntu 24.04 must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Ubuntu 24.04 SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/custom.conf",
                "Ubuntu 24.04 primary GDM configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Ubuntu 24.04 must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/bin/df"),
                "Ubuntu 24.04 df command path is incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Ubuntu 24.04 update-grub must not receive arguments");
    } else {
        throw std::runtime_error("unexpected selected platform profile: " + profile.id);
    }
}

void testCompatibilityIsFailClosed() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    fic::platform::OsReleaseValues values = compatibleValues(profile);
    std::string error;
    require(fic::platform::isHostCompatible(profile, values, error), error);

    values["ID"] = "another-distribution";
    require(!fic::platform::isHostCompatible(profile, values, error),
            "an incompatible os-release ID must be rejected");

    values = compatibleValues(profile);
    if (!profile.hostCompatibility.versionIds.empty()) {
        values["VERSION_ID"] = "unsupported-version";
        require(!fic::platform::isHostCompatible(profile, values, error),
                "an incompatible VERSION_ID must be rejected");
    }
    if (!profile.hostCompatibility.altBranchIds.empty()) {
        values["ALT_BRANCH_ID"] = "unsupported-branch";
        require(!fic::platform::isHostCompatible(profile, values, error),
                "an incompatible ALT_BRANCH_ID must be rejected");
    }
}

void testInvalidProfileIsRejected() {
    fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    profile.ssh.configPath = "etc/ssh/sshd_config";
    std::string error;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative SSH configuration path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    executableSpec(profile, fic::platform::ExecutableId::Sshd).candidates = {
        "usr/sbin/sshd"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative executable path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.executables.entries.push_back(profile.executables.entries.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate executable identifier must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.executables.entries.pop_back();
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a missing required executable must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sudo.managedConfigPath = "etc/sudoers.d/zzzz-fic";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative sudoers path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sysctl.managedConfigPath = "etc/sysctl.d/zzzz-fic.conf";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative sysctl managed path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sysctl.managedConfigPath = "/etc/sysctl.d/zzzz-fic";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a sysctl managed path without .conf suffix must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.displayManager.gdmConfigCandidates.clear();
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an empty GDM configuration path list must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.configDirectories.front() = "etc/pam.d";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM configuration directory must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.authenticationServices.push_back(
        profile.pam.authenticationServices.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate PAM service must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.passwordServices = {"../passwd"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an unsafe PAM service name must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.passwordHistoryConfigPath = "etc/security/pwhistory.conf";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM option file path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.grub.defaultsPath = "etc/default/grub";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative GRUB defaults path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.grub.rebuildArguments.push_back("unsafe\nargument");
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a GRUB generator argument containing a newline must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.protectedSystemFiles.front().permissions = 0;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "invalid DAC permissions must be rejected");
}

void testExecutableResolver() {
    std::string pattern = "/tmp/fic-platform-executables-XXXXXX";
    char* created = ::mkdtemp(pattern.data());
    require(created != nullptr, "cannot create temporary executable directory");
    const std::filesystem::path directory = created;

    try {
        const std::filesystem::path executable = directory / "sshd";
        std::ofstream stream(executable);
        stream << "#!/bin/sh\nexit 0\n";
        stream.close();
        require(::chmod(executable.c_str(), 0755) == 0,
                "cannot mark temporary command executable");

        fic::platform::PlatformExecutables registry;
        registry.entries = {{
            fic::platform::ExecutableId::Sshd,
            {directory / "missing", executable}
        }};
        fic::platform::PlatformExecutableResolverOptions resolverOptions;
        resolverOptions.enforceTrustedOwnership = false;
        fic::platform::PlatformExecutableResolver resolver(
            std::move(registry),
            resolverOptions);

        std::filesystem::path resolved;
        std::string error;
        require(resolver.resolve(
                    fic::platform::ExecutableId::Sshd, resolved, error),
                error);
        require(resolved == executable,
                "resolver did not select the first usable candidate");

        const std::filesystem::path replacement = directory / "missing";
        std::ofstream replacementStream(replacement);
        replacementStream << "#!/bin/sh\nexit 0\n";
        replacementStream.close();
        require(::chmod(replacement.c_str(), 0755) == 0,
                "cannot mark replacement command executable");
        std::filesystem::remove(executable);
        require(resolver.resolve(
                    fic::platform::ExecutableId::Sshd, resolved, error),
                error);
        require(resolved == replacement,
                "resolver must revalidate an invalidated cached candidate");

        std::ofstream restoredStream(executable);
        restoredStream << "#!/bin/sh\nexit 0\n";
        restoredStream.close();
        require(::chmod(executable.c_str(), 0755) == 0,
                "cannot restore temporary command");
        const std::filesystem::path symlink = directory / "sshd-link";
        std::filesystem::create_symlink(executable, symlink);
        fic::platform::PlatformExecutables symlinkRegistry;
        symlinkRegistry.entries = {{
            fic::platform::ExecutableId::Sshd,
            {symlink}
        }};
        fic::platform::PlatformExecutableResolver symlinkResolver(
            std::move(symlinkRegistry),
            resolverOptions);
        require(!symlinkResolver.resolve(
                    fic::platform::ExecutableId::Sshd, resolved, error),
                "resolver must reject a symbolic-link executable candidate");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        throw;
    }

    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

void testOsReleaseParsing() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    const fic::platform::OsReleaseValues expected = compatibleValues(profile);
    TemporaryOsRelease file;
    std::ofstream stream(file.path);
    stream << "NAME=\"Test Distribution\"\n";
    for (const auto& [key, value] : expected) {
        stream << key << "=\"" << value << "\"\n";
    }
    stream.close();

    fic::platform::OsReleaseValues parsed;
    std::string error;
    require(fic::platform::readOsRelease(file.path, parsed, error), error);
    require(parsed.at("NAME") == "Test Distribution",
            "quoted os-release value was not decoded");
    require(fic::platform::isHostCompatible(profile, parsed, error), error);
}

} // namespace

int main() {
    try {
        testSelectedProfile();
        testCompatibilityIsFailClosed();
        testInvalidProfileIsRejected();
        testExecutableResolver();
        testOsReleaseParsing();
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
