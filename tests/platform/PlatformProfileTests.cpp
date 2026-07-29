#include "platform/PlatformCompatibility.h"
#include "platform/PlatformProfile.h"

#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>

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

void testSelectedProfile() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    std::string error;
    require(fic::platform::validatePlatformProfile(profile, error), error);
    require(profile.sudo.mainConfigPath == "/etc/sudoers",
            "sudoers main configuration path is incorrect");
    require(profile.sudo.managedConfigPath == "/etc/sudoers.d/zzzz-fic",
            "managed sudoers path is incorrect");
    require(profile.sudo.visudoCandidates ==
                std::vector<std::string>({"/usr/sbin/visudo"}),
            "visudo candidates are incorrect");
    require(profile.displayManager.sddmConfigPath == "/etc/sddm.conf",
            "SDDM configuration path is incorrect");
    require(profile.displayManager.lightDmConfigPath ==
                "/etc/lightdm/lightdm.conf",
            "LightDM configuration path is incorrect");
    require(hasRule(profile.dac.protectedSystemFiles,
                    profile.sudo.mainConfigPath),
            "the selected sudoers configuration must be protected by DAC policy");

    if (profile.id == "alt-p11") {
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
    } else if (profile.id == "debian-12") {
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
    } else if (profile.id == "ubuntu-24.04") {
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Ubuntu 24.04 SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/custom.conf",
                "Ubuntu 24.04 primary GDM configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Ubuntu 24.04 must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/bin/df"),
                "Ubuntu 24.04 df command path is incorrect");
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
    profile.ssh.sshdCandidates = {"usr/sbin/sshd"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative executable path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sudo.managedConfigPath = "etc/sudoers.d/zzzz-fic";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative sudoers path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.displayManager.gdmConfigCandidates.clear();
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an empty GDM configuration path list must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.protectedSystemFiles.front().permissions = 0;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "invalid DAC permissions must be rejected");
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
        testOsReleaseParsing();
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
