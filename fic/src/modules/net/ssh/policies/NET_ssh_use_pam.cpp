#include "modules/net/ssh/policies/NET_ssh_use_pam.h"

NET_ssh_use_pam::NET_ssh_use_pam(
    const fic::platform::SshPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Ssh(platformConfig, executables) {
    sshParameter = "UsePAM";
    policyName = "ssh_use_pam";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("yes");
}

bool NET_ssh_use_pam::apply() {
    log("Starting SSH UsePAM check", logLevel::INFO);
    return Ssh::apply();
}
