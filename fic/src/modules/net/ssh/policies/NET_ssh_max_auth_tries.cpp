#include "modules/net/ssh/policies/NET_ssh_max_auth_tries.h"

NET_ssh_max_auth_tries::NET_ssh_max_auth_tries(
    const fic::platform::SshPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Ssh(platformConfig, executables) {
    this->Ssh::sshParameter = "MaxAuthTries";
    this->policyName = "ssh_max_auth_tries";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 5, 3);
}

NET_ssh_max_auth_tries::~NET_ssh_max_auth_tries() {
}

bool NET_ssh_max_auth_tries::apply() {
    this->log("Starting SSH MaxAuthTries check", logLevel::INFO);
    return this->Ssh::apply();
}
