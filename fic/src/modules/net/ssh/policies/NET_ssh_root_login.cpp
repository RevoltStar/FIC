#include "modules/net/ssh/policies/NET_ssh_root_login.h"

NET_ssh_root_login::NET_ssh_root_login(
    const fic::platform::SshPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Ssh(platformConfig, executables) {
    this->Ssh::sshParameter = "PermitRootLogin";
    this->policyName = "ssh_root_login";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"no", "prohibit-password", "forced-commands-only"}
    );
}

NET_ssh_root_login::~NET_ssh_root_login() {
}

bool NET_ssh_root_login::apply() {
    this->log("Starting SSH PermitRootLogin check", logLevel::INFO);
    return this->Ssh::apply();
}
