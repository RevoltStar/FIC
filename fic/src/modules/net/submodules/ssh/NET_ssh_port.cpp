#include "modules/net/submodules/ssh/NET_ssh_port.h"

NET_ssh_port::NET_ssh_port(
    const fic::platform::SshPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Ssh(platformConfig, executables) {
    this->Ssh::sshParameter = "Port";
    this->policyName = "ssh_port";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 65535, 22);
}

NET_ssh_port::~NET_ssh_port() {
}

bool NET_ssh_port::apply() {
    this->log("Starting SSH port check", logLevel::INFO);
    return this->Ssh::apply();
}
