#include "modules/net/submodules/ssh/NET_ssh_pubkey_auth.h"

NET_ssh_pubkey_auth::NET_ssh_pubkey_auth(
    const fic::platform::SshPlatformConfig& platformConfig,
    const fic::platform::SystemToolsPlatformConfig& systemTools)
    : Ssh(platformConfig, systemTools) {
    this->Ssh::sshParameter = "PubkeyAuthentication";
    this->policyName = "ssh_pubkey_auth";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>("yes");
}

NET_ssh_pubkey_auth::~NET_ssh_pubkey_auth() {
}

bool NET_ssh_pubkey_auth::apply() {
    this->log("Starting SSH PubkeyAuthentication check", logLevel::INFO);
    return this->Ssh::apply();
}
