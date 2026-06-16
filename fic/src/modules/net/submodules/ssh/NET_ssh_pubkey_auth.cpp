#include "modules/net/submodules/ssh/NET_ssh_pubkey_auth.h"

NET_ssh_pubkey_auth::NET_ssh_pubkey_auth()
    : Ssh(){
    this->Ssh::sshParameter = "PubkeyAuthentication";
    this->policyName = "ssh_pubkey_auth";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

NET_ssh_pubkey_auth::~NET_ssh_pubkey_auth() {
}

bool NET_ssh_pubkey_auth::apply() {
    this->log("Starting SSH PubkeyAuthentication check", logLevel::INFO);
    return this->Ssh::apply();
}
