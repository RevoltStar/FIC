#include "modules/net/submodules/ssh/NET_ssh_pubkey_auth.h"

NET_ssh_pubkey_auth::NET_ssh_pubkey_auth()
    : Ssh(){
    this->Ssh::sshParameter = "PubkeyAuthentication";
    this->policyName = "ssh_pubkey_auth";
    this->policyTypeValue = std::make_unique<EnableDisablePolicyTypeValue>();
}

NET_ssh_pubkey_auth::~NET_ssh_pubkey_auth() {
}

bool NET_ssh_pubkey_auth::check_and_fix() {
    this->log("Starting SSH PubkeyAuthentication check", logLevel::INFO);
    return this->Ssh::check_and_fix();
}
