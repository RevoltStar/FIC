#include "modules/net/submodules/ssh/NET_ssh_port.h"

NET_ssh_port::NET_ssh_port()
    : Ssh(){
    this->Ssh::sshParameter = "Port";
    this->policyName = "ssh_port";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 65535, 22);
}

NET_ssh_port::~NET_ssh_port() {
}

bool NET_ssh_port::check_and_fix() {
    this->log("Starting SSH port check", logLevel::INFO);
    return this->Ssh::check_and_fix();
}
