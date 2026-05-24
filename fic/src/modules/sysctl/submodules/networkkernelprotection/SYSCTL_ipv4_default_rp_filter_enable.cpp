#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv4_default_rp_filter_enable.h"

SYSCTL_ipv4_default_rp_filter_enable::SYSCTL_ipv4_default_rp_filter_enable()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.conf.default.rp_filter";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "ipv4_default_rp_filter_enable";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"1", "0", "2"});
}

bool SYSCTL_ipv4_default_rp_filter_enable::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
