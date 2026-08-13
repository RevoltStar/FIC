#ifndef FIC_FIREWALL_POLICIES_H
#define FIC_FIREWALL_POLICIES_H

#include "modules/firewall/FirewallBackend.h"

#include <fic/policy/Policy.h>

#include <map>
#include <string>

namespace fic::firewall {

class CustomRulesPolicyTypeValue final : public PolicyTypeValue {
public:
    CustomRulesPolicyTypeValue();

    PolicyEditorSpec getEditorSpec() const override;
    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;
};

class FirewallPolicy : public Policy {
protected:
    FirewallPolicy(
        std::string policyName,
        const fic::platform::PlatformExecutableResolver& executables);

    bool applyRules(const std::vector<FirewallRule>& rules);
    const fic::platform::PlatformExecutableResolver& executables_;
};

class BlockRdpPolicy final : public FirewallPolicy {
public:
    explicit BlockRdpPolicy(
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
};

class BlockFtpPolicy final : public FirewallPolicy {
public:
    explicit BlockFtpPolicy(
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
};

class CustomRulesPolicy final : public FirewallPolicy {
public:
    explicit CustomRulesPolicy(
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
};

class ExclusiveFirewallControlPolicy final : public FirewallPolicy {
public:
    explicit ExclusiveFirewallControlPolicy(
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
};

bool buildFirewallDesiredState(const std::map<std::string, bool>& enabled,
                               const std::string& customRulesValue,
                               FirewallDesiredState& desired,
                               std::string& error);

bool reconcileFirewall(
    const fic::platform::PlatformExecutableResolver& executables,
    std::string& error);

} // namespace fic::firewall

#endif // FIC_FIREWALL_POLICIES_H
