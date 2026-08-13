#include "modules/firewall/FirewallPolicies.h"

#include <fic/core/LocalizationManager.h>
#include <fic/core/Logger.h>
#include <fic/core/ModuleConfigFileHandler.h>

#include <iostream>
#include <utility>

namespace fic::firewall {
namespace {

class StatusOnlyPolicyTypeValue final : public FixedPolicyTypeValue {
public:
    bool validate(const std::string&) override {
        return false;
    }
};

FirewallRule blockedTcpPort(std::uint16_t port) {
    FirewallRule rule;
    rule.direction = Direction::Incoming;
    rule.protocol = Protocol::Tcp;
    rule.destinationPort.any = false;
    rule.destinationPort.first = port;
    rule.destinationPort.last = port;
    rule.action = Action::Block;
    return rule;
}

bool enabledValue(const std::map<std::string, bool>& enabled,
                  const std::string& policy) {
    const auto found = enabled.find(policy);
    return found != enabled.end() && found->second;
}

std::string chainLabel(const ForeignBaseChain& chain) {
    return chain.family + " " + chain.table + " " + chain.chain;
}

} // namespace

CustomRulesPolicyTypeValue::CustomRulesPolicyTypeValue() {
    this->defaultValue = "[]";
}

PolicyEditorSpec CustomRulesPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "textedit";
    return spec;
}

bool CustomRulesPolicyTypeValue::validate(const std::string& value) {
    std::vector<FirewallRule> rules;
    std::string normalized;
    std::string error;
    const bool valid = parseFirewallRules(value, rules, normalized, error);
    if (!valid) {
        std::cerr << "Invalid custom firewall rules: " << error << '\n';
    }
    return valid;
}

std::string CustomRulesPolicyTypeValue::postProcessingValue(
    const std::string& value) {
    std::vector<FirewallRule> rules;
    std::string normalized;
    std::string error;
    return parseFirewallRules(value, rules, normalized, error) ? normalized : "";
}

std::string CustomRulesPolicyTypeValue::reverse_postProcessingValue(
    const std::string& value) {
    return postProcessingValue(value);
}

std::string CustomRulesPolicyTypeValue::getPolicyRestrictionInfo() {
    return "JSON array: direction incoming|outgoing; protocol any|tcp|udp; "
           "source/destination any|IP|CIDR; source_port/destination_port "
           "any|integer|first-last; action allow|block";
}

FirewallPolicy::FirewallPolicy(
    std::string policy,
    const fic::platform::PlatformExecutableResolver& executables)
    : executables_(executables) {
    this->moduleName = "FIREWALL";
    this->submoduleName = "HostFiltering";
    this->policyName = std::move(policy);
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}

bool FirewallPolicy::applyRules(const std::vector<FirewallRule>& rules) {
    FirewallBackend backend(executables_);
    std::string error;
    if (!backend.applyPolicy(this->policyName, rules, error)) {
        this->log("Firewall policy apply failed: " + error, logLevel::ERROR);
        return false;
    }
    this->log("Firewall policy state applied: " + this->policyName, logLevel::INFO);
    return true;
}

BlockRdpPolicy::BlockRdpPolicy(
    const fic::platform::PlatformExecutableResolver& executables)
    : FirewallPolicy("block_rdp", executables) {
    this->policyTypeValue = std::make_unique<StatusOnlyPolicyTypeValue>();
}

bool BlockRdpPolicy::apply() {
    return applyRules({blockedTcpPort(3389)});
}

BlockFtpPolicy::BlockFtpPolicy(
    const fic::platform::PlatformExecutableResolver& executables)
    : FirewallPolicy("block_ftp", executables) {
    this->policyTypeValue = std::make_unique<StatusOnlyPolicyTypeValue>();
}

bool BlockFtpPolicy::apply() {
    return applyRules({blockedTcpPort(21)});
}

CustomRulesPolicy::CustomRulesPolicy(
    const fic::platform::PlatformExecutableResolver& executables)
    : FirewallPolicy("custom_rules", executables) {
    this->policyTypeValue = std::make_unique<CustomRulesPolicyTypeValue>();
}

bool CustomRulesPolicy::apply() {
    const std::optional<std::string> value = this->getValue();
    if (!value.has_value()) {
        return false;
    }
    std::vector<FirewallRule> rules;
    std::string normalized;
    std::string error;
    if (!parseFirewallRules(*value, rules, normalized, error)) {
        this->log("Invalid custom firewall rules: " + error, logLevel::ERROR);
        return false;
    }
    return applyRules(rules);
}

ExclusiveFirewallControlPolicy::ExclusiveFirewallControlPolicy(
    const fic::platform::PlatformExecutableResolver& executables)
    : FirewallPolicy("exclusive_firewall_control", executables) {
    this->policyTypeValue = std::make_unique<StatusOnlyPolicyTypeValue>();
}

bool ExclusiveFirewallControlPolicy::apply() {
    FirewallBackend backend(executables_);
    std::vector<ForeignBaseChain> neutralized;
    std::string error;
    if (!backend.applyExclusive(neutralized, error)) {
        this->log("Exclusive firewall control failed: " + error, logLevel::ERROR);
        return false;
    }
    for (const ForeignBaseChain& chain : neutralized) {
        this->log("Neutralized foreign host filtering chain: " +
                  chainLabel(chain), logLevel::WARN);
    }
    this->log("Exclusive firewall control applied", logLevel::INFO);
    return true;
}

bool buildFirewallDesiredState(const std::map<std::string, bool>& enabled,
                               const std::string& customRulesValue,
                               FirewallDesiredState& desired,
                               std::string& error) {
    desired = {};
    error.clear();
    if (enabledValue(enabled, "block_rdp")) {
        desired.policyRules["block_rdp"] = {blockedTcpPort(3389)};
    }
    if (enabledValue(enabled, "block_ftp")) {
        desired.policyRules["block_ftp"] = {blockedTcpPort(21)};
    }
    if (enabledValue(enabled, "custom_rules")) {
        std::vector<FirewallRule> rules;
        std::string normalized;
        if (!parseFirewallRules(customRulesValue, rules, normalized, error)) {
            return false;
        }
        if (!rules.empty()) {
            desired.policyRules["custom_rules"] = std::move(rules);
        }
    }
    desired.exclusive = enabledValue(enabled, "exclusive_firewall_control");
    return true;
}

bool reconcileFirewall(
    const fic::platform::PlatformExecutableResolver& executables,
    std::string& error) {
    ModuleConfigFileHandler config("FIREWALL");
    if (!config.loadConfig()) {
        error = "could not load FIREWALL.conf";
        Logger::log("Firewall reconciliation failed: " + error,
                    logLevel::ERROR, "daemon");
        return false;
    }

    std::map<std::string, bool> enabled;
    for (const std::string& policy : {
             "block_rdp", "block_ftp", "custom_rules",
             "exclusive_firewall_control"}) {
        enabled[policy] = config.getPolicyStatus(policy) == "ENABLE";
    }
    const std::string customRules = config.hasConfiguredValue("custom_rules")
        ? config.getPolicyValue("custom_rules") : "";
    FirewallDesiredState desired;
    if (!buildFirewallDesiredState(enabled, customRules, desired, error)) {
        Logger::log("Firewall reconciliation validation failed: " + error,
                    logLevel::ERROR, "daemon");
        return false;
    }

    FirewallBackend backend(executables);
    std::vector<ForeignBaseChain> neutralized;
    if (!backend.reconcile(desired, neutralized, error)) {
        Logger::log("Firewall reconciliation failed: " + error,
                    logLevel::ERROR, "daemon");
        return false;
    }
    for (const ForeignBaseChain& chain : neutralized) {
        Logger::log("Firewall reconciliation neutralized foreign chain: " +
                    chainLabel(chain), logLevel::WARN, "daemon");
    }
    Logger::log("Firewall reconciliation successful", logLevel::INFO, "daemon");
    return true;
}

} // namespace fic::firewall
