#ifndef FIC_FIREWALL_NFT_H
#define FIC_FIREWALL_NFT_H

#include "modules/firewall/FirewallRule.h"

#include <map>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fic::firewall {

struct ForeignBaseChain {
    std::string family;
    std::string table;
    std::string chain;
    std::string type;
    std::string hook;
    int priority = 0;
    std::string policy = "accept";
};

struct FirewallActualState {
    std::set<std::string> managedInetTables;
    std::map<std::string, std::set<std::string>> managedRuleComments;
    std::vector<ForeignBaseChain> foreignHostFilterChains;
};

struct FirewallDesiredState {
    std::map<std::string, std::vector<FirewallRule>> policyRules;
    bool exclusive = false;
};

const std::vector<std::string>& managedFirewallPolicies();
std::string managedTableName(const std::string& policyName);
std::string renderNftRule(const FirewallRule& rule,
                          const std::string& comment);
std::string renderManagedTable(const std::string& policyName,
                               const std::vector<FirewallRule>& rules);

bool parseNftActualState(const nlohmann::json& ruleset,
                         FirewallActualState& state,
                         std::string& error);

std::string buildPolicyScript(const std::string& policyName,
                              const std::vector<FirewallRule>& rules,
                              const FirewallActualState& actual);

std::string buildReconciliationScript(const FirewallDesiredState& desired,
                                      const FirewallActualState& actual,
                                      std::vector<ForeignBaseChain>& neutralized);

} // namespace fic::firewall

#endif // FIC_FIREWALL_NFT_H
