#include "modules/firewall/FirewallNft.h"

#include <algorithm>
#include <sstream>
#include <tuple>

namespace fic::firewall {
namespace {

const std::vector<std::string> MANAGED_POLICIES = {
    "block_rdp", "block_ftp", "custom_rules"
};

std::string quoteIdentifier(const std::string& value) {
    std::string quoted = "\"";
    for (const char ch : value) {
        if (ch == '\\' || ch == '"') {
            quoted.push_back('\\');
        }
        quoted.push_back(ch);
    }
    quoted.push_back('"');
    return quoted;
}

std::string portExpression(const PortRange& port) {
    if (port.first == port.last) {
        return std::to_string(port.first);
    }
    return std::to_string(port.first) + "-" + std::to_string(port.last);
}

void appendAddress(std::ostringstream& output,
                   const char* field,
                   const Address& address) {
    if (address.family == AddressFamily::Any) {
        return;
    }
    output << (address.family == AddressFamily::IPv4 ? "ip " : "ip6 ")
           << field << ' ' << address.value << ' ';
}

bool isManagedTable(const std::string& family, const std::string& table) {
    if (family != "inet") {
        return false;
    }
    return std::any_of(MANAGED_POLICIES.begin(), MANAGED_POLICIES.end(),
        [&](const std::string& policy) {
            return managedTableName(policy) == table;
        });
}

bool eligibleForeignChain(const ForeignBaseChain& chain) {
    const bool supportedFamily = chain.family == "inet" ||
        chain.family == "ip" || chain.family == "ip6";
    const bool hostHook = chain.hook == "input" || chain.hook == "output";
    const bool filterType = chain.type == "filter" || chain.type == "route";
    return supportedFamily && hostHook && filterType &&
        !isManagedTable(chain.family, chain.table);
}

} // namespace

const std::vector<std::string>& managedFirewallPolicies() {
    return MANAGED_POLICIES;
}

std::string managedTableName(const std::string& policyName) {
    return "fic_" + policyName;
}

std::string renderNftRule(const FirewallRule& rule,
                          const std::string& comment) {
    std::ostringstream output;
    appendAddress(output, "saddr", rule.source);
    appendAddress(output, "daddr", rule.destination);
    if (rule.protocol != Protocol::Any) {
        const char* protocol = rule.protocol == Protocol::Tcp ? "tcp" : "udp";
        if (rule.sourcePort.any && rule.destinationPort.any) {
            output << "meta l4proto " << protocol << ' ';
        } else {
            if (!rule.sourcePort.any) {
                output << protocol << " sport " << portExpression(rule.sourcePort) << ' ';
            }
            if (!rule.destinationPort.any) {
                output << protocol << " dport " << portExpression(rule.destinationPort) << ' ';
            }
        }
    }
    output << (rule.action == Action::Allow ? "accept" : "drop")
           << " comment " << quoteIdentifier(comment);
    return output.str();
}

std::string renderManagedTable(const std::string& policyName,
                               const std::vector<FirewallRule>& rules) {
    if (rules.empty()) {
        return "";
    }
    std::ostringstream output;
    output << "table inet " << managedTableName(policyName) << " {\n";
    for (const Direction direction : {Direction::Incoming, Direction::Outgoing}) {
        const bool hasDirection = std::any_of(rules.begin(), rules.end(),
            [&](const FirewallRule& rule) { return rule.direction == direction; });
        if (!hasDirection) {
            continue;
        }
        const char* chain = direction == Direction::Incoming ? "input" : "output";
        output << "  chain " << chain << " {\n"
               << "    type filter hook " << chain
               << " priority 0; policy accept;\n";
        for (std::size_t index = 0; index < rules.size(); ++index) {
            if (rules[index].direction != direction) {
                continue;
            }
            output << "    " << renderNftRule(
                rules[index], "fic:" + policyName + ":" + std::to_string(index))
                   << "\n";
        }
        output << "  }\n";
    }
    output << "}\n";
    return output.str();
}

bool parseNftActualState(const nlohmann::json& ruleset,
                         FirewallActualState& state,
                         std::string& error) {
    state = {};
    error.clear();
    if (!ruleset.is_object() || !ruleset.contains("nftables") ||
        !ruleset.at("nftables").is_array()) {
        error = "nft JSON response has no nftables array";
        return false;
    }
    try {
        std::vector<ForeignBaseChain> candidates;
        std::set<std::tuple<std::string, std::string, std::string>> chainsWithRules;
        for (const nlohmann::json& item : ruleset.at("nftables")) {
            if (!item.is_object()) {
                continue;
            }
            if (item.contains("table") && item.at("table").is_object()) {
                const nlohmann::json& table = item.at("table");
                const std::string family = table.at("family").get<std::string>();
                const std::string name = table.at("name").get<std::string>();
                if (isManagedTable(family, name)) {
                    state.managedInetTables.insert(name);
                }
            }
            if (item.contains("chain") && item.at("chain").is_object()) {
                const nlohmann::json& chain = item.at("chain");
                if (!chain.contains("type") || !chain.contains("hook")) {
                    continue;
                }
                ForeignBaseChain candidate {
                    chain.at("family").get<std::string>(),
                    chain.at("table").get<std::string>(),
                    chain.at("name").get<std::string>(),
                    chain.at("type").get<std::string>(),
                    chain.at("hook").get<std::string>(),
                    chain.at("prio").get<int>(),
                    chain.value("policy", "accept")
                };
                if (eligibleForeignChain(candidate)) {
                    candidates.push_back(std::move(candidate));
                }
            }
            if (item.contains("rule") && item.at("rule").is_object()) {
                const nlohmann::json& rule = item.at("rule");
                const std::string family = rule.at("family").get<std::string>();
                const std::string table = rule.at("table").get<std::string>();
                const std::string chain = rule.at("chain").get<std::string>();
                chainsWithRules.emplace(family, table, chain);
                if (isManagedTable(family, table) && rule.contains("comment") &&
                    rule.at("comment").is_string()) {
                    state.managedRuleComments[table].insert(
                        rule.at("comment").get<std::string>());
                }
            }
        }
        for (ForeignBaseChain& candidate : candidates) {
            const auto key = std::make_tuple(
                candidate.family, candidate.table, candidate.chain);
            if (candidate.policy == "drop" || chainsWithRules.count(key) != 0) {
                state.foreignHostFilterChains.push_back(std::move(candidate));
            }
        }
    } catch (const nlohmann::json::exception& exception) {
        error = std::string("invalid nft JSON response: ") + exception.what();
        state = {};
        return false;
    }
    return true;
}

std::string buildPolicyScript(const std::string& policyName,
                              const std::vector<FirewallRule>& rules,
                              const FirewallActualState& actual) {
    std::ostringstream output;
    const std::string table = managedTableName(policyName);
    if (actual.managedInetTables.count(table) != 0) {
        output << "delete table inet " << table << "\n";
    }
    output << renderManagedTable(policyName, rules);
    return output.str();
}

std::string buildReconciliationScript(const FirewallDesiredState& desired,
                                      const FirewallActualState& actual,
                                      std::vector<ForeignBaseChain>& neutralized) {
    neutralized.clear();
    std::ostringstream output;
    if (desired.exclusive) {
        for (const ForeignBaseChain& chain : actual.foreignHostFilterChains) {
            output << "flush chain " << chain.family << ' '
                   << quoteIdentifier(chain.table) << ' '
                   << quoteIdentifier(chain.chain) << "\n";
            output << "delete chain " << chain.family << ' '
                   << quoteIdentifier(chain.table) << ' '
                   << quoteIdentifier(chain.chain) << "\n";
            output << "add chain " << chain.family << ' '
                   << quoteIdentifier(chain.table) << ' '
                   << quoteIdentifier(chain.chain) << " { type "
                   << chain.type << " hook " << chain.hook
                   << " priority " << chain.priority
                   << "; policy accept; }\n";
            neutralized.push_back(chain);
        }
    }
    for (const std::string& table : actual.managedInetTables) {
        output << "delete table inet " << table << "\n";
    }
    for (const std::string& policy : MANAGED_POLICIES) {
        const auto found = desired.policyRules.find(policy);
        if (found != desired.policyRules.end()) {
            output << renderManagedTable(policy, found->second);
        }
    }
    return output.str();
}

} // namespace fic::firewall
