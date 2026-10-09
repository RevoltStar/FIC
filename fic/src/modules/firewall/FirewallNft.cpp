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
    if (table == "fic_incident_quarantine") return true;
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
        chain.table.rfind("fic_", 0) != 0;
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
            if (!item.is_object() || item.size() != 1) {
                error = "unsupported nft JSON entry";
                return false;
            }
            state.objects.push_back(item);
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


namespace {
using Json = nlohmann::json;
Json match(const Json& left, const Json& right) {
    return {{"match", {{"op", "=="}, {"left", left}, {"right", right}}}};
}
Json meta(const char* key) { return {{"meta", {{"key", key}}}}; }
Json payload(const char* protocol, const char* field) {
    return {{"payload", {{"protocol", protocol}, {"field", field}}}};
}
Json addressValue(const Address& address) {
    const auto slash = address.value.find('/');
    if (slash == std::string::npos) return address.value;
    const int length = std::stoi(address.value.substr(slash + 1));
    if (length == (address.family == AddressFamily::IPv4 ? 32 : 128))
        return address.value.substr(0, slash);
    return {{"prefix", {{"addr", address.value.substr(0, slash)},
                         {"len", std::stoi(address.value.substr(slash + 1))}}}};
}
Json portValue(const PortRange& port) {
    if (port.first == port.last) return port.first;
    return {{"range", Json::array({port.first, port.last})}};
}
Json expressions(const FirewallRule& rule, bool reply) {
    Json expr = Json::array();
    if (reply) {
        expr.push_back(match({{"ct", {{"key", "state"}}}}, "established"));
        expr.push_back(match({{"ct", {{"key", "direction"}}}}, "reply"));
    }
    const auto& source = reply ? rule.destination : rule.source;
    const auto& destination = reply ? rule.source : rule.destination;
    for (const auto& entry : {std::make_pair("saddr", source),
                              std::make_pair("daddr", destination)}) {
        if (entry.second.family != AddressFamily::Any)
            expr.push_back(match(payload(entry.second.family == AddressFamily::IPv4
                                    ? "ip" : "ip6", entry.first), addressValue(entry.second)));
    }
    if (rule.protocol != Protocol::Any) {
        const char* protocol = rule.protocol == Protocol::Tcp ? "tcp" : "udp";
        // Explicit protocol prevents interpreting non-TCP/UDP transport bytes.
        const auto& sport = reply ? rule.destinationPort : rule.sourcePort;
        const auto& dport = reply ? rule.sourcePort : rule.destinationPort;
        if (sport.any && dport.any) expr.push_back(match(meta("l4proto"), protocol));
        if (!sport.any) expr.push_back(match(payload(protocol, "sport"), portValue(sport)));
        if (!dport.any) expr.push_back(match(payload(protocol, "dport"), portValue(dport)));
    }
    expr.push_back({{rule.action == Action::Allow ? "accept" : "drop", nullptr}});
    return expr;
}
void appendChain(Json& objects, const std::string& table, const std::string& hook,
                 bool quarantine) {
    objects.push_back({{"chain", {{"family", "inet"}, {"table", table},
        {"name", hook}, {"type", "filter"}, {"hook", hook}, {"prio", 0},
        {"policy", quarantine ? "drop" : "accept"}}}});
}
void appendRule(Json& objects, const std::string& table, const std::string& chain,
                const Json& expr, const std::string& comment) {
    objects.push_back({{"rule", {{"family", "inet"}, {"table", table},
        {"chain", chain}, {"expr", expr}, {"comment", comment}}}});
}
}

nlohmann::json compileFirewallObjects(const FirewallDesiredState& desired) {
    Json objects = Json::array();
    if (desired.quarantine) {
        const std::string table = "fic_incident_quarantine";
        objects.push_back({{"table", {{"family", "inet"}, {"name", table}}}});
        for (const std::string hook : {"input", "output", "forward"})
            appendChain(objects, table, hook, true);
        appendRule(objects, table, "input", Json::array({match(meta("iifname"), "lo"),
                     {{"accept", nullptr}}}), "fic:quarantine:loopback:input");
        appendRule(objects, table, "output", Json::array({match(meta("oifname"), "lo"),
                     {{"accept", nullptr}}}), "fic:quarantine:loopback:output");
        const bool ipv6 = std::any_of(desired.exceptions.begin(), desired.exceptions.end(), [](const auto& rule) {
            return rule.source.family != AddressFamily::IPv4 && rule.destination.family != AddressFamily::IPv4;
        });
        if (ipv6) {
            // Link-local ND is necessary to reach an explicitly permitted IPv6
            // peer/gateway. No RA, DHCPv6, DNS or general ICMPv6 allowance.
            for (const std::string hook : {"input", "output"})
                for (const int type : {135, 136})
                    appendRule(objects, table, hook, Json::array({
                        match(payload("ip6", "hoplimit"), 255),
                        match(payload("icmpv6", "type"), type == 135 ? "nd-neighbor-solicit" : "nd-neighbor-advert"),
                        match(payload("icmpv6", "code"), "no-route"), {{"accept", nullptr}}}),
                        "fic:quarantine:nd:" + hook + ":" + std::to_string(type));
        }
        for (std::size_t i = 0; i < desired.exceptions.size(); ++i) {
            const auto& rule = desired.exceptions[i];
            const bool incoming = rule.direction == Direction::Incoming;
            appendRule(objects, table, incoming ? "input" : "output",
                       expressions(rule, false), "fic:quarantine:" + std::to_string(i));
            appendRule(objects, table, incoming ? "output" : "input",
                       expressions(rule, true), "fic:quarantine:reply:" + std::to_string(i));
        }
        return objects;
    }
    for (const auto& [policy, rules] : desired.policyRules) {
        if (rules.empty()) continue;
        const auto table = managedTableName(policy);
        objects.push_back({{"table", {{"family", "inet"}, {"name", table}}}});
        for (Direction direction : {Direction::Incoming, Direction::Outgoing}) {
            if (std::none_of(rules.begin(), rules.end(), [&](const auto& rule) {
                    return rule.direction == direction;
                })) continue;
            const std::string hook = direction == Direction::Incoming ? "input" : "output";
            appendChain(objects, table, hook, false);
        }
        for (std::size_t i = 0; i < rules.size(); ++i)
            appendRule(objects, table, rules[i].direction == Direction::Incoming ? "input" : "output",
                       expressions(rules[i], false), "fic:" + policy + ":" + std::to_string(i));
    }
    return objects;
}

bool observeManagedObjects(const Json& ruleset, std::map<std::string, Json>& tables,
                          std::string& error) {
    tables.clear();
    if (!ruleset.is_object() || !ruleset.contains("nftables") ||
        !ruleset.at("nftables").is_array()) {
        error = "nft JSON has no object array"; return false;
    }
    try {
        const std::set<std::string> kinds = {"metainfo", "table", "chain", "rule", "set", "map",
            "element", "flowtable", "counter", "quota", "ct helper", "limit", "ct timeout",
            "ct expectation"};
        std::map<std::string, Json> headers;
        std::map<std::string, std::set<std::string>> chains;
        for (const auto& item : ruleset.at("nftables")) {
            if (!item.is_object() || item.size() != 1 || !kinds.count(item.begin().key()) ||
                !item.begin().value().is_object()) {
                error = "unsupported nft JSON object"; return false;
            }
            const auto kind = item.begin().key();
            auto object = item.begin().value();
            if (kind == "metainfo") {
                if (object.at("json_schema_version") != 1) {
                    error = "unsupported nft JSON schema"; return false;
                }
                continue;
            }
            const std::string family = object.at("family").get<std::string>();
            const std::string table = object.at(kind == "table" ? "name" : "table").get<std::string>();
            if (!isManagedTable(family, table) && table.rfind("fic_", 0) != 0) continue;
            if (family != "inet" || (kind != "table" && kind != "chain" && kind != "rule")) {
                error = "unsupported object in reserved FIC table: " + table; return false;
            }
            object.erase("handle");
            // No other fields are erased: unexpected flags/devices/expressions fail proof.
            if (kind == "table") {
                if (headers.count(table)) { error = "duplicate nft table"; return false; }
                headers[table] = {{"table", object}};
                tables[table] = Json::array();
            } else {
                if (!headers.count(table)) { error = "orphan nft object"; return false; }
                if (kind == "chain") {
                    const auto name = object.at("name").get<std::string>();
                    if (!chains[table].insert(name).second) { error = "duplicate nft chain"; return false; }
                    object.at("type").get<std::string>(); object.at("hook").get<std::string>();
                    object.at("prio").get<int>(); object.at("policy").get<std::string>();
                } else {
                    if (!chains[table].count(object.at("chain").get<std::string>()) ||
                        !object.at("expr").is_array() || object.at("expr").empty()) {
                        error = "orphan or malformed nft rule"; return false;
                    }
                }
                tables[table].push_back({{kind, object}});
            }
        }
        for (auto& [table, objects] : tables) {
            // Kernel lists chains followed by their rules. Canonical order is
            // table, sorted chains, then rules grouped by chain (rule order retained).
            Json canonical = Json::array({headers.at(table)});
            for (const auto& chain : chains[table])
                for (const auto& item : objects)
                    if (item.contains("chain") && item.at("chain").at("name") == chain)
                        canonical.push_back(item);
            for (const auto& chain : chains[table])
                for (const auto& item : objects)
                    if (item.contains("rule") && item.at("rule").at("chain") == chain)
                        canonical.push_back(item);
            objects = std::move(canonical);
        }
        error.clear(); return true;
    } catch (const Json::exception& ex) {
        error = std::string("unproven nft objects: ") + ex.what(); return false;
    }
}

} // namespace fic::firewall
