#include "modules/firewall/FirewallNft.h"
#include "modules/firewall/FirewallPolicies.h"

#include <fic/core/ProcessExecutor.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <map>
#include <string>
#include <vector>

using fic::firewall::Action;
using fic::firewall::AddressFamily;
using fic::firewall::Direction;
using fic::firewall::FirewallActualState;
using fic::firewall::FirewallDesiredState;
using fic::firewall::FirewallRule;
using fic::firewall::ForeignBaseChain;
using fic::firewall::Protocol;

namespace {

std::string ruleJson(const std::string& direction = "incoming",
                     const std::string& protocol = "tcp",
                     const std::string& source = "any",
                     const std::string& destination = "any",
                     const std::string& sourcePort = "\"any\"",
                     const std::string& destinationPort = "22",
                     const std::string& action = "allow") {
    return "[{\"direction\":\"" + direction +
        "\",\"protocol\":\"" + protocol +
        "\",\"source\":\"" + source +
        "\",\"destination\":\"" + destination +
        "\",\"source_port\":" + sourcePort +
        ",\"destination_port\":" + destinationPort +
        ",\"action\":\"" + action + "\"}]";
}

bool parse(const std::string& value,
           std::vector<FirewallRule>& rules,
           std::string* normalizedOutput = nullptr) {
    std::string normalized;
    std::string error;
    const bool result = fic::firewall::parseFirewallRules(
        value, rules, normalized, error);
    if (normalizedOutput != nullptr) {
        *normalizedOutput = normalized;
    }
    return result;
}

void testJsonValidationAndNormalization() {
    std::vector<FirewallRule> rules;
    std::string normalized;
    assert(parse(ruleJson(), rules, &normalized));
    assert(rules.size() == 1);
    assert(rules[0].direction == Direction::Incoming);
    assert(rules[0].protocol == Protocol::Tcp);
    assert(rules[0].action == Action::Allow);
    assert(normalized ==
        "[{\"action\":\"allow\",\"destination\":\"any\","
        "\"destination_port\":22,\"direction\":\"incoming\","
        "\"protocol\":\"tcp\",\"source\":\"any\","
        "\"source_port\":\"any\"}]");

    assert(!parse("{}", rules));
    assert(!parse("not json", rules));
    assert(!parse(ruleJson("sideways"), rules));
    assert(!parse(ruleJson("incoming", "icmp"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "any", "any",
                           "\"any\"", "22", "reject"), rules));
    assert(!parse(
        "[{\"direction\":\"incoming\",\"protocol\":\"tcp\","
        "\"source\":\"any\",\"destination\":\"any\","
        "\"source_port\":\"any\",\"destination_port\":22,"
        "\"action\":\"allow\",\"priority\":1}]", rules));
}

void testAddresses() {
    std::vector<FirewallRule> rules;
    assert(parse(ruleJson("incoming", "tcp", "192.168.1.10"), rules));
    assert(rules[0].source.family == AddressFamily::IPv4);
    assert(parse(ruleJson("incoming", "tcp", "192.168.1.0/24"), rules));
    assert(rules[0].source.value == "192.168.1.0/24");
    assert(parse(ruleJson("outgoing", "udp", "2001:0db8::1"), rules));
    assert(rules[0].source.family == AddressFamily::IPv6);
    assert(rules[0].source.value == "2001:db8::1");
    assert(parse(ruleJson("outgoing", "udp", "2001:db8::/64"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "999.1.1.1"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "192.0.2.1/33"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "2001:db8::/129"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "192.0.2.1", "2001:db8::1"), rules));
}

void testPorts() {
    std::vector<FirewallRule> rules;
    assert(parse(ruleJson("incoming", "tcp", "any", "any", "53", "443"), rules));
    assert(rules[0].sourcePort.first == 53 && rules[0].sourcePort.last == 53);
    assert(parse(ruleJson("incoming", "udp", "any", "any",
                          "\"1000-2000\"", "\"any\""), rules));
    assert(rules[0].sourcePort.first == 1000 && rules[0].sourcePort.last == 2000);
    assert(!parse(ruleJson("incoming", "tcp", "any", "any", "0", "22"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "any", "any", "65536", "22"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "any", "any",
                           "\"2000-1000\"", "22"), rules));
    assert(!parse(ruleJson("incoming", "tcp", "any", "any",
                           "\"22\"", "22"), rules));
    assert(!parse(ruleJson("incoming", "any", "any", "any", "53", "22"), rules));
}

void testNftRendering() {
    std::vector<FirewallRule> rules;
    assert(parse(ruleJson("incoming", "tcp", "192.168.1.0/24", "any",
                          "\"1000-2000\"", "3389", "block"), rules));
    const std::string rendered = fic::firewall::renderNftRule(rules[0], "fic:test:0");
    assert(rendered ==
        "ip saddr 192.168.1.0/24 tcp sport 1000-2000 tcp dport 3389 "
        "drop comment \"fic:test:0\"");

    assert(parse(ruleJson("outgoing", "udp", "any", "2001:db8::1",
                          "\"any\"", "53", "allow"), rules));
    assert(fic::firewall::renderNftRule(rules[0], "fic:test:1") ==
        "ip6 daddr 2001:db8::1 udp dport 53 accept comment \"fic:test:1\"");

    const std::string table = fic::firewall::renderManagedTable("custom_rules", rules);
    assert(table.find("table inet fic_custom_rules") != std::string::npos);
    assert(table.find("type filter hook output priority 0; policy accept;") !=
           std::string::npos);
    assert(table.find("hook input") == std::string::npos);
}

void testDesiredState() {
    FirewallDesiredState desired;
    std::string error;
    assert(fic::firewall::buildFirewallDesiredState(
        {{"block_rdp", true}}, "", desired, error));
    assert(desired.policyRules.count("block_rdp") == 1);
    assert(desired.policyRules["block_rdp"][0].destinationPort.first == 3389);

    assert(fic::firewall::buildFirewallDesiredState(
        {{"block_rdp", false}, {"block_ftp", true}}, "", desired, error));
    assert(desired.policyRules.count("block_rdp") == 0);
    assert(desired.policyRules["block_ftp"][0].destinationPort.first == 21);
    assert(desired.policyRules["block_ftp"][0].action == Action::Block);

    assert(fic::firewall::buildFirewallDesiredState(
        {{"custom_rules", false}}, "invalid but ignored", desired, error));
    assert(desired.policyRules.count("custom_rules") == 0);
    assert(fic::firewall::buildFirewallDesiredState(
        {{"custom_rules", true}}, ruleJson(), desired, error));
    assert(desired.policyRules.count("custom_rules") == 1);
}

void testActualStateAndReconciliationScript() {
    const nlohmann::json actualJson = {
        {"nftables", nlohmann::json::array({
            {{"metainfo", {{"json_schema_version", 1}}}},
            {{"table", {{"family", "inet"}, {"name", "fic_block_rdp"}}}},
            {{"table", {{"family", "inet"}, {"name", "foreign"}}}},
            {{"chain", {{"family", "inet"}, {"table", "foreign"},
                         {"name", "host_input"}, {"type", "filter"},
                         {"hook", "input"}, {"prio", 0}, {"policy", "accept"}}}},
            {{"rule", {{"family", "inet"}, {"table", "foreign"},
                        {"chain", "host_input"}, {"expr", nlohmann::json::array()}}}},
            {{"chain", {{"family", "ip"}, {"table", "foreign"},
                         {"name", "route_output"}, {"type", "route"},
                         {"hook", "output"}, {"prio", -150}, {"policy", "drop"}}}},
            {{"chain", {{"family", "ip"}, {"table", "foreign"},
                         {"name", "forward"}, {"type", "filter"},
                         {"hook", "forward"}, {"prio", 0}, {"policy", "drop"}}}},
            {{"chain", {{"family", "ip"}, {"table", "foreign"},
                         {"name", "nat_output"}, {"type", "nat"},
                         {"hook", "output"}, {"prio", -100}, {"policy", "accept"}}}},
            {{"chain", {{"family", "bridge"}, {"table", "foreign"},
                         {"name", "bridge_input"}, {"type", "filter"},
                         {"hook", "input"}, {"prio", 0}, {"policy", "drop"}}}}
        })}
    };
    FirewallActualState actual;
    std::string error;
    assert(fic::firewall::parseNftActualState(actualJson, actual, error));
    assert(actual.managedInetTables.count("fic_block_rdp") == 1);
    assert(actual.foreignHostFilterChains.size() == 2);

    FirewallDesiredState desired;
    desired.policyRules["block_ftp"] = [] {
        FirewallRule rule;
        rule.protocol = Protocol::Tcp;
        rule.destinationPort.any = false;
        rule.destinationPort.first = 21;
        rule.destinationPort.last = 21;
        rule.action = Action::Block;
        return std::vector<FirewallRule>{rule};
    }();
    desired.exclusive = true;
    std::vector<ForeignBaseChain> neutralized;
    const std::string script = fic::firewall::buildReconciliationScript(
        desired, actual, neutralized);
    assert(script.find("delete table inet fic_block_rdp") != std::string::npos);
    assert(script.find("table inet fic_block_ftp") != std::string::npos);
    assert(script.find("flush chain inet \"foreign\" \"host_input\"") !=
           std::string::npos);
    assert(script.find("add chain ip \"foreign\" \"route_output\" { type route "
                       "hook output priority -150; policy accept; }") !=
           std::string::npos);
    assert(script.find("forward") == std::string::npos);
    assert(script.find("nat_output") == std::string::npos);
    assert(script.find("bridge_input") == std::string::npos);
    assert(neutralized.size() == 2);

    desired = {};
    neutralized.clear();
    const std::string staleRemoval = fic::firewall::buildReconciliationScript(
        desired, actual, neutralized);
    assert(staleRemoval == "delete table inet fic_block_rdp\n");
}

void testProcessStandardInput() {
    ProcessOptions options;
    options.standardInput = std::string(128U * 1024U, 'x');
    const ProcessResult result = ProcessExecutor::execute("/bin/cat", {}, options);
    assert(result.success());
    assert(result.standardOutput == *options.standardInput);
}

} // namespace

int main() {
    testJsonValidationAndNormalization();
    testAddresses();
    testPorts();
    testNftRendering();
    testDesiredState();
    testActualStateAndReconciliationScript();
    testProcessStandardInput();
    return 0;
}
