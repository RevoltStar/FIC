#include "modules/firewall/FirewallRule.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <set>
#include <sstream>

namespace fic::firewall {
namespace {

constexpr std::array<const char*, 7> REQUIRED_FIELDS = {
    "direction", "protocol", "source", "destination",
    "source_port", "destination_port", "action"
};

bool parseEnum(const nlohmann::json& value,
               const std::string& field,
               const std::set<std::string>& accepted,
               std::string& parsed,
               std::string& error) {
    if (!value.is_string()) {
        error = field + " must be a string";
        return false;
    }
    parsed = value.get<std::string>();
    if (accepted.count(parsed) == 0) {
        error = "unsupported " + field + ": " + parsed;
        return false;
    }
    return true;
}

bool parseUnsignedDecimal(const std::string& value,
                          unsigned int& parsed) {
    if (value.empty() || !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        })) {
        return false;
    }
    try {
        std::size_t consumed = 0;
        const unsigned long number = std::stoul(value, &consumed, 10);
        if (consumed != value.size() ||
            number > std::numeric_limits<unsigned int>::max()) {
            return false;
        }
        parsed = static_cast<unsigned int>(number);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool parsePortNumber(const nlohmann::json& value,
                     unsigned int& port) {
    if (!value.is_number_integer()) {
        return false;
    }
    long long number = 0;
    try {
        number = value.get<long long>();
    } catch (const nlohmann::json::exception&) {
        return false;
    }
    if (number < 1 || number > 65535) {
        return false;
    }
    port = static_cast<unsigned int>(number);
    return true;
}

bool parsePort(const nlohmann::json& value,
               const std::string& field,
               PortRange& port,
               std::string& error) {
    if (value.is_string()) {
        const std::string text = value.get<std::string>();
        if (text == "any") {
            port = {};
            return true;
        }
        const std::size_t separator = text.find('-');
        if (separator == std::string::npos || separator == 0 ||
            separator + 1 >= text.size() ||
            text.find('-', separator + 1) != std::string::npos) {
            error = field + " must be any, an integer, or a range like 1000-2000";
            return false;
        }
        unsigned int first = 0;
        unsigned int last = 0;
        if (!parseUnsignedDecimal(text.substr(0, separator), first) ||
            !parseUnsignedDecimal(text.substr(separator + 1), last) ||
            first < 1 || last > 65535 || first >= last) {
            error = field + " range must be ordered and inside 1..65535";
            return false;
        }
        port.any = false;
        port.first = static_cast<std::uint16_t>(first);
        port.last = static_cast<std::uint16_t>(last);
        return true;
    }

    unsigned int single = 0;
    if (!parsePortNumber(value, single)) {
        error = field + " port must be inside 1..65535";
        return false;
    }
    port.any = false;
    port.first = static_cast<std::uint16_t>(single);
    port.last = static_cast<std::uint16_t>(single);
    return true;
}

bool parseAddress(const nlohmann::json& value,
                  const std::string& field,
                  Address& address,
                  std::string& error) {
    if (!value.is_string()) {
        error = field + " must be a string";
        return false;
    }
    const std::string text = value.get<std::string>();
    if (text == "any") {
        address = {};
        return true;
    }

    std::string ip = text;
    std::string prefixText;
    const std::size_t slash = text.find('/');
    if (slash != std::string::npos) {
        if (slash == 0 || slash + 1 >= text.size() ||
            text.find('/', slash + 1) != std::string::npos) {
            error = "invalid " + field + " CIDR: " + text;
            return false;
        }
        ip = text.substr(0, slash);
        prefixText = text.substr(slash + 1);
    }

    std::array<unsigned char, 16> binary {};
    int family = AF_UNSPEC;
    unsigned int maxPrefix = 0;
    if (::inet_pton(AF_INET, ip.c_str(), binary.data()) == 1) {
        family = AF_INET;
        maxPrefix = 32;
        address.family = AddressFamily::IPv4;
    } else if (::inet_pton(AF_INET6, ip.c_str(), binary.data()) == 1) {
        family = AF_INET6;
        maxPrefix = 128;
        address.family = AddressFamily::IPv6;
    } else {
        error = "invalid " + field + " IP address: " + text;
        return false;
    }

    unsigned int prefix = maxPrefix;
    if (!prefixText.empty() &&
        (!parseUnsignedDecimal(prefixText, prefix) || prefix > maxPrefix)) {
        error = "invalid " + field + " CIDR prefix: " + text;
        return false;
    }

    std::array<char, INET6_ADDRSTRLEN> canonical {};
    if (::inet_ntop(family, binary.data(), canonical.data(), canonical.size()) == nullptr) {
        error = "could not normalize " + field + " address";
        return false;
    }
    address.value = canonical.data();
    if (slash != std::string::npos) {
        address.value += "/" + std::to_string(prefix);
    }
    return true;
}

nlohmann::json portToJson(const PortRange& port) {
    if (port.any) {
        return "any";
    }
    if (port.first == port.last) {
        return port.first;
    }
    return std::to_string(port.first) + "-" + std::to_string(port.last);
}

const char* directionName(Direction direction) {
    return direction == Direction::Incoming ? "incoming" : "outgoing";
}

const char* protocolName(Protocol protocol) {
    switch (protocol) {
    case Protocol::Any:
        return "any";
    case Protocol::Tcp:
        return "tcp";
    case Protocol::Udp:
        return "udp";
    }
    return "any";
}

const char* actionName(Action action) {
    return action == Action::Allow ? "allow" : "block";
}

bool parseRule(const nlohmann::json& value,
               FirewallRule& rule,
               std::string& error) {
    if (!value.is_object()) {
        error = "each firewall rule must be an object";
        return false;
    }
    if (value.size() != REQUIRED_FIELDS.size()) {
        error = "firewall rule must contain exactly the seven supported fields";
        return false;
    }
    for (const char* field : REQUIRED_FIELDS) {
        if (!value.contains(field)) {
            error = std::string("missing firewall rule field: ") + field;
            return false;
        }
    }

    std::string direction;
    if (!parseEnum(value.at("direction"), "direction",
                   {"incoming", "outgoing"}, direction, error)) {
        return false;
    }
    rule.direction = direction == "incoming" ? Direction::Incoming : Direction::Outgoing;

    std::string protocol;
    if (!parseEnum(value.at("protocol"), "protocol",
                   {"any", "tcp", "udp"}, protocol, error)) {
        return false;
    }
    rule.protocol = protocol == "tcp" ? Protocol::Tcp
        : protocol == "udp" ? Protocol::Udp : Protocol::Any;

    std::string action;
    if (!parseEnum(value.at("action"), "action",
                   {"allow", "block"}, action, error)) {
        return false;
    }
    rule.action = action == "allow" ? Action::Allow : Action::Block;

    if (!parseAddress(value.at("source"), "source", rule.source, error) ||
        !parseAddress(value.at("destination"), "destination", rule.destination, error) ||
        !parsePort(value.at("source_port"), "source_port", rule.sourcePort, error) ||
        !parsePort(value.at("destination_port"), "destination_port",
                   rule.destinationPort, error)) {
        return false;
    }
    if (rule.source.family != AddressFamily::Any &&
        rule.destination.family != AddressFamily::Any &&
        rule.source.family != rule.destination.family) {
        error = "source and destination use different IP families";
        return false;
    }
    if (rule.protocol == Protocol::Any &&
        (!rule.sourcePort.any || !rule.destinationPort.any)) {
        error = "ports require protocol tcp or udp";
        return false;
    }
    return true;
}

} // namespace

bool parseFirewallRules(const std::string& value,
                        std::vector<FirewallRule>& rules,
                        std::string& normalized,
                        std::string& error) {
    rules.clear();
    normalized.clear();
    error.clear();
    nlohmann::json document;
    try {
        document = nlohmann::json::parse(value);
    } catch (const nlohmann::json::exception& exception) {
        error = std::string("invalid firewall JSON: ") + exception.what();
        return false;
    }
    if (!document.is_array()) {
        error = "custom_rules top level must be a JSON array";
        return false;
    }

    nlohmann::json canonical = nlohmann::json::array();
    for (std::size_t index = 0; index < document.size(); ++index) {
        FirewallRule rule;
        std::string ruleError;
        if (!parseRule(document.at(index), rule, ruleError)) {
            error = "rule " + std::to_string(index) + ": " + ruleError;
            rules.clear();
            return false;
        }
        canonical.push_back(firewallRuleToJson(rule));
        rules.push_back(std::move(rule));
    }
    normalized = canonical.dump();
    return true;
}

nlohmann::json firewallRuleToJson(const FirewallRule& rule) {
    return {
        {"action", actionName(rule.action)},
        {"destination", rule.destination.value},
        {"destination_port", portToJson(rule.destinationPort)},
        {"direction", directionName(rule.direction)},
        {"protocol", protocolName(rule.protocol)},
        {"source", rule.source.value},
        {"source_port", portToJson(rule.sourcePort)}
    };
}

} // namespace fic::firewall
