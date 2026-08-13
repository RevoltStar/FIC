#ifndef FIC_FIREWALL_RULE_H
#define FIC_FIREWALL_RULE_H

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fic::firewall {

enum class Direction { Incoming, Outgoing };
enum class Protocol { Any, Tcp, Udp };
enum class Action { Allow, Block };
enum class AddressFamily { Any, IPv4, IPv6 };

struct Address {
    AddressFamily family = AddressFamily::Any;
    std::string value = "any";
};

struct PortRange {
    bool any = true;
    std::uint16_t first = 0;
    std::uint16_t last = 0;
};

struct FirewallRule {
    Direction direction = Direction::Incoming;
    Protocol protocol = Protocol::Any;
    Address source;
    Address destination;
    PortRange sourcePort;
    PortRange destinationPort;
    Action action = Action::Allow;
};

bool parseFirewallRules(const std::string& value,
                        std::vector<FirewallRule>& rules,
                        std::string& normalized,
                        std::string& error);

nlohmann::json firewallRuleToJson(const FirewallRule& rule);

} // namespace fic::firewall

#endif // FIC_FIREWALL_RULE_H
