#pragma once
#include "incident/IncidentController.h"
#include "modules/firewall/FirewallCoordinator.h"

namespace fic::incident {
class FirewallIncidentNetworkAdapter final : public IncidentNetworkBackend {
public:
    explicit FirewallIncidentNetworkAdapter(firewall::FirewallCoordinator& coordinator)
        : coordinator_(coordinator) {}
    bool applyQuarantine(bool enabled, std::string& diagnostic) override {
        return coordinator_.requestProfile(enabled, diagnostic);
    }
private:
    firewall::FirewallCoordinator& coordinator_;
};
}
