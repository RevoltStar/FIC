#pragma once

#include "modules/firewall/FirewallBackend.h"
#include <functional>
#include <mutex>
#include <fic/policy/PolicyDependency.h>

namespace fic::firewall {
enum class FirewallEffectiveProfile { Normal, IncidentQuarantine };

// Every backend entry point passes this authority before a kernel mutation.
// The production selector belongs to IncidentController; tests inject decisions.
struct FirewallCoordinatorOptions {
    std::function<FirewallEffectiveProfile()> profile;
    std::function<bool(FirewallDesiredState&, std::string&)> configuration;
};

class FirewallCoordinator {
public:
    explicit FirewallCoordinator(const FirewallBackend& backend,
                                 FirewallCoordinatorOptions options = {});
    FirewallCoordinator(const FirewallCoordinator&) = delete;
    FirewallCoordinator& operator=(const FirewallCoordinator&) = delete;
    bool reconcile(const FirewallDesiredState* normalIntent, bool& changed,
                   std::vector<ForeignBaseChain>& neutralized, std::string& error,
                   bool exclusiveRequested = false);
    bool applyPolicy(const std::string& policy, const std::vector<FirewallRule>& rules,
                     bool& changed, std::string& error);
    bool applyJournaledPolicy(const PolicyRef& policy, const std::vector<FirewallRule>& rules,
                              std::string& error);
    bool requestProfile(bool quarantine, std::string& error);
    static FirewallEffectiveProfile productionProfile();
    static bool productionConfiguration(FirewallDesiredState&, std::string&);
    static bool readConfiguration(const std::filesystem::path& path,
                                  const fic::core::SecureStateFileExpectation& expectation,
                                  FirewallEffectiveProfile profile,
                                  FirewallDesiredState&, std::string&);
private:
    bool effectiveState(const FirewallDesiredState* normalIntent,
                        FirewallDesiredState& desired, std::string& configError);
    const FirewallBackend& backend_;
    FirewallCoordinatorOptions options_;
};
}
