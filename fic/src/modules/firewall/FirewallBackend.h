#ifndef FIC_FIREWALL_BACKEND_H
#define FIC_FIREWALL_BACKEND_H

#include "modules/firewall/FirewallNft.h"
#include "platform/PlatformExecutableResolver.h"

#include <string>
#include <vector>

namespace fic::firewall {

class FirewallBackend {
public:
    explicit FirewallBackend(
        const fic::platform::PlatformExecutableResolver& executables);

    bool applyPolicy(const std::string& policyName,
                     const std::vector<FirewallRule>& rules,
                     std::string& error) const;

    bool applyExclusive(std::vector<ForeignBaseChain>& neutralized,
                        std::string& error) const;

    bool reconcile(const FirewallDesiredState& desired,
                   std::vector<ForeignBaseChain>& neutralized,
                   std::string& error) const;

private:
    bool resolveNft(std::string& executable, std::string& error) const;
    bool readActual(const std::string& executable,
                    FirewallActualState& state,
                    std::string& error) const;
    bool executeScript(const std::string& executable,
                       const std::string& script,
                       std::string& error) const;

    const fic::platform::PlatformExecutableResolver& executables_;
};

} // namespace fic::firewall

#endif // FIC_FIREWALL_BACKEND_H
