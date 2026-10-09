#ifndef FIC_FIREWALL_BACKEND_H
#define FIC_FIREWALL_BACKEND_H

#include "modules/firewall/FirewallNft.h"
#include "platform/PlatformExecutableResolver.h"

#include <string>
#include <vector>
#include <functional>
#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/fs/SecureStateFile.h>

namespace fic::firewall {

class FirewallCoordinator;
using NftRunner = std::function<ProcessResult(const std::vector<std::string>&,
                                             const ProcessOptions&)>;
struct FirewallOwnershipOptions {
    std::filesystem::path path;
    fic::core::SecureStateFileExpectation expectation;
};

class FirewallBackend {
public:
    explicit FirewallBackend(
        const fic::platform::PlatformExecutableResolver& executables);
    FirewallBackend(const fic::platform::PlatformExecutableResolver& executables,
                    NftRunner runner, FirewallOwnershipOptions ownership,
                    std::function<bool()> quarantineDecision = {},
                    std::function<bool(FirewallDesiredState&, std::string&)> configuration = {});

    bool applyPolicy(const std::string& policyName,
                     const std::vector<FirewallRule>& rules,
                     bool& changed,
                     std::string& error) const;

    bool applyExclusive(std::vector<ForeignBaseChain>& neutralized,
                        std::string& error) const;

    bool reconcile(const FirewallDesiredState& desired,
                   std::vector<ForeignBaseChain>& neutralized,
                   std::string& error) const;

private:
    friend class FirewallCoordinator;
    bool applyEffective(const FirewallDesiredState& desired, bool& changed,
                        std::vector<ForeignBaseChain>& neutralized,
                        std::string& error, const std::string& onlyPolicy = {}) const;
    ProcessResult run(const std::string& executable,
                      const std::vector<std::string>& args,
                      const ProcessOptions& options) const;
    bool resolveNft(std::string& executable, std::string& error) const;
    bool readActual(const std::string& executable,
                    FirewallActualState& state,
                    std::string& error) const;
    bool executeScript(const std::string& executable,
                       const std::string& script,
                       std::string& error) const;

    const fic::platform::PlatformExecutableResolver& executables_;
    NftRunner runner_;
    FirewallOwnershipOptions ownership_;
    std::function<bool()> quarantineDecision_;
    std::function<bool(FirewallDesiredState&, std::string&)> configuration_;
};

} // namespace fic::firewall

#endif // FIC_FIREWALL_BACKEND_H
