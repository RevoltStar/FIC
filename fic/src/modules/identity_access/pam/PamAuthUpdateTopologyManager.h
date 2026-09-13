#ifndef FIC_IDENTITY_ACCESS_PAM_AUTH_UPDATE_TOPOLOGY_MANAGER_H
#define FIC_IDENTITY_ACCESS_PAM_AUTH_UPDATE_TOPOLOGY_MANAGER_H

#include "modules/identity_access/pam/PamTopologyManager.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/process/ProcessExecutor.h>

#include <functional>
#include <string>
#include <vector>

namespace fic::identity::pam {

struct PamAuthUpdateTopologyManagerOptions {
    std::function<ProcessResult(
        const std::string&, const std::vector<std::string>&,
        const ProcessOptions&)> runner;
};

class PamAuthUpdateTopologyManager final : public PamTopologyManager {
public:
    PamAuthUpdateTopologyManager(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamCapabilityConfig capability,
        std::vector<std::string> services,
        const fic::platform::PlatformExecutableResolver& executables,
        PamAuthUpdateTopologyManagerOptions options = {});

    bool inspect(PamTopologyStatus& status, std::string& error) override;
    bool canEnable(std::string& error) const override;
    bool enable(std::string& error) override;
    bool disable(std::string& error) override;

    bool canEnableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const override;
    bool enableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) override;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamCapabilityConfig capability_;
    std::vector<std::string> services_;
    const fic::platform::PlatformExecutableResolver& executables_;
    PamAuthUpdateTopologyManagerOptions options_;

    // All faillock activation identifiers declared by this platform, across
    // every supported strategy. Used to reset the profile selection before
    // enabling the requested strategy.
    std::vector<std::string> knownActivationIdentifiers() const;
    const std::vector<std::string>* strategyActivationIdentifiers(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const;
    bool runPamAuthUpdate(
        const std::string& mode,
        const std::vector<std::string>& identifiers,
        std::string& error);
    bool resolveExecutable(std::filesystem::path& executable,
                           std::string& error) const;
};

} // namespace fic::identity::pam

#endif
