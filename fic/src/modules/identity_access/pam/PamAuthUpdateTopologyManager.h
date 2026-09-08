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

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamCapabilityConfig capability_;
    std::vector<std::string> services_;
    const fic::platform::PlatformExecutableResolver& executables_;
    PamAuthUpdateTopologyManagerOptions options_;
};

} // namespace fic::identity::pam

#endif
