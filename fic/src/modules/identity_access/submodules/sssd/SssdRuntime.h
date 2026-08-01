#ifndef FIC_IDENTITY_ACCESS_SSSD_RUNTIME_H
#define FIC_IDENTITY_ACCESS_SSSD_RUNTIME_H

#include "modules/identity_access/submodules/composite/ConfigurationParticipant.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/ProcessExecutor.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace fic::identity::sssd {

using SssdCommandRunner = std::function<ProcessResult(
    const std::string&,
    const std::vector<std::string>&,
    const ProcessOptions&)>;

class SssdRuntime {
public:
    explicit SssdRuntime(
        const fic::platform::PlatformExecutableResolver& executables,
        std::vector<std::string> serviceUnits = {"sssd.service"},
        SssdCommandRunner runner = {});

    ConfigurationPreparationResult attach(
        std::unique_ptr<PreparedConfigurationChange> persistentChange) const;

private:
    const fic::platform::PlatformExecutableResolver& executables_;
    std::vector<std::string> serviceUnits_;
    SssdCommandRunner runner_;
};

} // namespace fic::identity::sssd

#endif // FIC_IDENTITY_ACCESS_SSSD_RUNTIME_H
