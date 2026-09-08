#ifndef FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_FACTORY_H
#define FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_FACTORY_H

#include "modules/identity_access/pam/PamTopologyManager.h"
#include "platform/PlatformExecutableResolver.h"

#include <memory>
#include <string>
#include <vector>

namespace fic::identity::pam {

std::unique_ptr<PamTopologyManager> createPamTopologyManager(
    const fic::platform::PamPlatformConfig& platformConfig,
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    std::string& error);

} // namespace fic::identity::pam

#endif
