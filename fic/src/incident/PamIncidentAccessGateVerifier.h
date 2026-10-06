#pragma once

#include "platform/PlatformProfile.h"

#include <string>
#include <sys/types.h>

namespace fic::incident {

// Read-only proof of the installed account gate. A missing service is not a
// reachable login path; every installed controlled service is checked afresh.
class PamIncidentAccessGateVerifier {
public:
    static bool prove(const ::fic::platform::PamPlatformConfig& platform,
                      std::string& diagnostic);
    static bool proveForTests(
        const ::fic::platform::PamPlatformConfig& platform,
        uid_t expectedOwner, std::string& diagnostic);
};

} // namespace fic::incident
