#pragma once

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <string>
#include <sys/types.h>

namespace fic::incident {

enum class IncidentGateDetachProof {
    ProvenDetached,
    Referenced,
    Unprovable
};

// Read-only proof of the installed account gate. A missing service is not a
// reachable login path; every installed controlled service is checked afresh.
class PamIncidentAccessGateVerifier {
public:
    static bool prove(const ::fic::platform::PamPlatformConfig& platform,
                      std::string& diagnostic);
    static bool proveForTests(
        const ::fic::platform::PamPlatformConfig& platform,
        uid_t expectedOwner, std::string& diagnostic);
    // Detach proof scans physical rules, including trusted one-hop local
    // service aliases. This does not extend policy attach alias authority.
    // Only pam-auth-update platforms additionally require selection DB proof;
    // a declared packageTopologyTarget has no Debian selection dependency.
    static IncidentGateDetachProof proveDetached(
        const ::fic::platform::PamPlatformConfig& platform,
        std::string& diagnostic);
    // Package infrastructure may inspect a separately pinned selection area;
    // root ownership/trust requirements are unchanged.
    static IncidentGateDetachProof proveDetached(
        const ::fic::platform::PamPlatformConfig& platform,
        const std::filesystem::path& selectionPath,std::string& diagnostic);
    static IncidentGateDetachProof proveDetachedForTests(
        const ::fic::platform::PamPlatformConfig& platform,
        const std::filesystem::path& selectionPath,
        uid_t expectedOwner, std::string& diagnostic);
};

} // namespace fic::incident
