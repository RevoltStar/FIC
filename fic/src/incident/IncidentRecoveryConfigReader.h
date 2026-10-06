#pragma once

#include <fic/core/fs/SecureStateFile.h>

#include <filesystem>
#include <string>

namespace fic::incident {

class IncidentRecoveryConfigReader {
public:
    // Production always uses the fixed GLOBAL.conf path and root:fic proof.
    static bool ficMemberExemptionEnabled(std::string& diagnostic);

    // The expectation is explicit for isolated tests; callers must supply the
    // same secure file and parent proof used for production.
    static bool read(const std::filesystem::path& path,
                     const ::fic::core::SecureStateFileExpectation& expectation,
                     std::string& diagnostic);
};

} // namespace fic::incident
