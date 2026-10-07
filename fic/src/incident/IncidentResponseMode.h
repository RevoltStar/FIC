#pragma once

#include <fic/core/fs/SecureStateFile.h>

#include <filesystem>
#include <string>

namespace fic::incident {

enum class IncidentResponseMode { Off, Passive, Active };

struct IncidentResponseModeResult {
    IncidentResponseMode mode = IncidentResponseMode::Active;
    bool proven = false;
    std::string diagnostic;
};

class IncidentResponseModeResolver {
public:
    static IncidentResponseModeResult production();
    static IncidentResponseModeResult read(
        const std::filesystem::path& path,
        const ::fic::core::SecureStateFileExpectation& expectation);
};

const char* incidentResponseModeToken(IncidentResponseMode mode);

} // namespace fic::incident
