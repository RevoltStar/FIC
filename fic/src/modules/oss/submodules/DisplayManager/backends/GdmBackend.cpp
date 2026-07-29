#include "modules/oss/submodules/DisplayManager/backends/GdmBackend.h"

#include <filesystem>
#include <utility>

GdmBackend::GdmBackend(
    std::string selectedDisplayName,
    const std::vector<std::filesystem::path>& configCandidates)
    : displayName(std::move(selectedDisplayName))
{
    for (const std::filesystem::path& candidate : configCandidates) {
        std::error_code error;
        if (std::filesystem::exists(candidate, error) && !error) {
            path = candidate.string();
            return;
        }
    }
    if (!configCandidates.empty()) {
        path = configCandidates.front().string();
    }
}
