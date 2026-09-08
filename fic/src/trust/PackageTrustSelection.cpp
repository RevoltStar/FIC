#include "trust/PackageTrustSelection.h"

#include <algorithm>
#include <filesystem>
#include <string>

namespace fic::trust {

std::vector<fic::platform::ExecutableId> declaredExecutableIds(
    const fic::platform::PlatformExecutables& executables) {
    std::vector<fic::platform::ExecutableId> declared;
    declared.reserve(executables.entries.size());
    for (const fic::platform::PlatformExecutableSpec& spec :
         executables.entries) {
        declared.push_back(spec.id);
    }
    return declared;
}

std::vector<fic::platform::ExecutableId> selectAffectedExecutableIds(
    const fic::platform::PlatformExecutables& executables,
    std::istream& affectedPaths) {
    std::vector<fic::platform::ExecutableId> selected;
    for (std::string line; std::getline(affectedPaths, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::filesystem::path affectedPath(line);
        if (!affectedPath.is_absolute() ||
            affectedPath != affectedPath.lexically_normal()) {
            continue;
        }
        for (const fic::platform::PlatformExecutableSpec& spec :
             executables.entries) {
            if (std::find(spec.candidates.begin(), spec.candidates.end(),
                          affectedPath) == spec.candidates.end()) {
                continue;
            }
            if (std::find(selected.begin(), selected.end(), spec.id) ==
                selected.end()) {
                selected.push_back(spec.id);
            }
        }
    }
    return selected;
}

} // namespace fic::trust
