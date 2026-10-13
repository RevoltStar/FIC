#ifndef FIC_SUDOERS_MANAGED_INCLUDE_H
#define FIC_SUDOERS_MANAGED_INCLUDE_H

#include <filesystem>
#include <string>

namespace fic::sudoers {

// A syntactic placement proof only. Presence of these markers NEVER grants
// ownership; the transaction must independently prove journal provenance.
enum class ManagedIncludeState { Absent, Present, Conflict };

struct ManagedIncludeInspection {
    ManagedIncludeState state = ManagedIncludeState::Conflict;
    std::size_t offset = 0;
    std::string message;
};

std::string managedIncludeBlock(const std::filesystem::path& managedPath);
ManagedIncludeInspection inspectManagedInclude(
    const std::string& mainContent, const std::filesystem::path& managedPath);

} // namespace fic::sudoers
#endif
