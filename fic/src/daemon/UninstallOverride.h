#pragma once
#include <filesystem>
#include <string>
namespace fic::daemon {
enum class UninstallRollbackMode { Standard, IgnoreError, Skip };
enum class UninstallRequirement { Required, BestEffort, Skip };
struct UninstallOverride {
    bool present=false;
    UninstallRollbackMode rollback=UninstallRollbackMode::Standard;
    UninstallRequirement prepare=UninstallRequirement::Required;
    UninstallRequirement stop=UninstallRequirement::Required;
};
// Data only. No shell evaluation, policy inspection or mutation.
bool readUninstallOverride(UninstallOverride&,std::string& error,
    const std::filesystem::path& file="/etc/fic-uninstall-overload");
}
