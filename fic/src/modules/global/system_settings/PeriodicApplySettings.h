#ifndef FIC_PERIODIC_APPLY_SETTINGS_H
#define FIC_PERIODIC_APPLY_SETTINGS_H
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <optional>
#include <string>

namespace fic::daemon {
struct PeriodicApplySettings {
    int intervalSeconds = 1800;
    int minPauseSeconds = 30;
};
// Preserve the historical --interval parser, including positive values outside
// policy bounds and the explicit invalid/nonpositive -> 1800 fallback.
std::optional<int> periodicIntervalOverride(int argc, char* argv[]);
bool readPeriodicApplySettings(ModuleConfigFileHandler& config,
                               std::optional<int> intervalOverride,
                               PeriodicApplySettings& settings, std::string& error);
bool validPeriodicSeconds(const std::string& value, int minimum, int maximum);
} // namespace fic::daemon
#endif
