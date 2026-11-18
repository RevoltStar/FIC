#include "modules/global/system_settings/PeriodicApplySettings.h"
#include <charconv>

namespace fic::daemon {
bool validPeriodicSeconds(const std::string& value, int minimum, int maximum) {
    int parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    return !value.empty() && result.ec == std::errc{} &&
        result.ptr == value.data() + value.size() && parsed >= minimum && parsed <= maximum;
}

std::optional<int> periodicIntervalOverride(int argc, char* argv[]) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) != "--interval") continue;
        try {
            const int value = std::stoi(argv[i + 1]);
            return value > 0 ? value : 1800;
        } catch (...) { return 1800; }
    }
    return std::nullopt;
}

bool readPeriodicApplySettings(ModuleConfigFileHandler& config,
                               std::optional<int> intervalOverride,
                               PeriodicApplySettings& settings, std::string& error) {
    error.clear();
    if (!config.loadConfig()) {
        error = "could not read GLOBAL periodic apply settings";
        return false;
    }
    PeriodicApplySettings candidate;
    const auto read = [&](const char* name, int minimum, int maximum,
                          int disabled, int& output) {
        if (!config.hasPolicyStatus(name) && !config.hasConfiguredValue(name)) return true;
        const std::string status = config.ConfigFileHandler::getValue(
            std::string(name) + ".status");
        if (status == "DISABLE") { output = disabled; return true; }
        const std::string value = config.getPolicyValue(name);
        if (status != "ENABLE" || !validPeriodicSeconds(value, minimum, maximum)) {
            error = std::string("invalid GLOBAL periodic apply setting: ") + name;
            return false;
        }
        output = std::stoi(value);
        return true;
    };
    if ((!intervalOverride && !read("check_interval", 60, 86400, 1800, candidate.intervalSeconds)) ||
        !read("periodic_apply_min_pause", 0, 600, 0, candidate.minPauseSeconds)) return false;
    if (intervalOverride) candidate.intervalSeconds = *intervalOverride;
    settings = candidate;
    return true;
}
} // namespace fic::daemon
