#include "modules/oss/submodules/DisplayManager.h"

#include "session/ProcessExecutor.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <unistd.h>

namespace {
std::string find_systemctl()
{
    for (const char* path : {"/usr/bin/systemctl", "/bin/systemctl"}) {
        if (::access(path, X_OK) == 0) {
            return path;
        }
    }
    return "";
}

std::unordered_map<std::string, std::string> parse_properties(const std::string& output)
{
    std::unordered_map<std::string, std::string> properties;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        const size_t separator = line.find('=');
        if (separator != std::string::npos) {
            properties[line.substr(0, separator)] = line.substr(separator + 1);
        }
    }
    return properties;
}

std::string display_manager_name(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    std::istringstream tokens(value);
    std::string token;
    while (tokens >> token) {
        const std::string filename = std::filesystem::path(token).filename().string();
        if (filename == "gdm3" || filename == "gdm3.service") return "GDM3";
        if (filename == "gdm" || filename == "gdm.service") return "GDM";
        if (filename == "sddm" || filename == "sddm.service") return "SDDM";
        if (filename == "lightdm" || filename == "lightdm.service") return "LIGHTDM";
    }
    return "UNKNOWN";
}
} // namespace

DisplayManager::DisplayManager()
    :OSS()
{
    this->submoduleName = "DisplayManager";
}

bool DisplayManager::apply() {
    return true;
}

std::string DisplayManager::detectDisplayManager() const {
    const std::string systemctl = find_systemctl();
    if (systemctl.empty()) {
        return "UNKNOWN";
    }

    const ProcessResult result = ProcessExecutor::execute(
        systemctl,
        {
            "show", "display-manager.service",
            "--property=Id",
            "--property=Names",
            "--property=FragmentPath",
            "--property=ActiveState",
            "--no-pager"
        }
    );
    if (!result.success()) {
        return "UNKNOWN";
    }

    const auto properties = parse_properties(result.standardOutput);
    const auto property = [&properties](const std::string& name) {
        const auto it = properties.find(name);
        return it == properties.end() ? std::string() : it->second;
    };
    if (property("ActiveState") != "active") {
        return "UNKNOWN";
    }

    for (const char* name : {"Id", "Names", "FragmentPath"}) {
        const std::string detected = display_manager_name(property(name));
        if (detected != "UNKNOWN") {
            return detected;
        }
    }

    return "UNKNOWN";
}
