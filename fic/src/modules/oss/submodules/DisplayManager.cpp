#include "modules/oss/submodules/DisplayManager.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

DisplayManager::DisplayManager()
    :OSS()
{
    this->submoduleName = "DisplayManager";
}

bool DisplayManager::check_and_fix() {
    return true;
}

bool DisplayManager::fileExists(const std::string& path) const {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

std::string DisplayManager::detectDisplayManager() const {
    auto normalizeName = [](std::string value) -> std::string {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        if (value.find("gdm3") != std::string::npos) return "GDM3";
        if (value.find("gdm") != std::string::npos) return "GDM";
        if (value.find("sddm") != std::string::npos) return "SDDM";
        if (value.find("lightdm") != std::string::npos) return "LIGHTDM";

        return "UNKNOWN";
    };

    const std::string displayManagerService = "/etc/systemd/system/display-manager.service";

    if (fileExists(displayManagerService)) {
        std::error_code ec;
        if (std::filesystem::is_symlink(displayManagerService, ec)) {
            auto target = std::filesystem::read_symlink(displayManagerService, ec).string();
            auto detected = normalizeName(target);
            if (detected != "UNKNOWN") {
                return detected;
            }
        }

        std::ifstream serviceFile(displayManagerService);
        if (serviceFile.is_open()) {
            std::string line;
            while (std::getline(serviceFile, line)) {
                auto detected = normalizeName(line);
                if (detected != "UNKNOWN") {
                    return detected;
                }
            }
        }
    }

    if (fileExists(gdm3Conf)) return "GDM3";
    if (fileExists(gdmConf)) return "GDM";
    if (fileExists(sddmConf)) return "SDDM";
    if (fileExists(lightdmConf)) return "LIGHTDM";

    return "UNKNOWN";
}
