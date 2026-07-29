#ifndef DISPLAY_MANAGER_BACKEND_H
#define DISPLAY_MANAGER_BACKEND_H

#include "platform/PlatformProfile.h"

#include <memory>
#include <string>
#include <vector>

enum class DisplayManagerKind {
    Unknown,
    Sddm,
    LightDm,
    Gdm
};

struct DisplayManagerConfigValue {
    std::string section;
    std::string key;
    std::string value;
};

class DisplayManagerBackend {
public:
    virtual ~DisplayManagerBackend() = default;

    virtual DisplayManagerKind kind() const = 0;
    virtual const char* name() const = 0;
    virtual const std::string& configPath() const = 0;

    bool updateConfig(
        const std::vector<DisplayManagerConfigValue>& values,
        std::string& error
    ) const;

    bool readConfig(
        const std::string& section,
        const std::string& key,
        std::string& value,
        std::string& error
    ) const;
};

class DisplayManagerBackendFactory {
public:
    static std::unique_ptr<DisplayManagerBackend> create(
        const std::string& displayManager,
        const fic::platform::DisplayManagerPlatformConfig& platformConfig);
};

#endif // DISPLAY_MANAGER_BACKEND_H
