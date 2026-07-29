#ifndef LIGHTDM_BACKEND_H
#define LIGHTDM_BACKEND_H

#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

#include <utility>

class LightDmBackend final : public DisplayManagerBackend {
public:
    explicit LightDmBackend(std::string configPath)
        : path(std::move(configPath)) {}

    DisplayManagerKind kind() const override { return DisplayManagerKind::LightDm; }
    const char* name() const override { return "LightDM"; }
    const std::string& configPath() const override { return path; }

private:
    std::string path;
};

#endif // LIGHTDM_BACKEND_H
