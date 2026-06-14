#ifndef LIGHTDM_BACKEND_H
#define LIGHTDM_BACKEND_H

#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

class LightDmBackend final : public DisplayManagerBackend {
public:
    DisplayManagerKind kind() const override { return DisplayManagerKind::LightDm; }
    const char* name() const override { return "LightDM"; }
    const std::string& configPath() const override;
};

#endif // LIGHTDM_BACKEND_H
