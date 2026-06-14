#ifndef SDDM_BACKEND_H
#define SDDM_BACKEND_H

#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

class SddmBackend final : public DisplayManagerBackend {
public:
    DisplayManagerKind kind() const override { return DisplayManagerKind::Sddm; }
    const char* name() const override { return "SDDM"; }
    const std::string& configPath() const override;
};

#endif // SDDM_BACKEND_H
