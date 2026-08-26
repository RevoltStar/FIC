#ifndef SDDM_BACKEND_H
#define SDDM_BACKEND_H

#include "modules/oss/display_manager/backends/DisplayManagerBackend.h"

#include <utility>

class SddmBackend final : public DisplayManagerBackend {
public:
    explicit SddmBackend(std::string configPath)
        : path(std::move(configPath)) {}

    DisplayManagerKind kind() const override { return DisplayManagerKind::Sddm; }
    const char* name() const override { return "SDDM"; }
    const std::string& configPath() const override { return path; }

private:
    std::string path;
};

#endif // SDDM_BACKEND_H
