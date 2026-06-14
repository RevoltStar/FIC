#ifndef GDM_BACKEND_H
#define GDM_BACKEND_H

#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

class GdmBackend final : public DisplayManagerBackend {
public:
    explicit GdmBackend(bool debianVariant);

    DisplayManagerKind kind() const override { return DisplayManagerKind::Gdm; }
    const char* name() const override { return displayName.c_str(); }
    const std::string& configPath() const override { return path; }

private:
    std::string displayName;
    std::string path;
};

#endif // GDM_BACKEND_H
