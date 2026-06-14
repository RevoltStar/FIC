#include "modules/oss/submodules/DisplayManager/backends/GdmBackend.h"

#include <filesystem>

GdmBackend::GdmBackend(bool debianVariant)
    : displayName(debianVariant ? "GDM3" : "GDM")
{
    if (!debianVariant) {
        path = "/etc/gdm/custom.conf";
        return;
    }

    std::error_code error;
    if (std::filesystem::exists("/etc/gdm3/daemon.conf", error)) {
        path = "/etc/gdm3/daemon.conf";
    } else if (std::filesystem::exists("/etc/gdm3/custom.conf", error)) {
        path = "/etc/gdm3/custom.conf";
    } else {
        path = "/etc/gdm3/daemon.conf";
    }
}
