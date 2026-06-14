#include "modules/oss/submodules/DisplayManager/backends/SddmBackend.h"

const std::string& SddmBackend::configPath() const
{
    static const std::string path = "/etc/sddm.conf";
    return path;
}
