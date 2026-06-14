#include "modules/oss/submodules/DisplayManager/backends/LightDmBackend.h"

const std::string& LightDmBackend::configPath() const
{
    static const std::string path = "/etc/lightdm/lightdm.conf";
    return path;
}
