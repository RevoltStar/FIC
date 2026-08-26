#include "modules/oss/desktop_environment/DesktopEnvironment.h"

DesktopEnvironment::DesktopEnvironment()
    :OSS()
{
    this->submoduleName = "DesktopEnvironment";
}

bool DesktopEnvironment::apply() {
    return true;
}

