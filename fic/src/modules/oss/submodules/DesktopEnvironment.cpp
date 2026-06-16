#include "modules/oss/submodules/DesktopEnvironment.h"

DesktopEnvironment::DesktopEnvironment()
    :OSS()
{
    this->submoduleName = "DesktopEnvironment";
}

bool DesktopEnvironment::apply() {
    return true;
}

