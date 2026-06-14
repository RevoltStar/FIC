#include "modules/oss/submodules/DesktopEnvironment.h"

DesktopEnvironment::DesktopEnvironment()
    :OSS()
{
    this->submoduleName = "DesktopEnvironment";
}

bool DesktopEnvironment::check_and_fix() {
    return true;
}

