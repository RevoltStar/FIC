#include "modules/oss/submodules/SessionManagement.h"

SessionManagement::SessionManagement()
    : OSS()
{
    this->submoduleName = "SessionManagement";
}

bool SessionManagement::check_and_fix()
{
    return true;
}
