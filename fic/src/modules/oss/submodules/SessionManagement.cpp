#include "modules/oss/submodules/SessionManagement.h"

SessionManagement::SessionManagement()
    : OSS()
{
    this->submoduleName = "SessionManagement";
}

bool SessionManagement::apply()
{
    return true;
}
