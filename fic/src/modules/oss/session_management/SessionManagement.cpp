#include "modules/oss/session_management/SessionManagement.h"

SessionManagement::SessionManagement()
    : OSS()
{
    this->submoduleName = "SessionManagement";
}

bool SessionManagement::apply()
{
    return true;
}
