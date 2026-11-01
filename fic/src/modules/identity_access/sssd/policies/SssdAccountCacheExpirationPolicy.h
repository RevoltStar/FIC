#pragma once
#include "modules/identity_access/sssd/SssdPolicy.h"
class SssdAccountCacheExpirationPolicy final : public SssdPolicy {
public:
    SssdAccountCacheExpirationPolicy();
};
