#ifndef FIC_ALT_GROUP_POLICIES_H
#define FIC_ALT_GROUP_POLICIES_H

#include "modules/identity_access/IdentityAccessPolicy.h"

namespace fic::identity::alt_groups {

class AltLdapUsersDefaultGroupsPolicy final : public IdentityAccessPolicy {
public:
    AltLdapUsersDefaultGroupsPolicy();
    bool apply() override;
};

class AltRoleGroupsPolicy final : public IdentityAccessPolicy {
public:
    AltRoleGroupsPolicy();
    bool apply() override;
};

} // namespace fic::identity::alt_groups
#endif
