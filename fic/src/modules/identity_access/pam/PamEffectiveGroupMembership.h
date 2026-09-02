#ifndef FIC_IDENTITY_ACCESS_PAM_EFFECTIVE_GROUP_MEMBERSHIP_H
#define FIC_IDENTITY_ACCESS_PAM_EFFECTIVE_GROUP_MEMBERSHIP_H

#include <string>
#include <vector>

#include <sys/types.h>

namespace fic::identity::pam {

struct PamEffectiveGroupMembership {
    bool groupExists = false;
    gid_t groupId = 0;
    std::vector<std::string> users;
};

// Mirrors pam_succeed_if "user ingroup group": resolve the user and group via
// NSS, then account for primary GID, gr_mem and libc getgrouplist().
bool resolvePamEffectiveGroupMembership(
    const std::string& group,
    PamEffectiveGroupMembership& membership,
    std::string& error);

} // namespace fic::identity::pam

#endif
