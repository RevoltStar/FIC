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

struct PamUserIdentity {
    std::string canonicalName;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t primaryGroup = static_cast<gid_t>(-1);
};

bool resolvePamUserIdentity(const std::string& name,
                            PamUserIdentity& identity,
                            std::string& error);
bool isPamUserMemberOfGroup(const PamUserIdentity& identity,
                            const std::string& group,
                            bool& member,
                            std::string& error);

// Mirrors pam_succeed_if "user ingroup group": resolve the user and group via
// NSS, then account for primary GID, gr_mem and libc getgrouplist().
bool resolvePamEffectiveGroupMembership(
    const std::string& group,
    PamEffectiveGroupMembership& membership,
    std::string& error);

} // namespace fic::identity::pam

#endif
