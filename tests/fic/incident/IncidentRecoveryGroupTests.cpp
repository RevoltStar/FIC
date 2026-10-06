#include "modules/identity_access/pam/PamEffectiveGroupMembership.h"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <array>
#include <stdexcept>
#include <string>

namespace {
void require(bool value) {
    if (!value) throw std::runtime_error("incident recovery NSS regression");
}
}

int main() {
    std::array<char, 16384> userBuffer{};
    passwd userRecord{};
    passwd* user = nullptr;
    require(::getpwuid_r(::geteuid(), &userRecord, userBuffer.data(),
                         userBuffer.size(), &user) == 0 && user != nullptr);

    std::array<char, 16384> groupBuffer{};
    group groupRecord{};
    group* primaryGroup = nullptr;
    require(::getgrgid_r(user->pw_gid, &groupRecord, groupBuffer.data(),
                         groupBuffer.size(), &primaryGroup) == 0 &&
            primaryGroup != nullptr);

    std::string error;
    fic::identity::pam::PamUserIdentity identity;
    require(fic::identity::pam::resolvePamUserIdentity(
        user->pw_name, identity, error));
    require(identity.uid == user->pw_uid &&
            identity.primaryGroup == user->pw_gid &&
            identity.canonicalName == user->pw_name);

    bool member = false;
    require(fic::identity::pam::isPamUserMemberOfGroup(
        identity, primaryGroup->gr_name, member, error) && member);
    member = true;
    require(!fic::identity::pam::isPamUserMemberOfGroup(
        identity, "fic-recovery-test-nonexistent-group", member, error) &&
            !member);
}
