#include "modules/identity_access/pam/PamEffectiveGroupMembership.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <grp.h>
#include <pwd.h>
#include <set>
#include <vector>

#include <unistd.h>

namespace fic::identity::pam {
namespace {

constexpr std::size_t InitialLookupBytes = 16U * 1024U;
constexpr std::size_t MaximumLookupBytes = 4U * 1024U * 1024U;
constexpr int MaximumGroupCount = 65536;

bool growLookupBuffer(std::vector<char>& buffer, std::string& error) {
    if (buffer.size() >= MaximumLookupBytes) {
        error = "NSS record exceeds the supported lookup buffer";
        return false;
    }
    buffer.resize(std::min(buffer.size() * 2U, MaximumLookupBytes));
    return true;
}

bool lookupGroup(const std::string& name,
                 PamEffectiveGroupMembership& membership,
                 std::set<std::string>& textualMembers,
                 std::string& error) {
    std::vector<char> buffer(InitialLookupBytes);
    struct group record {};
    struct group* result = nullptr;
    for (;;) {
        const int lookup = ::getgrnam_r(
            name.c_str(), &record, buffer.data(), buffer.size(), &result);
        if (lookup == ERANGE) {
            if (!growLookupBuffer(buffer, error)) return false;
            continue;
        }
        if (lookup != 0) {
            error = "NSS group lookup failed for " + name + ": " +
                std::strerror(lookup);
            return false;
        }
        if (result == nullptr) {
            membership = {};
            return true;
        }
        membership.groupExists = true;
        membership.groupId = record.gr_gid;
        if (record.gr_mem != nullptr) {
            for (char** member = record.gr_mem; *member != nullptr; ++member) {
                textualMembers.insert(*member);
            }
        }
        return true;
    }
}

bool enumerateUserNames(std::set<std::string>& users, std::string& error) {
    std::vector<char> buffer(InitialLookupBytes);
    ::setpwent();
    for (;;) {
        struct passwd record {};
        struct passwd* result = nullptr;
        const int lookup = ::getpwent_r(
            &record, buffer.data(), buffer.size(), &result);
        if (lookup == ERANGE) {
            if (!growLookupBuffer(buffer, error)) {
                ::endpwent();
                return false;
            }
            continue;
        }
        if (lookup != 0) {
            ::endpwent();
            error = "NSS passwd enumeration failed: " +
                std::string(std::strerror(lookup));
            return false;
        }
        if (result == nullptr) break;
        if (record.pw_name == nullptr || *record.pw_name == '\0') {
            ::endpwent();
            error = "NSS passwd enumeration returned an unnamed identity";
            return false;
        }
        users.insert(record.pw_name);
    }
    ::endpwent();
    return true;
}

bool lookupUser(const std::string& name,
                gid_t& primaryGroup,
                std::string& canonicalName,
                std::string& error) {
    std::vector<char> buffer(InitialLookupBytes);
    struct passwd record {};
    struct passwd* result = nullptr;
    for (;;) {
        const int lookup = ::getpwnam_r(
            name.c_str(), &record, buffer.data(), buffer.size(), &result);
        if (lookup == ERANGE) {
            if (!growLookupBuffer(buffer, error)) return false;
            continue;
        }
        if (lookup != 0) {
            error = "NSS user lookup failed for " + name + ": " +
                std::strerror(lookup);
            return false;
        }
        if (result == nullptr || record.pw_name == nullptr) {
            error = "NSS identity disappeared during verification: " + name;
            return false;
        }
        primaryGroup = record.pw_gid;
        canonicalName = record.pw_name;
        return true;
    }
}

bool getGroupListContains(const std::string& user,
                          gid_t primaryGroup,
                          gid_t targetGroup,
                          bool& contains,
                          std::string& error) {
    int count = 32;
    std::vector<gid_t> groups(static_cast<std::size_t>(count));
    for (;;) {
        int requested = count;
        const int result = ::getgrouplist(
            user.c_str(), primaryGroup, groups.data(), &requested);
        if (result >= 0) {
            groups.resize(static_cast<std::size_t>(requested));
            contains = std::find(groups.begin(), groups.end(), targetGroup) !=
                groups.end();
            return true;
        }
        if (requested <= count || requested > MaximumGroupCount) {
            error = "NSS supplementary-group lookup is incomplete for " + user;
            return false;
        }
        count = requested;
        groups.resize(static_cast<std::size_t>(count));
    }
}

} // namespace

bool resolvePamEffectiveGroupMembership(
    const std::string& group,
    PamEffectiveGroupMembership& membership,
    std::string& error) {
    membership = {};
    std::set<std::string> textualMembers;
    if (!lookupGroup(group, membership, textualMembers, error) ||
        !membership.groupExists) {
        return error.empty();
    }

    // Explicit gr_mem names must be checked even if an NSS passwd backend
    // does not enumerate them. The supported ALT contract additionally allows
    // files/systemd passwd enumeration for primary and initgroups membership.
    std::set<std::string> users = textualMembers;
    if (!enumerateUserNames(users, error)) return false;
    for (const std::string& enumeratedName : users) {
        gid_t primaryGroup = 0;
        std::string user;
        if (!lookupUser(
                enumeratedName, primaryGroup, user, error)) {
            return false;
        }
        bool effective = primaryGroup == membership.groupId ||
            textualMembers.count(user) != 0;
        if (!effective && !getGroupListContains(
                user, primaryGroup, membership.groupId, effective, error)) {
            return false;
        }
        if (effective) membership.users.push_back(std::move(user));
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam
