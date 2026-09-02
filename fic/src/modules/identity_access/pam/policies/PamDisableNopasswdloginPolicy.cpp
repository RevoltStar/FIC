#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"
#include "modules/identity_access/nss/NssConfiguration.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <optional>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {

struct GroupState {
    bool exists = false;
    unsigned long gid = 0;
    std::vector<std::string> members;
};

bool readRegularFile(const std::filesystem::path& path,
                     std::string& content,
                     std::string& error) {
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode) ||
        S_ISLNK(status.st_mode) || status.st_uid != ::geteuid() ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "unsafe or unavailable identity file: " + path.string();
        return false;
    }
    std::ifstream input(path);
    if (!input.is_open()) {
        error = "could not read identity file: " + path.string();
        return false;
    }
    content.assign(std::istreambuf_iterator<char>(input),
                   std::istreambuf_iterator<char>());
    if (input.bad()) {
        error = "could not read complete identity file: " + path.string();
        return false;
    }
    return true;
}

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find(delimiter, start);
        result.push_back(value.substr(
            start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

bool parseUnsigned(const std::string& value, unsigned long& parsed) {
    if (value.empty() || !std::all_of(
            value.begin(), value.end(), [](unsigned char ch) {
                return std::isdigit(ch) != 0;
            })) return false;
    try {
        parsed = std::stoul(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool matchesSupportedServices(
    const std::vector<fic::identity::nss::NssService>& services,
    const std::vector<std::vector<std::string>>& supported,
    const std::string& database,
    std::string& error) {
    std::vector<std::string> names;
    for (const auto& service : services) {
        if (!service.actions.empty()) {
            error = "NSS " + database +
                " uses service actions outside the platform contract";
            return false;
        }
        names.push_back(service.name);
    }
    if (std::find(supported.begin(), supported.end(), names) ==
        supported.end()) {
        std::ostringstream actual;
        for (const std::string& name : names) {
            if (actual.tellp() > 0) actual << ' ';
            actual << name;
        }
        error = "unsupported NSS " + database + " service list: " +
            actual.str();
        return false;
    }
    return true;
}

bool verifySupportedNss(
    const fic::platform::PamPlatformConfig::PasswordlessLoginControl& control,
    std::string& error) {
    fic::identity::nss::NssConfigurationOptions options;
    options.mainFile.path = control.nsswitchPath;
    options.mainFile.expectedOwner = ::geteuid();
    options.mainFile.expectedGroup.reset();
    options.mainFile.forbiddenMode = 0022;
    fic::identity::nss::NssConfiguration configuration(std::move(options));

    std::optional<std::vector<fic::identity::nss::NssService>> passwd;
    std::optional<std::vector<fic::identity::nss::NssService>> group;
    std::optional<std::vector<fic::identity::nss::NssService>> initgroups;
    if (!configuration.tryGetServices("passwd", passwd, error) ||
        !configuration.tryGetServices("group", group, error) ||
        !configuration.tryGetServices("initgroups", initgroups, error)) {
        return false;
    }
    if (!passwd.has_value() || !group.has_value()) {
        error = "NSS passwd and group databases must have explicit entries";
        return false;
    }
    if (!matchesSupportedServices(
            *passwd, control.supportedNss.passwd, "passwd", error) ||
        !matchesSupportedServices(
            *group, control.supportedNss.group, "group", error)) {
        return false;
    }
    // glibc getgrouplist() uses the group database when initgroups is absent.
    return !initgroups.has_value() || matchesSupportedServices(
        *initgroups, control.supportedNss.initgroups, "initgroups", error);
}

bool readGroupState(const std::filesystem::path& path,
                    const std::string& group,
                    GroupState& state,
                    std::string& error) {
    std::string content;
    if (!readRegularFile(path, content, error)) return false;
    state = {};
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        const auto fields = split(line, ':');
        unsigned long gid = 0;
        if (fields.size() != 4 || fields[0].empty() ||
            !parseUnsigned(fields[2], gid)) {
            error = "malformed local group database";
            return false;
        }
        if (fields[0] != group) continue;
        if (state.exists) {
            error = "duplicate local passwordless group: " + group;
            return false;
        }
        state.exists = true;
        state.gid = gid;
        if (!fields[3].empty()) {
            state.members = split(fields[3], ',');
            if (std::any_of(state.members.begin(), state.members.end(),
                            [](const std::string& member) {
                                return member.empty();
                            })) {
                error = "malformed passwordless group member list";
                return false;
            }
        }
    }
    return true;
}

bool hasPrimaryGroup(const std::filesystem::path& path,
                     unsigned long gid,
                     std::string& user,
                     std::string& error) {
    std::string content;
    if (!readRegularFile(path, content, error)) return true;
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        const auto fields = split(line, ':');
        unsigned long recordGid = 0;
        if (fields.size() != 7 || fields[0].empty() ||
            !parseUnsigned(fields[3], recordGid)) {
            error = "malformed local passwd database";
            return true;
        }
        if (recordGid == gid) {
            user = fields[0];
            return true;
        }
    }
    return false;
}

} // namespace

PamDisableNopasswdloginPolicy::PamDisableNopasswdloginPolicy(
    fic::platform::PamPlatformConfig platform,
    const fic::platform::PlatformExecutableResolver& executables,
    Runner runner,
    EffectiveMembershipResolver membershipResolver)
    : platform_(std::move(platform)), executables_(executables),
      runner_(std::move(runner)),
      membershipResolver_(std::move(membershipResolver)) {
    policyName = "disable_nopasswdlogin";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
    if (!runner_) {
        runner_ = [](const std::string& executable,
                     const std::vector<std::string>& arguments) {
            return VerifiedProcessExecutor::execute(executable, arguments);
        };
    }
    if (!membershipResolver_) {
        membershipResolver_ =
            fic::identity::pam::resolvePamEffectiveGroupMembership;
    }
}

bool PamDisableNopasswdloginPolicy::applyPam(const std::string&) {
    if (!platform_.passwordlessLoginControl.has_value()) {
        log("Platform does not declare a passwordless-login mechanism",
            logLevel::ERROR);
        return false;
    }
    const auto& control = *platform_.passwordlessLoginControl;
    std::string error;
    if (!verifySupportedNss(control, error)) {
        log("Cannot prove passwordless group is safely enforceable: " + error,
            logLevel::ERROR);
        return false;
    }
    GroupState group;
    if (!readGroupState(control.groupPath, control.groupName, group, error)) {
        log("Could not inspect passwordless group: " + error, logLevel::ERROR);
        return false;
    }
    fic::identity::pam::PamEffectiveGroupMembership effective;
    if (!membershipResolver_(control.groupName, effective, error)) {
        log("Could not verify effective passwordless group membership: " +
                error,
            logLevel::ERROR);
        return false;
    }
    if (!group.exists) {
        if (!effective.users.empty()) {
            log("Passwordless membership remains effective through NSS, but "
                "the local group does not exist",
                logLevel::ERROR);
            return false;
        }
        return true;
    }
    if (!effective.groupExists || effective.groupId != group.gid) {
        log("Local and effective NSS passwordless groups are inconsistent",
            logLevel::ERROR);
        return false;
    }
    std::string primaryUser;
    error.clear();
    if (hasPrimaryGroup(
            control.passwdPath, group.gid, primaryUser, error)) {
        log(error.empty()
                ? "Refusing to change primary group of user " + primaryUser
                : "Could not inspect primary groups: " + error,
            logLevel::ERROR);
        return false;
    }
    if (group.members.empty()) {
        if (!effective.users.empty()) {
            log("Passwordless membership remains effective through NSS; "
                "systemd/role-derived membership is not locally mutable",
                logLevel::ERROR);
            return false;
        }
        return true;
    }

    std::filesystem::path gpasswd;
    if (!executables_.resolve(
            fic::platform::ExecutableId::Gpasswd, gpasswd, error)) {
        log("Could not resolve gpasswd: " + error, logLevel::ERROR);
        return false;
    }
    const ProcessResult result = runner_(
        gpasswd.string(), {"-M", "", control.groupName});
    if (!result.success()) {
        log("Could not clear passwordless group membership: " +
                (result.error.empty() ? result.standardError : result.error),
            logLevel::ERROR);
        return false;
    }
    GroupState verified;
    fic::identity::pam::PamEffectiveGroupMembership verifiedEffective;
    primaryUser.clear();
    error.clear();
    if (!verifySupportedNss(control, error) ||
        !readGroupState(
            control.groupPath, control.groupName, verified, error) ||
        !verified.exists || verified.gid != group.gid ||
        !verified.members.empty() ||
        hasPrimaryGroup(
            control.passwdPath, verified.gid, primaryUser, error) ||
        !membershipResolver_(
            control.groupName, verifiedEffective, error) ||
        !verifiedEffective.groupExists ||
        verifiedEffective.groupId != verified.gid ||
        !verifiedEffective.users.empty()) {
        log("Passwordless group postcondition failed: " +
                (error.empty() ? "membership remains effective" : error),
            logLevel::ERROR);
        return false;
    }
    return true;
}
