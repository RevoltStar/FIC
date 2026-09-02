#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"

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

bool verifyFilesOnlyNss(const std::filesystem::path& path,
                        std::string& error) {
    std::string content;
    if (!readRegularFile(path, content, error)) return false;
    std::istringstream input(content);
    std::string line;
    bool passwdFound = false;
    bool groupFound = false;
    bool initgroupsFound = false;
    while (std::getline(input, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string database = line.substr(0, colon);
        database.erase(std::remove_if(database.begin(), database.end(),
                                      [](unsigned char ch) {
                                          return std::isspace(ch) != 0;
                                      }), database.end());
        bool* found = nullptr;
        if (database == "passwd") {
            found = &passwdFound;
        } else if (database == "group") {
            found = &groupFound;
        } else if (database == "initgroups") {
            found = &initgroupsFound;
        } else {
            continue;
        }
        if (*found) {
            error = "NSS " + database +
                " database must have exactly one explicit entry";
            return false;
        }
        *found = true;
        std::istringstream services(line.substr(colon + 1));
        std::string service;
        std::vector<std::string> values;
        while (services >> service) values.push_back(service);
        if (values != std::vector<std::string>{"files"}) {
            error = "NSS " + database + " database is not local-files-only";
            return false;
        }
    }
    if (!passwdFound || !groupFound) {
        error = "NSS passwd and group databases must have explicit entries";
        return false;
    }
    return true;
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
    Runner runner)
    : platform_(std::move(platform)), executables_(executables),
      runner_(std::move(runner)) {
    policyName = "disable_nopasswdlogin";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
    if (!runner_) {
        runner_ = [](const std::string& executable,
                     const std::vector<std::string>& arguments) {
            return VerifiedProcessExecutor::execute(executable, arguments);
        };
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
    if (!verifyFilesOnlyNss(control.nsswitchPath, error)) {
        log("Cannot prove passwordless group is locally enforceable: " + error,
            logLevel::ERROR);
        return false;
    }
    GroupState group;
    if (!readGroupState(control.groupPath, control.groupName, group, error)) {
        log("Could not inspect passwordless group: " + error, logLevel::ERROR);
        return false;
    }
    if (!group.exists) return true;
    std::string primaryUser;
    if (hasPrimaryGroup(
            control.passwdPath, group.gid, primaryUser, error)) {
        log(error.empty()
                ? "Refusing to change primary group of user " + primaryUser
                : "Could not inspect primary groups: " + error,
            logLevel::ERROR);
        return false;
    }
    if (group.members.empty()) return true;

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
    primaryUser.clear();
    if (!verifyFilesOnlyNss(control.nsswitchPath, error) ||
        !readGroupState(
            control.groupPath, control.groupName, verified, error) ||
        !verified.exists || !verified.members.empty() ||
        hasPrimaryGroup(
            control.passwdPath, verified.gid, primaryUser, error)) {
        log("Passwordless group postcondition failed: " +
                (error.empty() ? "membership remains effective" : error),
            logLevel::ERROR);
        return false;
    }
    return true;
}
