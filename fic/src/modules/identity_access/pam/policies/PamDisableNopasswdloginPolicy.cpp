#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"
#include "modules/identity_access/nss/NssConfiguration.h"
#include "modules/identity_access/pam/PamConfiguration.h"

#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/fs/TrustedFileReader.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <optional>
#include <set>
#include <sstream>
#include <unistd.h>
#include <utility>

namespace {

struct GroupState {
    bool exists = false;
    unsigned long gid = 0;
    std::vector<std::string> members;
};

enum class EnforcementMode {
    GroupMembership,
    PamBypass
};

bool readIdentityFile(
    const std::filesystem::path& path,
    const fic::core::TrustedFilePostValidationHook& validationHook,
    std::string& content,
    std::string& error) {
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    return fic::core::readTrustedFile(
        path, options, content, error, nullptr, validationHook);
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

bool classifyServices(
    const std::vector<fic::identity::nss::NssService>& services,
    const std::vector<std::vector<std::string>>& supported,
    const std::vector<std::string>& pamBypassServices,
    const std::string& database,
    bool& requiresPamBypass,
    std::string& error) {
    std::vector<std::string> names;
    std::set<std::string> unique;
    for (const auto& service : services) {
        if (!service.actions.empty()) {
            error = "NSS " + database +
                " uses service actions outside the platform contract";
            return false;
        }
        if (!unique.insert(service.name).second) {
            error = "NSS " + database + " contains a duplicate service: " +
                service.name;
            return false;
        }
        if (std::find(pamBypassServices.begin(), pamBypassServices.end(),
                      service.name) != pamBypassServices.end()) {
            requiresPamBypass = true;
            continue;
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

bool classifyNss(
    const fic::platform::PamPlatformConfig::PasswordlessLoginControl& control,
    EnforcementMode& mode,
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
    bool requiresPamBypass = false;
    if (!classifyServices(
            *passwd, control.supportedNss.passwd,
            control.pamBypassNssServices, "passwd", requiresPamBypass,
            error) ||
        !classifyServices(
            *group, control.supportedNss.group,
            control.pamBypassNssServices, "group", requiresPamBypass,
            error)) {
        return false;
    }
    // glibc getgrouplist() uses the group database when initgroups is absent.
    if (initgroups.has_value() &&
        !classifyServices(
            *initgroups, control.supportedNss.initgroups,
            control.pamBypassNssServices, "initgroups", requiresPamBypass,
            error)) {
        return false;
    }
    mode = requiresPamBypass
        ? EnforcementMode::PamBypass
        : EnforcementMode::GroupMembership;
    return true;
}

bool parseGroupState(const std::string& content,
                     const std::string& group,
                     GroupState& state,
                     std::string& error) {
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

bool findPrimaryGroup(const std::string& content,
                      unsigned long gid,
                      std::string& user,
                      std::string& error) {
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

using BypassRule = fic::platform::PamTrustedAuthenticationBypassRule;

struct PamTarget {
    const BypassRule* rule = nullptr;
    std::filesystem::path path;
    std::string original;
    std::string candidate;
    fic::core::TrustedFileMetadata metadata;
};

bool readPamTarget(const std::filesystem::path& path,
                   bool& exists,
                   std::string& content,
                   fic::core::TrustedFileMetadata& metadata,
                   std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) {
            exists = false;
            error.clear();
            return true;
        }
        error = "could not inspect PAM service " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    exists = true;
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    options.requireRegularFile = true;
    options.requireSingleLink = true;
    return fic::core::readTrustedFile(path, options, content, error, &metadata);
}

AtomicTargetState atomicState(
    const fic::core::TrustedFileMetadata& metadata,
    const std::string& content) {
    AtomicTargetState state;
    state.identity.device = metadata.device;
    state.identity.inode = metadata.inode;
    state.content = content;
    state.mode = metadata.mode & 07777;
    state.owner = metadata.owner;
    state.group = metadata.group;
    return state;
}

AtomicWriteOptions writeOptions(
    const fic::core::TrustedFileMetadata& metadata,
    const std::string& content) {
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    options.expectedTargetState = atomicState(metadata, content);
    return options;
}

bool targetsPasswordlessGroup(const fic::identity::pam::PamRule& rule,
                              const std::string& group) {
    for (std::size_t index = 0; index + 1 < rule.arguments.size(); ++index) {
        if (rule.arguments[index] == "ingroup" &&
            rule.arguments[index + 1] == group) {
            return true;
        }
    }
    return false;
}

bool removeLine(const std::string& content,
                std::size_t line,
                std::string& candidate) {
    if (line == 0) {
        return false;
    }
    std::size_t begin = 0;
    for (std::size_t current = 1; current < line; ++current) {
        begin = content.find('\n', begin);
        if (begin == std::string::npos) {
            return false;
        }
        ++begin;
    }
    std::size_t end = content.find('\n', begin);
    end = end == std::string::npos ? content.size() : end + 1;
    candidate = content;
    candidate.erase(begin, end - begin);
    return true;
}

bool inspectPamBypass(const std::filesystem::path& path,
                      const std::string& content,
                      const BypassRule& contract,
                      std::string& candidate,
                      bool& compliant,
                      std::string& error) {
    std::vector<fic::identity::pam::PamRule> rules;
    if (!fic::identity::pam::PamConfiguration::parseRulesContent(
            path, content, rules, error)) {
        return false;
    }
    const fic::identity::pam::PamRule* exact = nullptr;
    for (const auto& rule : rules) {
        if (rule.group != fic::identity::pam::PamManagementGroup::Auth ||
            rule.includeKind != fic::identity::pam::PamIncludeKind::None ||
            std::filesystem::path(rule.module).filename() != contract.module ||
            !targetsPasswordlessGroup(rule, contract.arguments.back())) {
            continue;
        }
        const bool matches = rule.control == contract.control &&
            rule.arguments == contract.arguments;
        if (!matches || exact != nullptr) {
            error = path.string() +
                ": conflicting passwordless PAM bypass rule";
            return false;
        }
        exact = &rule;
    }
    if (exact == nullptr) {
        compliant = true;
        candidate = content;
        error.clear();
        return true;
    }
    compliant = false;
    if (!removeLine(content, exact->line, candidate)) {
        error = path.string() + ": invalid passwordless PAM rule position";
        return false;
    }
    error.clear();
    return true;
}

bool restorePamTargets(
    const std::vector<PamTarget>& targets,
    std::size_t written,
    const PamDisableNopasswdloginPolicy::Writer& writer,
    const std::string& failure,
    std::string& error) {
    std::string rollbackFailures;
    while (written > 0) {
        const PamTarget& target = targets[--written];
        bool exists = false;
        std::string current;
        fic::core::TrustedFileMetadata metadata;
        std::string targetError;
        if (!readPamTarget(
                target.path, exists, current, metadata, targetError) ||
            !exists ||
            !writer(target.path.string(), target.original,
                    writeOptions(metadata, current), &targetError)) {
            if (!rollbackFailures.empty()) {
                rollbackFailures += "; ";
            }
            rollbackFailures += target.path.string() + ": " + targetError;
            continue;
        }
        std::string restored;
        fic::core::TrustedFileMetadata restoredMetadata;
        if (!readPamTarget(target.path, exists, restored, restoredMetadata,
                           targetError) ||
            !exists || restored != target.original) {
            if (!rollbackFailures.empty()) {
                rollbackFailures += "; ";
            }
            rollbackFailures += target.path.string() +
                ": rollback verification failed: " + targetError;
        }
    }
    error = failure;
    if (rollbackFailures.empty()) {
        error += "; original PAM configuration restored";
    } else {
        error += "; CRITICAL: rollback failed: " + rollbackFailures;
    }
    return false;
}

bool enforcePamBypasses(
    const fic::platform::PamPlatformConfig& platform,
    const PamDisableNopasswdloginPolicy::Writer& writer,
    std::string& error) {
    std::vector<PamTarget> targets;
    for (const auto& rule : platform.trustedAuthenticationBypasses) {
        if (rule.reason != fic::platform::
                PamTrustedAuthenticationBypassReason::
                    ExplicitPasswordlessLogin) {
            continue;
        }
        if (!rule.source.has_value() || rule.arguments.empty()) {
            error = "incomplete platform passwordless PAM bypass contract";
            return false;
        }
        PamTarget target;
        target.rule = &rule;
        target.path = *rule.source;
        bool exists = false;
        if (!readPamTarget(target.path, exists, target.original,
                           target.metadata, error)) {
            return false;
        }
        if (!exists) {
            continue;
        }
        bool compliant = false;
        if (!inspectPamBypass(target.path, target.original, rule,
                              target.candidate, compliant, error)) {
            return false;
        }
        if (!compliant) {
            targets.push_back(std::move(target));
        }
    }

    std::size_t written = 0;
    for (const auto& target : targets) {
        std::string writeError;
        if (!writer(target.path.string(), target.candidate,
                    writeOptions(target.metadata, target.original),
                    &writeError)) {
            return restorePamTargets(
                targets, written, writer,
                "could not atomically disable passwordless PAM bypass at " +
                    target.path.string() + ": " + writeError,
                error);
        }
        ++written;
    }

    for (const auto& rule : platform.trustedAuthenticationBypasses) {
        if (rule.reason != fic::platform::
                PamTrustedAuthenticationBypassReason::
                    ExplicitPasswordlessLogin) {
            continue;
        }
        bool exists = false;
        std::string verified;
        std::string ignoredCandidate;
        fic::core::TrustedFileMetadata metadata;
        std::string verifyError;
        bool compliant = true;
        const auto& path = *rule.source;
        if (!readPamTarget(path, exists, verified, metadata, verifyError) ||
            (exists &&
             (!inspectPamBypass(path, verified, rule, ignoredCandidate,
                                compliant, verifyError) ||
              !compliant))) {
            return restorePamTargets(
                targets, written, writer,
                "passwordless PAM bypass postcondition failed at " +
                    path.string() + ": " +
                    (verifyError.empty() ? "bypass remains active"
                                         : verifyError),
                error);
        }
    }
    error.clear();
    return true;
}

} // namespace

PamDisableNopasswdloginPolicy::PamDisableNopasswdloginPolicy(
    fic::platform::PamPlatformConfig platform,
    const fic::platform::PlatformExecutableResolver& executables,
    Runner runner,
    EffectiveMembershipResolver membershipResolver,
    fic::core::TrustedFilePostValidationHook readValidationHook,
    Writer writer)
    : platform_(std::move(platform)), executables_(executables),
      runner_(std::move(runner)),
      membershipResolver_(std::move(membershipResolver)),
      readValidationHook_(std::move(readValidationHook)),
      writer_(std::move(writer)) {
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
    if (!writer_) {
        writer_ = AtomicFileWriter::write;
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
    EnforcementMode enforcementMode = EnforcementMode::GroupMembership;
    if (!classifyNss(control, enforcementMode, error)) {
        log("Cannot prove passwordless group is safely enforceable: " + error,
            logLevel::ERROR);
        return false;
    }
    if (enforcementMode == EnforcementMode::PamBypass) {
        if (!enforcePamBypasses(platform_, writer_, error)) {
            log("Could not disable passwordless PAM bypass: " + error,
                logLevel::ERROR);
            return false;
        }
        return true;
    }
    GroupState group;
    std::string groupContent;
    if (!readIdentityFile(control.groupPath, readValidationHook_,
                          groupContent, error) ||
        !parseGroupState(groupContent, control.groupName, group, error)) {
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
    std::string passwdContent;
    error.clear();
    if (!readIdentityFile(control.passwdPath, readValidationHook_,
                          passwdContent, error) ||
        findPrimaryGroup(passwdContent, group.gid, primaryUser, error)) {
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
    groupContent.clear();
    passwdContent.clear();
    error.clear();
    if (!classifyNss(control, enforcementMode, error) ||
        enforcementMode != EnforcementMode::GroupMembership ||
        !readIdentityFile(control.groupPath, readValidationHook_,
                          groupContent, error) ||
        !parseGroupState(
            groupContent, control.groupName, verified, error) ||
        !verified.exists || verified.gid != group.gid ||
        !verified.members.empty() ||
        !readIdentityFile(control.passwdPath, readValidationHook_,
                          passwdContent, error) ||
        findPrimaryGroup(
            passwdContent, verified.gid, primaryUser, error) ||
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
