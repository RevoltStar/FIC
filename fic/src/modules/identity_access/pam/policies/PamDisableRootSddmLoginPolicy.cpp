#include "modules/identity_access/pam/policies/PamDisableRootSddmLoginPolicy.h"

#include <fic/core/fs/TrustedFileReader.h>

#include <algorithm>
#include <cctype>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using ExclusionRule = fic::platform::PamTrustedAuthenticationExclusionRule;

enum class RuleState {
    Compliant,
    Upgradeable,
    Missing,
    Conflict
};

struct Inspection {
    RuleState state = RuleState::Conflict;
    std::size_t includeIndex = 0;
    std::size_t ruleIndex = 0;
};

std::vector<std::string> tokens(const std::string& line) {
    std::string code = line;
    const std::size_t comment = code.find('#');
    if (comment != std::string::npos) {
        code.erase(comment);
    }
    std::istringstream input(code);
    std::vector<std::string> result;
    std::string token;
    while (input >> token) {
        result.push_back(token);
    }
    return result;
}

std::vector<std::string> splitLines(const std::string& content) {
    std::vector<std::string> lines;
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

std::string joinLines(const std::vector<std::string>& lines) {
    std::string result;
    for (const auto& line : lines) {
        result += line;
        result.push_back('\n');
    }
    return result;
}

bool exactRule(const std::vector<std::string>& fields,
               const ExclusionRule& rule,
               const std::string& control) {
    if (fields.size() != 3 + rule.arguments.size() ||
        fields[0] != "auth" || fields[1] != control ||
        fields[2] != rule.module) {
        return false;
    }
    return std::equal(rule.arguments.begin(), rule.arguments.end(),
                      fields.begin() + 3);
}

const std::string& enforcedControl(const ExclusionRule& rule) {
    return rule.enforcedControl.empty() ? rule.control : rule.enforcedControl;
}

bool rootSucceedIfRule(const std::vector<std::string>& fields) {
    if (fields.size() < 6 || fields[0] != "auth" ||
        std::filesystem::path(fields[2]).filename() != "pam_succeed_if.so") {
        return false;
    }
    for (std::size_t i = 3; i + 2 < fields.size(); ++i) {
        if (fields[i] == "user" && fields[i + 1] == "!=" &&
            fields[i + 2] == "root") {
            return true;
        }
    }
    return false;
}

bool commonAuthInclude(const std::vector<std::string>& fields,
                       const ExclusionRule& rule) {
    return fields.size() == 2 && fields[0] == "@include" &&
        fields[1] == rule.insertBeforeIncludeTarget;
}

Inspection inspectContent(const std::string& content,
                          const ExclusionRule& rule,
                          std::string& error) {
    const auto lines = splitLines(content);
    std::size_t knownCount = 0;
    std::size_t knownIndex = 0;
    bool knownIsEnforced = false;
    std::size_t includeCount = 0;
    std::size_t includeIndex = 0;
    bool conflictingRootRule = false;

    for (std::size_t i = 0; i < lines.size(); ++i) {
        const auto fields = tokens(lines[i]);
        if (fields.empty()) {
            continue;
        }
        const bool isEnforced =
            exactRule(fields, rule, enforcedControl(rule));
        const bool isNative =
            !isEnforced && exactRule(fields, rule, rule.control);
        if (isEnforced || isNative) {
            ++knownCount;
            knownIndex = i;
            knownIsEnforced = isEnforced;
            continue;
        }
        if (rootSucceedIfRule(fields)) {
            conflictingRootRule = true;
        }
        if (commonAuthInclude(fields, rule)) {
            ++includeCount;
            includeIndex = i;
        }
    }

    if (includeCount != 1) {
        error = "SDDM PAM topology must contain exactly one @include " +
            rule.insertBeforeIncludeTarget;
        return {RuleState::Conflict, 0, 0};
    }
    if (knownCount > 1) {
        error = "SDDM PAM topology contains duplicate root exclusion rules";
        return {RuleState::Conflict, includeIndex, knownIndex};
    }
    if (conflictingRootRule) {
        error = "SDDM PAM topology contains an unmanaged root exclusion rule";
        return {RuleState::Conflict, includeIndex, knownIndex};
    }
    if (knownCount == 1) {
        if (knownIndex >= includeIndex) {
            error = "SDDM root exclusion rule is not placed before common-auth";
            return {RuleState::Conflict, includeIndex, knownIndex};
        }
        error.clear();
        return {knownIsEnforced ? RuleState::Compliant : RuleState::Upgradeable,
                includeIndex, knownIndex};
    }
    error.clear();
    return {RuleState::Missing, includeIndex, 0};
}

bool readTarget(const std::filesystem::path& path,
                std::string& content,
                fic::core::TrustedFileMetadata& metadata,
                std::string& error) {
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    options.requireRegularFile = true;
    options.requireSingleLink = true;
    return fic::core::readTrustedFile(
        path, options, content, error, &metadata);
}

AtomicTargetState atomicState(const fic::core::TrustedFileMetadata& metadata,
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

const ExclusionRule* rootSddmContract(
    const fic::platform::PamPlatformConfig& platform,
    std::string& error) {
    const ExclusionRule* selected = nullptr;
    for (const auto& rule : platform.trustedAuthenticationExclusions) {
        if (rule.service != "sddm" || rule.excludedUser != "root" ||
            rule.reason != fic::platform::
                PamTrustedAuthenticationExclusionReason::
                    ExplicitSubjectExclusion) {
            continue;
        }
        if (selected != nullptr) {
            error = "platform declares multiple SDDM root exclusion contracts";
            return nullptr;
        }
        selected = &rule;
    }
    if (selected == nullptr || !selected->source.has_value() ||
        selected->control.empty() || selected->module.empty() ||
        selected->arguments.empty() ||
        selected->insertBeforeIncludeTarget.empty() ||
        selected->enforcedControl.empty()) {
        error = "platform does not declare a complete SDDM root exclusion contract";
        return nullptr;
    }
    error.clear();
    return selected;
}

std::string canonicalRule(const ExclusionRule& rule) {
    std::string line =
        "auth " + enforcedControl(rule) + " " + rule.module;
    for (const auto& argument : rule.arguments) {
        line += " " + argument;
    }
    return line;
}

} // namespace

PamDisableRootSddmLoginPolicy::PamDisableRootSddmLoginPolicy(
    fic::platform::PamPlatformConfig platform,
    Writer writer)
    : platform_(std::move(platform)), writer_(std::move(writer)) {
    policyName = "disable_root_sddm_login";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
    if (!writer_) {
        writer_ = [](const std::string& path,
                     const std::string& content,
                     const AtomicWriteOptions& options,
                     std::string* error) {
            return AtomicFileWriter::write(path, content, options, error);
        };
    }
}

bool PamDisableRootSddmLoginPolicy::applyPam(const std::string&) {
    std::string error;
    const ExclusionRule* contract = rootSddmContract(platform_, error);
    if (contract == nullptr) {
        log("Cannot enforce SDDM root-login restriction: " + error,
            logLevel::ERROR);
        return false;
    }

    const std::filesystem::path target = *contract->source;
    std::string original;
    fic::core::TrustedFileMetadata originalMetadata;
    if (!readTarget(target, original, originalMetadata, error)) {
        log("Could not inspect SDDM PAM service: " + error, logLevel::ERROR);
        return false;
    }

    const Inspection inspection = inspectContent(original, *contract, error);
    if (inspection.state == RuleState::Conflict) {
        log("Refusing to modify SDDM PAM topology: " + error,
            logLevel::ERROR);
        return false;
    }
    if (inspection.state == RuleState::Compliant) {
        return true;
    }

    auto lines = splitLines(original);
    if (inspection.state == RuleState::Upgradeable) {
        if (inspection.ruleIndex >= lines.size()) {
            log("Refusing to modify SDDM PAM topology: invalid rule position",
                logLevel::ERROR);
            return false;
        }
        lines[inspection.ruleIndex] = canonicalRule(*contract);
    } else {
        if (inspection.includeIndex > lines.size()) {
            log("Refusing to modify SDDM PAM topology: invalid include position",
                logLevel::ERROR);
            return false;
        }
        lines.insert(lines.begin() + inspection.includeIndex,
                     canonicalRule(*contract));
    }
    const std::string candidate = joinLines(lines);

    AtomicWriteOptions options = writeOptions(originalMetadata, original);
    if (!writer_(target.string(), candidate, options, &error)) {
        log("Could not atomically enforce SDDM root-login restriction: " +
                error,
            logLevel::ERROR);
        return false;
    }

    std::string verified;
    fic::core::TrustedFileMetadata verifiedMetadata;
    std::string verifyError;
    const bool postcondition =
        readTarget(target, verified, verifiedMetadata, verifyError) &&
        inspectContent(verified, *contract, verifyError).state ==
            RuleState::Compliant;
    if (postcondition) {
        return true;
    }

    std::string rollbackError;
    bool rollbackOk = false;
    std::string current;
    fic::core::TrustedFileMetadata currentMetadata;
    if (readTarget(target, current, currentMetadata, rollbackError)) {
        AtomicWriteOptions rollbackOptions =
            writeOptions(currentMetadata, current);
        rollbackOk = writer_(target.string(), original, rollbackOptions,
                             &rollbackError);
        if (rollbackOk) {
            std::string restored;
            fic::core::TrustedFileMetadata restoredMetadata;
            rollbackOk = readTarget(
                target, restored, restoredMetadata, rollbackError) &&
                restored == original;
        }
    }

    std::string message =
        "SDDM root-login restriction postcondition failed: " +
        (verifyError.empty() ? "managed rule was not effective" : verifyError);
    if (!rollbackOk) {
        message += "; rollback failed: " +
            (rollbackError.empty() ? "unknown rollback error" : rollbackError);
    } else {
        message += "; original PAM configuration restored";
    }
    log(message, logLevel::ERROR);
    return false;
}
