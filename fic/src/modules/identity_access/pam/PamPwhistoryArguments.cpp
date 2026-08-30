#include "modules/identity_access/pam/PamPwhistoryArguments.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <set>
#include <sstream>

#include <unistd.h>

namespace fic::identity::pam {
namespace {

bool parseUnsigned(const std::string& value, unsigned& result) {
    if (value.empty()) {
        return false;
    }
    const char* first = value.data();
    const char* last = first + value.size();
    const auto parsed = std::from_chars(first, last, result);
    return parsed.ec == std::errc{} && parsed.ptr == last;
}

bool asciiEqual(const std::string& left, const std::string& right) {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(),
                   [](unsigned char a, unsigned char b) {
                       return std::tolower(a) == std::tolower(b);
                   });
}

bool asciiPrefix(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() &&
        std::equal(prefix.begin(), prefix.end(), value.begin(),
                   [](unsigned char a, unsigned char b) {
                       return std::tolower(a) == std::tolower(b);
                   });
}

bool renderMutatedContent(const PamRule& expectedRule,
                          const PamProviderPolicyBinding& binding,
                          const std::string& expectedValue,
                          bool expectedFlagEnabled,
                          const std::string& original,
                          std::string& result,
                          std::string& error) {
    std::vector<PamRule> parsed;
    if (!PamConfiguration::parseRulesContent(
            expectedRule.source, original, parsed, error)) {
        return false;
    }
    const auto matches = [&](const PamRule& rule) {
        return rule.line == expectedRule.line &&
            rule.includeKind == PamIncludeKind::None &&
            rule.group == expectedRule.group &&
            rule.control == expectedRule.control &&
            rule.module == expectedRule.module &&
            rule.arguments == expectedRule.arguments;
    };
    const auto found = std::find_if(parsed.begin(), parsed.end(), matches);
    if (found == parsed.end() ||
        std::count_if(parsed.begin(), parsed.end(), matches) != 1) {
        error = "authoritative pam_pwhistory rule changed before mutation";
        return false;
    }

    std::vector<std::string> arguments;
    const std::string prefix = binding.option + "=";
    for (const auto& argument : found->arguments) {
        const bool managedAssignment =
            binding.syntax == PamNativeOptionSyntax::Assignment &&
            asciiPrefix(argument, prefix);
        const bool managedFlag =
            binding.syntax == PamNativeOptionSyntax::Flag &&
            asciiEqual(argument, binding.option);
        if (!managedAssignment && !managedFlag) {
            arguments.push_back(argument);
        }
    }
    if (binding.syntax == PamNativeOptionSyntax::Assignment) {
        arguments.push_back(binding.option + "=" + expectedValue);
    } else if (expectedFlagEnabled) {
        arguments.push_back(binding.option);
    }

    std::istringstream input(original);
    std::string physical;
    std::vector<std::string> lines;
    while (std::getline(input, physical)) {
        lines.push_back(physical);
    }
    if (expectedRule.line == 0 || expectedRule.line > lines.size()) {
        error = "authoritative pam_pwhistory rule line is out of range";
        return false;
    }
    const std::string& target = lines[expectedRule.line - 1];
    std::size_t trailingBackslashes = 0;
    for (auto it = target.rbegin(); it != target.rend() && *it == '\\'; ++it) {
        ++trailingBackslashes;
    }
    if ((trailingBackslashes % 2) != 0) {
        error = "continued pam_pwhistory rules are not safe to mutate";
        return false;
    }

    std::string group = pamManagementGroupName(found->group);
    const std::size_t first = target.find_first_not_of(" \t");
    const std::string suppressedGroup = "-" + group;
    if (first != std::string::npos &&
        target.compare(first, suppressedGroup.size(), suppressedGroup) == 0 &&
        first + suppressedGroup.size() < target.size() &&
        std::isspace(static_cast<unsigned char>(
            target[first + suppressedGroup.size()])) != 0) {
        group = suppressedGroup;
    }
    const std::size_t comment = target.find('#');
    std::size_t commentPrefix = comment;
    while (commentPrefix != std::string::npos && commentPrefix > first &&
           std::isspace(static_cast<unsigned char>(
               target[commentPrefix - 1])) != 0) {
        --commentPrefix;
    }
    std::string replacement = target.substr(0, first) + group + " " +
        found->control + " " + found->module;
    for (const auto& argument : arguments) {
        replacement += " " + argument;
    }
    if (comment != std::string::npos) {
        replacement += target.substr(commentPrefix);
    }
    lines[expectedRule.line - 1] = std::move(replacement);
    result.clear();
    const bool finalNewline = !original.empty() && original.back() == '\n';
    for (std::size_t index = 0; index < lines.size(); ++index) {
        result += lines[index];
        if (index + 1 < lines.size() || finalNewline) {
            result.push_back('\n');
        }
    }
    return true;
}

} // namespace

bool PamPwhistoryArguments::evaluate(
    const PamRule& rule,
    PamPwhistoryArgumentState& state,
    std::string& error) {
    state = PamPwhistoryArgumentState{};
    bool rememberSeen = false;
    bool useAuthtokSeen = false;
    bool enforceSeen = false;
    bool debugSeen = false;
    bool retrySeen = false;
    bool authtokTypeSeen = false;
    bool tryFirstPassSeen = false;
    bool useFirstPassSeen = false;
    for (const auto& argument : rule.arguments) {
        if (argument.empty() ||
            std::any_of(argument.begin(), argument.end(), [](unsigned char c) {
                return std::isspace(c) != 0 || c == '#' || c == '\\' ||
                    c == '\'' || c == '"';
            })) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": unsafe pam_pwhistory argument token";
            return false;
        }
        if (asciiEqual(argument, "use_authtok")) {
            if (useAuthtokSeen) {
                error = "duplicate pam_pwhistory argument use_authtok";
                return false;
            }
            useAuthtokSeen = true;
        } else if (asciiEqual(argument, "enforce_for_root")) {
            if (enforceSeen) {
                error = "duplicate pam_pwhistory argument enforce_for_root";
                return false;
            }
            enforceSeen = true;
            state.enforceForRoot = true;
        } else if (asciiPrefix(argument, "remember=")) {
            unsigned remember = 0;
            if (rememberSeen ||
                !parseUnsigned(argument.substr(9), remember)) {
                error = "invalid or duplicate pam_pwhistory remember argument";
                return false;
            }
            rememberSeen = true;
            state.rememberOverride = remember;
        } else if (asciiEqual(argument, "debug")) {
            if (debugSeen) {
                error = "duplicate pam_pwhistory argument debug";
                return false;
            }
            debugSeen = true;
        } else if (asciiPrefix(argument, "retry=")) {
            unsigned retry = 0;
            if (retrySeen || !parseUnsigned(argument.substr(6), retry)) {
                error = "invalid or duplicate pam_pwhistory retry argument";
                return false;
            }
            retrySeen = true;
        } else if (asciiPrefix(argument, "authtok_type=") &&
                   argument.size() > 13) {
            if (authtokTypeSeen) {
                error = "duplicate pam_pwhistory authtok_type argument";
                return false;
            }
            authtokTypeSeen = true;
        } else if (asciiEqual(argument, "try_first_pass")) {
            if (tryFirstPassSeen) {
                error = "duplicate pam_pwhistory argument try_first_pass";
                return false;
            }
            tryFirstPassSeen = true;
        } else if (asciiEqual(argument, "use_first_pass")) {
            if (useFirstPassSeen) {
                error = "duplicate pam_pwhistory argument use_first_pass";
                return false;
            }
            useFirstPassSeen = true;
        } else {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": unsupported pam_pwhistory argument " + argument;
            return false;
        }
    }
    if (!useAuthtokSeen) {
        error = rule.source.string() + ":" + std::to_string(rule.line) +
            ": pam_pwhistory requires use_authtok";
        return false;
    }
    error.clear();
    return true;
}

bool PamPwhistoryArguments::uniqueRule(
    const PamProviderInspection& inspection,
    PamRule& rule,
    std::string& error) {
    std::set<std::pair<std::filesystem::path, std::size_t>> identities;
    for (const auto& candidate : inspection.providerRules) {
        identities.emplace(candidate.source, candidate.line);
        rule = candidate;
    }
    if (identities.size() != 1) {
        error = "legacy pam_pwhistory topology does not have one authoritative rule";
        return false;
    }
    PamPwhistoryArgumentState state;
    return evaluate(rule, state, error);
}

bool PamPwhistoryArguments::hasExpectedState(
    const PamProviderInspection& inspection,
    const PamProviderPolicyBinding& binding,
    const std::string& expectedValue,
    bool expectedFlagEnabled,
    std::string& error) {
    for (const auto& rule : inspection.providerRules) {
        PamPwhistoryArgumentState state;
        if (!evaluate(rule, state, error)) {
            return false;
        }
        if (binding.option == "remember") {
            unsigned expected = 0;
            if (!parseUnsigned(expectedValue, expected) ||
                state.effectiveRemember() != expected) {
                error = "effective pam_pwhistory remember does not match requested value";
                return false;
            }
        } else if (binding.option == "enforce_for_root") {
            if (state.enforceForRoot != expectedFlagEnabled) {
                error = "effective pam_pwhistory enforce_for_root does not match requested state";
                return false;
            }
        } else {
            error = "unsupported managed pam_pwhistory argument " + binding.option;
            return false;
        }
    }
    error.clear();
    return true;
}

bool PamPwhistoryArguments::setExpectedState(
    const PamRule& rule,
    const PamProviderPolicyBinding& binding,
    const std::string& expectedValue,
    bool expectedFlagEnabled,
    PamConfigFileSnapshot& snapshot,
    std::string& error) {
    return PamConfigFileTransaction::mutate(
        snapshot,
        [&](const PamConfigFileTransaction::Writer& writer,
            std::string& mutationError) {
            std::string content;
            if (!renderMutatedContent(
                    rule, binding, expectedValue, expectedFlagEnabled,
                    snapshot.content, content, mutationError)) {
                return false;
            }
            AtomicWriteOptions options;
            options.createIfMissing = false;
            options.rejectSymlink = true;
            options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
            return writer(
                snapshot.path.string(), content, options, &mutationError);
        },
        error);
}

} // namespace fic::identity::pam
