#include "modules/identity_access/pam/PamProviderInspector.h"

#include "modules/identity_access/pam/PamProviderCatalog.h"

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>

#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

std::string moduleBaseName(const PamRule& rule) {
    return std::filesystem::path(rule.module).filename().string();
}

std::optional<PamProviderKind> providerForRule(
    const PamRule& rule,
    PamCapability capability) {
    const std::string module = moduleBaseName(rule);
    return pamProviderForModule(
        capability, module,
        PamProviderInspector::argumentValue(rule, "remember").has_value());
}

bool inspectFaillockTopology(const std::vector<PamRule>& authRules,
                            const std::vector<PamRule>& accountRules,
                            std::string& error,
                            const std::string& service) {
    std::size_t preauth = 0;
    std::size_t authfail = 0;
    std::size_t authsucc = 0;
    std::size_t rolelessAuth = 0;
    std::size_t account = 0;

    for (const auto& rule : authRules) {
        if (moduleBaseName(rule) != "pam_faillock.so") {
            continue;
        }
        const bool isPreauth =
            std::find(rule.arguments.begin(), rule.arguments.end(), "preauth") !=
            rule.arguments.end();
        const bool isAuthfail =
            std::find(rule.arguments.begin(), rule.arguments.end(), "authfail") !=
            rule.arguments.end();
        const bool isAuthsucc =
            std::find(rule.arguments.begin(), rule.arguments.end(), "authsucc") !=
            rule.arguments.end();
        preauth += isPreauth ? 1 : 0;
        authfail += isAuthfail ? 1 : 0;
        authsucc += isAuthsucc ? 1 : 0;
        rolelessAuth += !isPreauth && !isAuthfail && !isAuthsucc ? 1 : 0;
    }
    for (const auto& rule : accountRules) {
        account += moduleBaseName(rule) == "pam_faillock.so" ? 1 : 0;
    }

    const bool authSuccessTopology =
        authfail == 1 && authsucc == 1 && preauth <= 1 && account == 0;
    const bool accountTopology =
        authfail == 1 && authsucc == 0 && preauth == 1 && account == 1;
    if (rolelessAuth != 0 || (!authSuccessTopology && !accountTopology)) {
        error =
            "incomplete pam_faillock topology for PAM service " + service +
            ": expected one authfail plus one authsucc, or one preauth, "
            "one authfail and one account call; duplicate calls are rejected";
        return false;
    }
    return true;
}

bool uniqueArgumentValue(const PamRule& rule,
                         const std::string& option,
                         std::optional<std::string>& value,
                         std::string& error)
{
    value.reset();
    const std::string prefix = option + "=";
    for (const auto& argument : rule.arguments) {
        if (argument == option) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": PAM argument " + option +
                " requires an assigned value";
            return false;
        }
        if (argument.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        if (value.has_value()) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": duplicate PAM argument " +
                option;
            return false;
        }
        value = argument.substr(prefix.size());
    }
    return true;
}

} // namespace

bool PamProviderInspector::inspect(
    PamConfiguration& configuration,
    const std::vector<std::string>& candidateServices,
    PamCapability capability,
    PamProviderKind expectedProvider,
    PamProviderInspection& inspection,
    std::string& error,
    PamProviderInspectionFailure* failure) {
    error.clear();
    inspection = PamProviderInspection{};
    inspection.provider = expectedProvider;
    if (failure != nullptr) {
        *failure = PamProviderInspectionFailure::None;
    }
    std::vector<std::string> services;
    if (!configuration.existingServices(
            candidateServices, services, error)) {
        if (failure != nullptr) {
            *failure = PamProviderInspectionFailure::Broken;
        }
        return false;
    }
    if (services.empty()) {
        error = "none of the configured PAM services exists";
        if (failure != nullptr) {
            *failure = PamProviderInspectionFailure::Broken;
        }
        return false;
    }

    std::set<std::filesystem::path> configurationFiles;
    for (const auto& service : services) {
        std::vector<PamRule> primaryRules;
        const PamManagementGroup primaryGroup =
            capability == PamCapability::AuthenticationLockout
                ? PamManagementGroup::Auth
                : PamManagementGroup::Password;
        if (!configuration.collectRules(
                service,
                primaryGroup,
                primaryRules,
                error,
                &configurationFiles)) {
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Broken;
            }
            return false;
        }

        std::vector<PamRule> accountRules;
        if (capability == PamCapability::AuthenticationLockout &&
            !configuration.collectRules(
                service,
                PamManagementGroup::Account,
                accountRules,
                error,
                &configurationFiles)) {
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Broken;
            }
            return false;
        }

        std::map<PamProviderKind, std::vector<PamRule>> providers;
        for (const auto& rule : primaryRules) {
            const auto provider = providerForRule(rule, capability);
            if (provider.has_value()) {
                providers[*provider].push_back(rule);
            }
        }
        for (const auto& rule : accountRules) {
            const auto provider = providerForRule(rule, capability);
            if (provider.has_value()) {
                providers[*provider].push_back(rule);
            }
        }

        if (providers.empty()) {
            error = "PAM service " + service +
                " does not contain a provider for the requested capability";
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Inactive;
            }
            return false;
        }
        if (providers.size() != 1) {
            std::string names;
            for (const auto& [provider, unused] : providers) {
                if (!names.empty()) {
                    names += ", ";
                }
                names += pamProviderName(provider);
            }
            error = "conflicting PAM providers for service " + service +
                ": " + names;
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Conflicting;
            }
            return false;
        }

        const auto& [provider, rules] = *providers.begin();
        if (provider != expectedProvider) {
            error = "PAM service " + service + " uses unsupported provider " +
                pamProviderName(provider) + "; expected " +
                pamProviderName(expectedProvider);
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Broken;
            }
            return false;
        }
        if (expectedProvider == PamProviderKind::PamFaillock &&
            !inspectFaillockTopology(
                primaryRules, accountRules, error, service)) {
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Broken;
            }
            return false;
        }
        if (expectedProvider != PamProviderKind::PamFaillock &&
            rules.size() != 1) {
            error = "ambiguous " + pamProviderName(expectedProvider) +
                " topology for PAM service " + service +
                ": expected exactly one provider call";
            if (failure != nullptr) {
                *failure = PamProviderInspectionFailure::Broken;
            }
            return false;
        }

        inspection.services.push_back(service);
        inspection.providerRules.insert(
            inspection.providerRules.end(), rules.begin(), rules.end());
    }
    inspection.configurationFiles.assign(
        configurationFiles.begin(), configurationFiles.end());
    return true;
}

PamProviderFileState PamProviderInspector::inspectExpectedProviderFile(
    PamProviderKind provider,
    const std::vector<std::filesystem::path>& moduleDirectories,
    std::string& error) {
    const std::string module = pamProviderModuleName(provider);
    for (const auto& directory : moduleDirectories) {
        const auto candidate = directory / module;
        struct stat info {};
        if (::stat(candidate.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
            continue;
        }
        if (info.st_uid != ::geteuid()) {
            error = "PAM provider is not owned by the daemon owner: " +
                candidate.string();
            return PamProviderFileState::Untrusted;
        }
        if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "PAM provider is writable by group or others: " +
                candidate.string();
            return PamProviderFileState::Untrusted;
        }
        error.clear();
        return PamProviderFileState::Trusted;
    }
    error = "PAM provider file was not found for " + module;
    return PamProviderFileState::Missing;
}

bool PamProviderInspector::verifyExternalConfigContract(
    const PamProviderInspection& inspection,
    const std::string& expectedConfigPath,
    std::string& error)
{
    error.clear();
    const auto& descriptor = pamProviderDescriptor(inspection.provider);
    if (descriptor.externalConfigMode == PamExternalConfigMode::None) {
        return true;
    }
    const std::filesystem::path expected(expectedConfigPath);
    if (!expected.is_absolute() || expected != expected.lexically_normal()) {
        error = "managed PAM configuration path is not absolute and normalized";
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        std::optional<std::string> configuredPath;
        if (!uniqueArgumentValue(
                rule, descriptor.externalConfigArgument,
                configuredPath, error)) {
            return false;
        }
        if (!configuredPath.has_value()) {
            if (descriptor.externalConfigMode ==
                PamExternalConfigMode::Required) {
                error = rule.source.string() + ":" +
                    std::to_string(rule.line) + ": provider requires PAM " +
                    descriptor.externalConfigArgument + "=" +
                    expected.string();
                return false;
            }
            continue;
        }
        const std::filesystem::path configured(*configuredPath);
        if (!configured.is_absolute() ||
            configured != configured.lexically_normal()) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": provider configuration path is not absolute and normalized: " +
                *configuredPath;
            return false;
        }
        if (configured != expected) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": provider uses another configuration file: " +
                *configuredPath;
            return false;
        }
    }
    return true;
}

bool PamProviderInspector::verifyOptionOverrides(
    const PamProviderInspection& inspection,
    const std::string& expectedConfigPath,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error) {
    error.clear();
    if (!verifyExternalConfigContract(
            inspection, expectedConfigPath, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        std::optional<std::string> overrideValue;
        if (!uniqueArgumentValue(rule, option, overrideValue, error)) {
            return false;
        }
        if (overrideValue.has_value() && *overrideValue != expectedValue) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": PAM argument " + option + "=" + *overrideValue +
                " overrides the requested value " + expectedValue;
            return false;
        }
    }
    return true;
}

bool PamProviderInspector::verifyFlagOverrides(
    const PamProviderInspection& inspection,
    const std::string& expectedConfigPath,
    const std::string& flag,
    bool expectedEnabled,
    std::string& error,
    const std::vector<std::string>& conflictingOptionsWhenDisabled) {
    error.clear();
    const std::string assignmentPrefix = flag + "=";
    if (!verifyExternalConfigContract(
            inspection, expectedConfigPath, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        std::size_t flagOccurrences = 0;
        for (const auto& argument : rule.arguments) {
            flagOccurrences += argument == flag ? 1U : 0U;
            if (argument.compare(0, assignmentPrefix.size(),
                                 assignmentPrefix) == 0) {
                error = rule.source.string() + ":" +
                    std::to_string(rule.line) + ": PAM flag " + flag +
                    " must not have a value";
                return false;
            }
        }
        if (flagOccurrences > 1) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": duplicate PAM flag " + flag;
            return false;
        }
        if (!expectedEnabled && hasArgument(rule, flag)) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": PAM argument " + flag +
                " overrides the requested disabled state";
            return false;
        }
        if (!expectedEnabled) {
            for (const auto& option : conflictingOptionsWhenDisabled) {
                if (hasArgument(rule, option) ||
                    argumentValue(rule, option).has_value()) {
                    error = rule.source.string() + ":" +
                        std::to_string(rule.line) + ": PAM argument " +
                        option +
                        " conflicts with the requested disabled state";
                    return false;
                }
            }
        }
    }
    return true;
}

bool PamProviderInspector::verifyProviderFiles(
    const PamProviderInspection& inspection,
    const std::vector<std::filesystem::path>& moduleDirectories,
    std::string& error) {
    std::set<std::string> checkedModules;
    for (const auto& rule : inspection.providerRules) {
        if (!checkedModules.insert(rule.module).second) {
            continue;
        }

        std::vector<std::filesystem::path> candidates;
        const std::filesystem::path configuredPath(rule.module);
        if (configuredPath.is_absolute()) {
            candidates.push_back(configuredPath);
        } else {
            for (const auto& directory : moduleDirectories) {
                candidates.push_back(directory / configuredPath);
            }
        }

        bool found = false;
        for (const auto& candidate : candidates) {
            struct stat info {};
            if (::stat(candidate.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
                continue;
            }
            if (info.st_uid != ::geteuid()) {
                error = "PAM provider is not owned by the daemon owner: " +
                    candidate.string();
                return false;
            }
            if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
                error = "PAM provider is writable by group or others: " +
                    candidate.string();
                return false;
            }
            found = true;
            break;
        }
        if (!found) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": PAM provider file was not found for " + rule.module;
            return false;
        }
    }
    return true;
}

bool PamProviderInspector::verifyConfigurationFiles(
    const PamProviderInspection& inspection,
    std::string& error) {
    for (const auto& path : inspection.configurationFiles) {
        struct stat info {};
        if (::stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
            error = "PAM configuration source is not a regular file: " +
                path.string();
            return false;
        }
        if (info.st_uid != ::geteuid()) {
            error = "PAM configuration source is not owned by the daemon owner: " +
                path.string();
            return false;
        }
        if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "PAM configuration source is writable by group or others: " +
                path.string();
            return false;
        }
    }
    return true;
}

std::optional<std::string> PamProviderInspector::argumentValue(
    const PamRule& rule,
    const std::string& option) {
    const std::string prefix = option + "=";
    for (const auto& argument : rule.arguments) {
        if (argument.compare(0, prefix.size(), prefix) == 0) {
            return argument.substr(prefix.size());
        }
    }
    return std::nullopt;
}

bool PamProviderInspector::hasArgument(const PamRule& rule,
                                       const std::string& argument) {
    return std::find(
               rule.arguments.begin(), rule.arguments.end(), argument) !=
        rule.arguments.end();
}

std::string pamProviderName(PamProviderKind provider) {
    return pamProviderDescriptor(provider).name;
}

std::string pamProviderModuleName(PamProviderKind provider) {
    return pamProviderDescriptor(provider).moduleName;
}

} // namespace fic::identity::pam
