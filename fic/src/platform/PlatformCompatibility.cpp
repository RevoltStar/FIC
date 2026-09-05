#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <utility>

namespace fic::platform {
namespace {

std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    if (first >= last) {
        return "";
    }
    return std::string(first, last);
}

bool contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

std::string join(const std::vector<std::string>& values) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) {
            result += ", ";
        }
        result += value;
    }
    return result;
}

bool decodeValue(const std::string& encoded, std::string& value) {
    if (encoded.empty() || (encoded.front() != '"' && encoded.front() != '\'')) {
        value = encoded;
        return true;
    }

    const char quote = encoded.front();
    if (encoded.size() < 2 || encoded.back() != quote) {
        return false;
    }

    value.clear();
    for (size_t index = 1; index + 1 < encoded.size(); ++index) {
        const char ch = encoded[index];
        if (quote == '"' && ch == '\\' && index + 2 < encoded.size()) {
            const char escaped = encoded[++index];
            if (escaped == '"' || escaped == '\\' || escaped == '$' || escaped == '`') {
                value.push_back(escaped);
            } else {
                value.push_back('\\');
                value.push_back(escaped);
            }
            continue;
        }
        value.push_back(ch);
    }
    return true;
}

bool validAbsolutePath(const std::filesystem::path& path) {
    return path.is_absolute() && path == path.lexically_normal();
}

bool validateExecutableCandidates(
    const std::vector<std::filesystem::path>& candidates,
    const std::string& label,
    std::string& error) {
    if (candidates.empty()) {
        error = label + " candidates are empty";
        return false;
    }
    std::set<std::filesystem::path> uniqueCandidates;
    for (const std::filesystem::path& candidate : candidates) {
        if (!validAbsolutePath(candidate)) {
            error = label + " candidate must be an absolute normalized path: " +
                    candidate.string();
            return false;
        }
        if (!uniqueCandidates.insert(candidate).second) {
            error = label + " candidate is duplicated: " + candidate.string();
            return false;
        }
    }
    return true;
}

bool validateExecutables(const PlatformExecutables& executables,
                         std::string& error) {
    const std::vector<ExecutableId> supportedIds = allExecutableIds();
    std::set<ExecutableId> uniqueIds;
    for (const PlatformExecutableSpec& spec : executables.entries) {
        if (std::find(supportedIds.begin(), supportedIds.end(), spec.id) ==
            supportedIds.end()) {
            error = "platform profile contains an unsupported executable identifier";
            return false;
        }
        if (!uniqueIds.insert(spec.id).second) {
            error = std::string("executable is duplicated in platform profile: ") +
                    executableIdName(spec.id);
            return false;
        }
        if (!validateExecutableCandidates(
                spec.candidates, executableIdName(spec.id), error)) {
            return false;
        }
        if (spec.activeProviderSelector.empty() !=
            spec.providerExecutables.empty()) {
            error = std::string(executableIdName(spec.id)) +
                    " must define both active provider selector and provider mappings";
            return false;
        }
        if (!spec.activeProviderSelector.empty()) {
            if (!validAbsolutePath(spec.activeProviderSelector)) {
                error = std::string(executableIdName(spec.id)) +
                        " active provider selector must be an absolute normalized path";
                return false;
            }
            std::set<std::filesystem::path> providers;
            std::set<std::filesystem::path> mappedExecutables;
            for (const PlatformExecutableSpec::ProviderExecutable& mapping :
                 spec.providerExecutables) {
                if (!validAbsolutePath(mapping.provider) ||
                    !validAbsolutePath(mapping.executable)) {
                    error = std::string(executableIdName(spec.id)) +
                            " provider mapping paths must be absolute and normalized";
                    return false;
                }
                if (!providers.insert(mapping.provider).second ||
                    !mappedExecutables.insert(mapping.executable).second) {
                    error = std::string(executableIdName(spec.id)) +
                            " provider mapping is duplicated";
                    return false;
                }
                if (std::find(spec.candidates.begin(), spec.candidates.end(),
                              mapping.executable) == spec.candidates.end()) {
                    error = std::string(executableIdName(spec.id)) +
                            " provider executable is not listed as a candidate: " +
                            mapping.executable.string();
                    return false;
                }
            }
        }
    }
    for (const ExecutableId id : supportedIds) {
        const PlatformExecutableSpec* spec =
            findExecutableSpec(executables, id);
        if (spec == nullptr || !spec->required) {
            error = std::string("platform profile must define required executable: ") +
                    executableIdName(id);
            return false;
        }
    }
    return true;
}

bool validatePath(const std::filesystem::path& path,
                  const std::string& label,
                  std::string& error) {
    if (!validAbsolutePath(path)) {
        error = label + " must be an absolute normalized path";
        return false;
    }
    return true;
}

bool validatePaths(const std::vector<std::filesystem::path>& paths,
                   const std::string& label,
                   std::string& error) {
    if (paths.empty()) {
        error = label + " list is empty";
        return false;
    }
    for (const std::filesystem::path& path : paths) {
        if (!validatePath(path, label, error)) {
            return false;
        }
    }
    return true;
}

bool validatePamServices(const std::vector<std::string>& services,
                         const std::string& label,
                         std::string& error) {
    if (services.empty()) {
        error = label + " list is empty";
        return false;
    }

    std::set<std::string> uniqueServices;
    for (const std::string& service : services) {
        if (service.empty() ||
            !std::all_of(service.begin(), service.end(), [](unsigned char ch) {
                return std::isalnum(ch) != 0 || ch == '_' || ch == '-' || ch == '.';
            })) {
            error = label + " contains an invalid PAM service name: " + service;
            return false;
        }
        if (!uniqueServices.insert(service).second) {
            error = label + " contains a duplicated PAM service: " + service;
            return false;
        }
    }
    return true;
}

bool validateNssServiceContract(
    const std::vector<std::vector<std::string>>& alternatives,
    const std::string& database,
    std::string& error) {
    if (alternatives.empty()) {
        error = "passwordless-login NSS " + database +
            " contract has no supported service lists";
        return false;
    }
    std::set<std::vector<std::string>> unique;
    for (const auto& services : alternatives) {
        if (services.empty() || !unique.insert(services).second) {
            error = "invalid passwordless-login NSS " + database +
                " service-list contract";
            return false;
        }
        for (const std::string& service : services) {
            if (service.empty() ||
                service.find_first_of("[]=:, \t\r\n") != std::string::npos) {
                error = "invalid passwordless-login NSS service in " +
                    database + " contract";
                return false;
            }
        }
    }
    return true;
}

bool validatePamTrustedAuthenticationBypasses(
    const PamPlatformConfig& pam,
    std::string& error) {
    const auto authenticationScope = std::find_if(
        pam.scopes.begin(), pam.scopes.end(), [](const auto& scope) {
            return scope.scope == PamScope::EffectiveAuthenticationStack;
        });
    if (authenticationScope == pam.scopes.end()) {
        error = "effective PAM authentication scope is missing";
        return false;
    }
    std::set<std::pair<std::string, std::string>> uniqueRules;
    for (const auto& rule : pam.trustedAuthenticationBypasses) {
        if (!contains(authenticationScope->services, rule.service)) {
            error = "trusted PAM authentication bypass references an "
                "unverified service: " + rule.service;
            return false;
        }
        if (rule.module.empty() ||
            !std::all_of(
                rule.module.begin(), rule.module.end(), [](unsigned char ch) {
                    return std::isalnum(ch) != 0 || ch == '_' || ch == '-' ||
                        ch == '.';
                }) ||
            rule.module.find('/') != std::string::npos) {
            error = "trusted PAM authentication bypass contains an invalid "
                "module name: " + rule.module;
            return false;
        }
        switch (rule.reason) {
        case PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller:
            if (!rule.control.empty() || !rule.arguments.empty() ||
                rule.source.has_value()) {
                error = "already-privileged PAM bypass must not declare "
                    "exact-rule constraints";
                return false;
            }
            break;
        case PamTrustedAuthenticationBypassReason::ExplicitPasswordlessLogin: {
            const std::filesystem::path expectedSource =
                pam.configDirectories.front() / rule.service;
            if (rule.control != "sufficient" || rule.arguments.empty() ||
                !rule.source.has_value() ||
                !validatePath(*rule.source,
                              "trusted PAM bypass source", error) ||
                rule.source->lexically_normal() !=
                    expectedSource.lexically_normal()) {
                if (error.empty()) {
                    error = "explicit passwordless PAM bypass must declare "
                        "exact control, arguments, and service source";
                }
                return false;
            }
            if (!std::all_of(
                    rule.arguments.begin(), rule.arguments.end(),
                    [](const std::string& argument) {
                        return !argument.empty() &&
                            argument.find_first_of(" \t\r\n") ==
                                std::string::npos;
                    })) {
                error = "explicit passwordless PAM bypass contains an "
                    "invalid argument";
                return false;
            }
            break;
        }
        default:
            error = "trusted PAM authentication bypass contains an "
                "unsupported reason";
            return false;
        }
        if (!uniqueRules.emplace(rule.service, rule.module).second) {
            error = "trusted PAM authentication bypass is duplicated: " +
                rule.service + ":" + rule.module;
            return false;
        }
    }
    const auto& passwordless = pam.passwordlessLoginControl;
    const std::size_t explicitRuleCount = static_cast<std::size_t>(std::count_if(
        pam.trustedAuthenticationBypasses.begin(),
        pam.trustedAuthenticationBypasses.end(), [](const auto& rule) {
            return rule.reason ==
                PamTrustedAuthenticationBypassReason::ExplicitPasswordlessLogin;
        }));
    if (passwordless.has_value()) {
        if (passwordless->groupName.empty() ||
            passwordless->groupName.find_first_of(":, \t\r\n") !=
                std::string::npos ||
            !validAbsolutePath(passwordless->passwdPath) ||
            !validAbsolutePath(passwordless->groupPath) ||
            !validAbsolutePath(passwordless->nsswitchPath) ||
            passwordless->passwdPath != "/etc/passwd" ||
            passwordless->groupPath != "/etc/group" ||
            passwordless->nsswitchPath != "/etc/nsswitch.conf") {
            error = "invalid passwordless-login enforcement metadata";
            return false;
        }
        if (!validateNssServiceContract(
                passwordless->supportedNss.passwd, "passwd", error) ||
            !validateNssServiceContract(
                passwordless->supportedNss.group, "group", error) ||
            !validateNssServiceContract(
                passwordless->supportedNss.initgroups, "initgroups", error)) {
            return false;
        }
        const bool allExplicitRulesMatch = std::all_of(
            pam.trustedAuthenticationBypasses.begin(),
            pam.trustedAuthenticationBypasses.end(),
            [&](const auto& rule) {
                return rule.reason != PamTrustedAuthenticationBypassReason::
                           ExplicitPasswordlessLogin ||
                    rule.arguments == std::vector<std::string>{
                        "user", "ingroup", passwordless->groupName};
            });
        if (explicitRuleCount == 0 || !allExplicitRulesMatch) {
            error = "passwordless-login control does not match an exact "
                "trusted PAM bypass";
            return false;
        }
    } else if (explicitRuleCount != 0) {
        error = "explicit passwordless PAM bypass has no enforcement metadata";
        return false;
    }
    return true;
}

bool validatePamTrustedServiceAliases(const PamPlatformConfig& pam,
                                      std::string& error) {
    std::set<std::filesystem::path> aliases;
    for (const auto& alias : pam.trustedServiceAliases) {
        if (!validAbsolutePath(alias.aliasPath) ||
            std::find(pam.configDirectories.begin(),
                      pam.configDirectories.end(),
                      alias.aliasPath.parent_path()) ==
                pam.configDirectories.end()) {
            error = "trusted PAM service alias must be a normalized path "
                "inside a declared PAM configuration directory: " +
                alias.aliasPath.string();
            return false;
        }
        if (!aliases.insert(alias.aliasPath).second) {
            error = "trusted PAM service alias is duplicated: " +
                alias.aliasPath.string();
            return false;
        }
        if (alias.allowedTargets.empty()) {
            error = "trusted PAM service alias target allowlist is empty: " +
                alias.aliasPath.string();
            return false;
        }
        std::set<std::filesystem::path> targets;
        for (const auto& target : alias.allowedTargets) {
            if (!validAbsolutePath(target) ||
                target.parent_path() != alias.aliasPath.parent_path() ||
                target == alias.aliasPath) {
                error = "trusted PAM service alias target must be a distinct "
                    "normalized path in the alias directory: " +
                    target.string();
                return false;
            }
            if (!targets.insert(target).second) {
                error = "trusted PAM service alias target is duplicated: " +
                    target.string();
                return false;
            }
        }
    }
    return true;
}

bool validatePamProviderConfigTopology(
    const PamCapabilityConfig& capability,
    const fic::identity::pam::PamProviderDescriptor& provider,
    std::string& error)
{
    const PamProviderConfigTopology& topology =
        capability.configTopology.has_value()
        ? *capability.configTopology
        : provider.defaultConfigTopology;

    switch (topology.precedence) {
    case PamConfigPrecedence::DropInsThenPrimary:
        break;
    default:
        error = "PAM provider configuration topology has unsupported "
            "precedence";
        return false;
    }
    switch (topology.explicitConfig) {
    case PamExplicitConfigSemantics::Unsupported:
        break;
    case PamExplicitConfigSemantics::ReplacesNativeTopology:
        if (provider.externalConfigMode ==
                fic::identity::pam::PamExternalConfigMode::None ||
            provider.externalConfigArgument[0] == '\0') {
            error = "PAM provider topology declares explicit config "
                "replacement without a supported config argument";
            return false;
        }
        break;
    default:
        error = "PAM provider configuration topology has unsupported "
            "explicit config semantics";
        return false;
    }

    if (capability.configTopology.has_value() &&
        topology.explicitConfig !=
            provider.defaultConfigTopology.explicitConfig) {
        error = "PAM provider topology override changes provider-owned "
            "explicit config semantics";
        return false;
    }

    std::set<std::filesystem::path> filePaths;
    if (topology.primaryPath.has_value()) {
        if (!validAbsolutePath(*topology.primaryPath)) {
            error = "PAM topology primary path must be an absolute "
                "normalized path";
            return false;
        }
        if (*topology.primaryPath != capability.configPath) {
            error = "PAM topology primary path does not match the managed "
                "provider configuration path";
            return false;
        }
        filePaths.insert(*topology.primaryPath);
    } else if (!topology.fallbackPaths.empty() ||
               !topology.dropInDirectories.empty()) {
        error = "PAM provider topology cannot declare fallback or drop-in "
            "paths without a primary path";
        return false;
    }

    for (const auto& fallback : topology.fallbackPaths) {
        if (!validAbsolutePath(fallback)) {
            error = "PAM topology fallback path must be an absolute "
                "normalized path";
            return false;
        }
        if (!filePaths.insert(fallback).second) {
            error = "PAM topology file path is duplicated: " +
                fallback.string();
            return false;
        }
    }

    std::set<std::filesystem::path> dropInPaths;
    for (const auto& directory : topology.dropInDirectories) {
        if (!validAbsolutePath(directory)) {
            error = "PAM topology drop-in directory must be an absolute "
                "normalized path";
            return false;
        }
        if (filePaths.find(directory) != filePaths.end()) {
            error = "PAM topology path cannot be both a file and a drop-in "
                "directory: " + directory.string();
            return false;
        }
        if (!dropInPaths.insert(directory).second) {
            error = "PAM topology drop-in directory is duplicated: " +
                directory.string();
            return false;
        }
    }

    if (provider.semanticBackend ==
        fic::identity::pam::PamProviderSemanticBackendKind::Pwquality) {
        if (!topology.primaryPath.has_value() ||
            topology.explicitConfig !=
                PamExplicitConfigSemantics::Unsupported ||
            topology.precedence != PamConfigPrecedence::DropInsThenPrimary) {
            error = "pam_pwquality platform topology is incompatible with "
                "the target semantic backend";
            return false;
        }
    }
    return true;
}

bool validatePamComposition(const PamPlatformConfig& pam,
                            std::string& error) {
    if (pam.scopes.empty() || pam.capabilities.empty()) {
        error = "PAM scope and capability composition must not be empty";
        return false;
    }
    std::set<PamScope> scopes;
    for (const auto& scope : pam.scopes) {
        if (!scopes.insert(scope.scope).second) {
            error = "PAM scope is duplicated";
            return false;
        }
        if (!validatePamServices(scope.services, "PAM scope service", error)) {
            return false;
        }
    }

    std::set<PamCapability> capabilities;
    std::set<std::filesystem::path> configPaths;
    for (const auto& capability : pam.capabilities) {
        if (!capabilities.insert(capability.capability).second) {
            error = "PAM capability is duplicated";
            return false;
        }
        if (scopes.find(capability.scope) == scopes.end()) {
            error = "PAM capability references an undefined scope";
            return false;
        }
        if ((capability.capability == PamCapability::AuthenticationLockout) !=
            (capability.scope == PamScope::EffectiveAuthenticationStack)) {
            error = "PAM capability references an incompatible service scope";
            return false;
        }
        const auto& provider =
            fic::identity::pam::pamProviderDescriptor(capability.provider);
        if (provider.capability != capability.capability) {
            error = "PAM provider does not implement its declared capability";
            return false;
        }
        switch (capability.subjectScope) {
        case PamIdentitySubjectScope::AllPamSubjects:
            break;
        case PamIdentitySubjectScope::LocalUsersOnly:
            if (capability.capability != PamCapability::PasswordQuality) {
                error = "local-only PAM subject scope is only supported for "
                    "password-quality capability";
                return false;
            }
            break;
        default:
            error = "PAM capability has an unsupported identity subject scope";
            return false;
        }
        switch (capability.configurationMode) {
        case PamCapabilityConfigurationMode::ProviderConfigFile:
            if (!validatePath(
                    capability.configPath, "PAM provider configuration path",
                    error) ||
                !validatePamProviderConfigTopology(
                    capability, provider, error)) {
                return false;
            }
            if (!configPaths.insert(capability.configPath).second) {
                error = "PAM provider configuration path is shared by multiple "
                    "capabilities";
                return false;
            }
            break;
        case PamCapabilityConfigurationMode::ModuleArguments:
            if (capability.provider != PamProviderKind::PamPwhistory ||
                capability.capability != PamCapability::PasswordHistory) {
                error = "PAM module-argument configuration is only supported "
                    "for pam_pwhistory";
                return false;
            }
            if (!capability.configPath.empty() ||
                capability.configTopology.has_value()) {
                error = "PAM module-argument configuration must not declare "
                    "an external provider configuration path or topology";
                return false;
            }
            break;
        default:
            error = "PAM capability has an unsupported configuration mode";
            return false;
        }
        if (capability.topology == PamTopologyStrategyKind::AltTcbManaged) {
            if (capability.capability == PamCapability::AuthenticationLockout) {
                if (!capability.topologyTarget.empty()) {
                    error = "ALT managed pam_faillock must use typed topology "
                        "targets instead of a singular topology target";
                    return false;
                }
                if (capability.managedTopologyTargets.empty()) {
                    error = "ALT managed pam_faillock topology target list is empty";
                    return false;
                }
                std::set<std::filesystem::path> targetPaths;
                std::size_t accountTargets = 0;
                for (const auto& target : capability.managedTopologyTargets) {
                    if (!validatePath(
                            target.path, "PAM managed topology target", error)) {
                        return false;
                    }
                    if (!targetPaths.insert(target.path).second) {
                        error = "PAM managed topology target is duplicated: " +
                            target.path.string();
                        return false;
                    }
                    switch (target.role) {
                    case PamManagedTopologyTargetRole::Authentication:
                        break;
                    case PamManagedTopologyTargetRole::AuthenticationAndAccount:
                        ++accountTargets;
                        break;
                    default:
                        error = "PAM managed topology target has an unsupported role";
                        return false;
                    }
                }
                if (accountTargets != 1) {
                    error = "ALT managed pam_faillock requires exactly one "
                        "authentication-and-account target";
                    return false;
                }
            } else {
                if (!validatePath(
                        capability.topologyTarget, "PAM topology target", error)) {
                    return false;
                }
                if (!capability.managedTopologyTargets.empty()) {
                    error = "typed PAM managed topology targets are only supported "
                        "for authentication lockout";
                    return false;
                }
            }
        } else if (!capability.topologyTarget.empty() ||
                   !capability.managedTopologyTargets.empty()) {
            error = "PAM topology target metadata is set for a strategy that "
                "does not manage a target";
            return false;
        }
    }
    return true;
}

bool validateArguments(const std::vector<std::string>& arguments,
                       const std::string& label,
                       std::string& error) {
    for (const std::string& argument : arguments) {
        if (argument.empty() || argument.find_first_of("\r\n") !=
                std::string::npos || argument.find('\0') != std::string::npos) {
            error = label + " contains an invalid argument";
            return false;
        }
    }
    return true;
}

bool validateFileAccessRules(const std::vector<FileAccessRule>& rules,
                             const std::string& label,
                             std::string& error) {
    if (rules.empty()) {
        error = label + " list is empty";
        return false;
    }
    std::set<std::filesystem::path> uniquePaths;
    for (const FileAccessRule& rule : rules) {
        if (!validatePath(rule.path, label + " path", error)) {
            return false;
        }
        if (rule.owner.empty() || rule.group.empty()) {
            error = label + " owner and group must not be empty: " +
                    rule.path.string();
            return false;
        }
        if (rule.permissions == 0 || (rule.permissions & ~07777U) != 0) {
            error = label + " permissions are invalid: " + rule.path.string();
            return false;
        }
        if (!uniquePaths.insert(rule.path).second) {
            error = label + " path is duplicated: " + rule.path.string();
            return false;
        }
        std::set<std::filesystem::path> uniqueSymlinkTargets;
        for (const std::filesystem::path& target :
             rule.allowedFinalSymlinkTargets) {
            if (!validAbsolutePath(target)) {
                error = label +
                    " allowed final symlink target must be a non-empty "
                    "absolute normalized path: " + target.string();
                return false;
            }
            if (!uniqueSymlinkTargets.insert(target).second) {
                error = label + " allowed final symlink target is duplicated: " +
                    target.string();
                return false;
            }
        }
        for (const ProviderManagedFileTarget& target :
             rule.providerManagedFinalSymlinkTargets) {
            if (!validAbsolutePath(target.path)) {
                error = label +
                    " provider-managed final symlink target must be a non-empty "
                    "absolute normalized path: " + target.path.string();
                return false;
            }
            if (!uniqueSymlinkTargets.insert(target.path).second) {
                error = label + " final symlink target is duplicated: " +
                    target.path.string();
                return false;
            }
            switch (target.provider) {
            case ManagedFileProvider::SystemdResolved:
            case ManagedFileProvider::NetworkManager:
            case ManagedFileProvider::Resolvconf:
                break;
            default:
                error = label + " has an invalid managed-file provider: " +
                    rule.path.string();
                return false;
            }
        }
    }
    return true;
}

bool validateSecurePathDefault(const std::string& value, std::string& error) {
    if (value.empty()) {
        error = "sudo secure_path default is empty";
        return false;
    }
    std::size_t begin = 0;
    while (begin <= value.size()) {
        const std::size_t end = value.find(':', begin);
        const std::string component = value.substr(
            begin, end == std::string::npos ? std::string::npos : end - begin);
        const std::filesystem::path path(component);
        if (component.empty() || component.find("//") != std::string::npos ||
            (component.size() > 1 && component.back() == '/') ||
            !validAbsolutePath(path)) {
            error = "sudo secure_path default contains an invalid path: " +
                component;
            return false;
        }
        for (const auto& pathComponent : path) {
            if (pathComponent == "." || pathComponent == "..") {
                error = "sudo secure_path default contains a dot component: " +
                    component;
                return false;
            }
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    return true;
}

bool validateTcbCredentialStorage(
    const std::optional<TcbCredentialStorageConfig>& optionalConfig,
    std::string& error) {
    if (!optionalConfig) {
        return true;
    }
    const TcbCredentialStorageConfig& config = *optionalConfig;
    if (!validatePath(config.rootPath, "TCB credential root", error)) {
        return false;
    }
    if (config.rootOwner.empty() || config.rootGroup.empty() ||
        config.entryGroup.empty() || config.rootPermissions == 0 ||
        (config.rootPermissions & ~07777U) != 0 ||
        config.entryDirectoryPermissions == 0 ||
        (config.entryDirectoryPermissions & ~07777U) != 0 ||
        config.files.empty()) {
        error = "invalid TCB credential storage metadata";
        return false;
    }
    std::set<std::string> names;
    bool hasRequiredFile = false;
    for (const TcbCredentialFileRule& file : config.files) {
        if (file.name.empty() || file.name == "." || file.name == ".." ||
            file.name.find('/') != std::string::npos ||
            file.permissions == 0 || (file.permissions & ~07777U) != 0 ||
            !names.insert(file.name).second) {
            error = "invalid TCB credential file metadata";
            return false;
        }
        hasRequiredFile = hasRequiredFile || file.required;
    }
    if (!hasRequiredFile) {
        error = "TCB credential storage has no required credential file";
        return false;
    }
    return true;
}

} // namespace

bool validatePlatformProfile(const PlatformProfile& profile, std::string& error) {
    if (profile.id.empty() || profile.displayName.empty()) {
        error = "platform id and display name must not be empty";
        return false;
    }
    if (profile.hostCompatibility.osIds.empty()) {
        error = "platform profile must declare at least one compatible os-release ID";
        return false;
    }
    if (!validatePath(profile.ssh.configPath, "SSH configuration path", error)) {
        return false;
    }
    if (!profile.ssh.includeBasePath.empty() &&
        !validAbsolutePath(profile.ssh.includeBasePath)) {
        error = "SSH Include base path must be absolute and normalized";
        return false;
    }
    if (!validateExecutables(profile.executables, error)) {
        return false;
    }
    if (!validateExecutableCandidates(
            profile.packageManager.queryCandidates,
            "package manager query executable",
            error)) {
        return false;
    }
    if (profile.ssh.serviceUnits.empty()) {
        error = "SSH service unit list is empty";
        return false;
    }
    if (!validatePath(profile.sudo.mainConfigPath, "sudoers main path", error) ||
        !validatePath(profile.sudo.managedConfigPath, "sudoers managed path", error) ||
        !validateSecurePathDefault(profile.sudo.securePathDefault, error) ||
        !validatePath(profile.sysctl.managedConfigPath, "sysctl managed path", error) ||
        !validatePaths(profile.pam.configDirectories,
                       "PAM configuration directory", error) ||
        !validatePaths(profile.pam.moduleDirectories,
                       "PAM module directory", error) ||
        !validatePamComposition(profile.pam, error) ||
        !validatePamTrustedServiceAliases(profile.pam, error) ||
        !validatePamTrustedAuthenticationBypasses(profile.pam, error) ||
        !validatePath(profile.passwordAging.loginDefsPath,
                      "login.defs path", error) ||
        !validatePath(profile.passwordAging.passwdPath,
                      "local passwd path", error) ||
        !validatePath(profile.passwordAging.shadowPath,
                      "local shadow path", error) ||
        !validatePath(profile.passwordAging.tcbDirectory,
                      "local TCB directory", error) ||
        !validatePath(profile.userCreation.useraddDefaultsPath,
                      "useradd defaults path", error) ||
        !validatePath(profile.userCreation.loginDefsPath,
                      "user-creation login.defs path", error) ||
        !validatePath(profile.userCreation.passwdPath,
                      "user-creation local passwd path", error) ||
        !validatePath(profile.userCreation.groupPath,
                      "user-creation local group path", error) ||
        !validatePath(profile.userCreation.shellsPath,
                      "user-creation shells path", error) ||
        !validatePath(profile.displayManager.sddmConfigPath,
                      "SDDM configuration path", error) ||
        !validatePath(profile.displayManager.lightDmConfigPath,
                      "LightDM configuration path", error) ||
        !validatePaths(profile.displayManager.gdmConfigCandidates,
                       "GDM configuration path", error) ||
        !validatePath(profile.grub.defaultsPath,
                      "GRUB defaults path", error) ||
        !validateArguments(profile.grub.rebuildArguments,
                           "GRUB rebuild arguments", error) ||
        !validateFileAccessRules(profile.dac.protectedSystemFiles,
                                 "DAC protected system file", error) ||
        !validateFileAccessRules(profile.dac.protectedSystemCommands,
                                 "DAC protected system command", error) ||
        !validateTcbCredentialStorage(profile.dac.tcbCredentialStorage,
                                      error)) {
        return false;
    }
    const PasswordAgingPolicyDefaults& aging =
        profile.passwordAging.policyDefaults;
    if (aging.minDays < 0 || aging.maxDays < -1 || aging.warningDays < -1 ||
        (aging.maxDays != -1 && aging.minDays > aging.maxDays) ||
        aging.uidMax < aging.uidMin) {
        error = "invalid password-aging platform defaults";
        return false;
    }
    const PasswordAgingMissingKeySemantics& missing =
        profile.passwordAging.missingKeySemantics;
    if (missing.minDays < -1 || missing.maxDays < -1 ||
        missing.warningDays < -1 ||
        (missing.maxDays != -1 && missing.minDays > missing.maxDays)) {
        error = "invalid password-aging missing-key semantics";
        return false;
    }
    const UserCreationPolicyDefaults& creation =
        profile.userCreation.policyDefaults;
    const auto validDefaultPath = [](const std::string& value) {
        const std::filesystem::path path(value);
        return validAbsolutePath(path) && path != path.root_path();
    };
    if (!validDefaultPath(creation.homeBaseDirectory) ||
        !validDefaultPath(creation.skeletonDirectory) ||
        !validDefaultPath(creation.defaultShell) ||
        (creation.createHome != "yes" && creation.createHome != "no") ||
        (creation.createPrivateGroup != "yes" &&
         creation.createPrivateGroup != "no") ||
        creation.defaultPrimaryGroup.empty() ||
        std::all_of(
            creation.defaultPrimaryGroup.begin(),
            creation.defaultPrimaryGroup.end(),
            [](unsigned char character) { return std::isdigit(character) != 0; })) {
        error = "invalid user-creation platform defaults";
        return false;
    }
    if (profile.sysctl.managedConfigPath.extension() != ".conf") {
        error = "sysctl managed path must use .conf extension";
        return false;
    }
    error.clear();
    return true;
}

bool readOsRelease(const std::filesystem::path& path,
                   OsReleaseValues& values,
                   std::string& error) {
    std::ifstream stream(path);
    if (!stream.is_open()) {
        error = "cannot open " + path.string();
        return false;
    }

    values.clear();
    std::string line;
    size_t lineNumber = 0;
    while (std::getline(stream, line)) {
        ++lineNumber;
        line = trim(std::move(line));
        if (line.empty() || line.front() == '#') {
            continue;
        }

        const size_t separator = line.find('=');
        if (separator == std::string::npos || separator == 0) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": malformed os-release entry";
            return false;
        }

        const std::string key = trim(line.substr(0, separator));
        const std::string encodedValue = trim(line.substr(separator + 1));
        if (!std::all_of(key.begin(), key.end(), [](unsigned char ch) {
                return std::isupper(ch) != 0 || std::isdigit(ch) != 0 || ch == '_';
            })) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": invalid os-release key";
            return false;
        }

        std::string decodedValue;
        if (!decodeValue(encodedValue, decodedValue)) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": malformed quoted os-release value";
            return false;
        }
        values[key] = std::move(decodedValue);
    }

    if (!stream.eof()) {
        error = "failed while reading " + path.string();
        return false;
    }
    error.clear();
    return true;
}

bool isHostCompatible(const PlatformProfile& profile,
                      const OsReleaseValues& values,
                      std::string& error) {
    const auto id = values.find("ID");
    if (id == values.end() || !contains(profile.hostCompatibility.osIds, id->second)) {
        error = "compiled profile '" + profile.id + "' expects os-release ID in [" +
                join(profile.hostCompatibility.osIds) + "], detected '" +
                (id == values.end() ? std::string("<missing>") : id->second) + "'";
        return false;
    }

    if (!profile.hostCompatibility.versionIds.empty()) {
        const auto version = values.find("VERSION_ID");
        if (version == values.end() ||
            !contains(profile.hostCompatibility.versionIds, version->second)) {
            error = "compiled profile '" + profile.id +
                    "' expects VERSION_ID in [" +
                    join(profile.hostCompatibility.versionIds) + "], detected '" +
                    (version == values.end() ? std::string("<missing>") : version->second) +
                    "'";
            return false;
        }
    }

    if (!profile.hostCompatibility.altBranchIds.empty()) {
        const auto branch = values.find("ALT_BRANCH_ID");
        if (branch == values.end() ||
            !contains(profile.hostCompatibility.altBranchIds, branch->second)) {
            error = "compiled profile '" + profile.id +
                    "' expects ALT_BRANCH_ID in [" +
                    join(profile.hostCompatibility.altBranchIds) + "], detected '" +
                    (branch == values.end() ? std::string("<missing>") : branch->second) +
                    "'";
            return false;
        }
    }

    error.clear();
    return true;
}

bool validateHostCompatibility(const PlatformProfile& profile,
                               const std::filesystem::path& osReleasePath,
                               std::string& error) {
    OsReleaseValues values;
    return readOsRelease(osReleasePath, values, error) &&
           isHostCompatible(profile, values, error);
}

} // namespace fic::platform
