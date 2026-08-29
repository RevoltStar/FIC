#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"

#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PasswdqcConfigFile.h"
#include "modules/identity_access/pam/PwqualityConfigFile.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <sys/stat.h>

namespace fic::identity::pam {
namespace {

using CapabilityVerifier = bool (*)(
    const PamProviderInspection&,
    const fic::platform::PamCapabilityConfig&,
    bool,
    PamProviderSemanticFailure&,
    std::string&);
using OptionVerifier = bool (*)(
    const PamProviderInspection&,
    const fic::platform::PamCapabilityConfig&,
    const std::string&,
    const std::string&,
    std::string&);
using FlagVerifier = bool (*)(
    const PamProviderInspection&,
    const fic::platform::PamCapabilityConfig&,
    const std::string&,
    bool,
    const std::vector<std::string>&,
    std::string&);

struct SemanticBackend {
    CapabilityVerifier verifyCapability = nullptr;
    OptionVerifier verifyOption = nullptr;
    FlagVerifier verifyFlag = nullptr;
};

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

bool genericCapability(const PamProviderInspection&,
                       const fic::platform::PamCapabilityConfig&,
                       bool,
                       PamProviderSemanticFailure& failure,
                       std::string& error)
{
    failure = PamProviderSemanticFailure::None;
    error.clear();
    return true;
}

const fic::platform::PamProviderConfigTopology& providerTopology(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability)
{
    return capability.configTopology.has_value()
        ? *capability.configTopology
        : pamProviderDescriptor(inspection.provider).defaultConfigTopology;
}

bool pathExists(const std::filesystem::path& path,
                bool& exists,
                std::string& error)
{
    struct stat info {};
    if (::lstat(path.c_str(), &info) == 0) {
        exists = true;
        return true;
    }
    if (errno == ENOENT) {
        exists = false;
        return true;
    }
    error = "could not inspect PAM provider configuration input " +
        path.string() + ": " + std::strerror(errno);
    return false;
}

bool verifyNoUnmanagedGenericInputs(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    std::string& error)
{
    const auto& descriptor = pamProviderDescriptor(inspection.provider);
    for (const auto& rule : inspection.providerRules) {
        if (descriptor.externalConfigMode != PamExternalConfigMode::None &&
            PamProviderInspector::argumentValue(
                rule, descriptor.externalConfigArgument).has_value()) {
            continue;
        }

        const auto& topology = providerTopology(inspection, capability);
        for (const auto& directory : topology.dropInDirectories) {
            bool exists = false;
            if (!pathExists(directory, exists, error)) {
                return false;
            }
            if (!exists) {
                continue;
            }
            std::error_code iterationError;
            const auto begin = std::filesystem::directory_iterator(
                directory, iterationError);
            if (iterationError) {
                error = "could not enumerate unmanaged PAM provider drop-ins " +
                    directory.string() + ": " + iterationError.message();
                return false;
            }
            if (begin != std::filesystem::directory_iterator{}) {
                error = "unmanaged PAM provider drop-in configuration may "
                    "override the managed state: " + directory.string();
                return false;
            }
        }

        bool primaryExists = false;
        if (topology.primaryPath.has_value() &&
            !pathExists(*topology.primaryPath, primaryExists, error)) {
            return false;
        }
        if (primaryExists) {
            continue;
        }
        for (const auto& fallback : topology.fallbackPaths) {
            bool fallbackExists = false;
            if (!pathExists(fallback, fallbackExists, error)) {
                return false;
            }
            if (fallbackExists) {
                error = "unmanaged PAM provider fallback configuration is "
                    "active while the managed primary file is absent: " +
                    fallback.string();
                return false;
            }
        }
    }
    return true;
}

bool genericOption(const PamProviderInspection& inspection,
                   const fic::platform::PamCapabilityConfig& capability,
                   const std::string& option,
                   const std::string& expectedValue,
                   std::string& error)
{
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
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

bool genericFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        return false;
    }
    const std::string assignmentPrefix = flag + "=";
    for (const auto& rule : inspection.providerRules) {
        std::size_t occurrences = 0;
        for (const auto& argument : rule.arguments) {
            occurrences += argument == flag ? 1U : 0U;
            if (argument.compare(0, assignmentPrefix.size(),
                                 assignmentPrefix) == 0) {
                error = rule.source.string() + ":" +
                    std::to_string(rule.line) + ": PAM flag " + flag +
                    " must not have a value";
                return false;
            }
        }
        if (occurrences > 1) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": duplicate PAM flag " + flag;
            return false;
        }
        if (!expectedEnabled && PamProviderInspector::hasArgument(rule, flag)) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": PAM argument " + flag +
                " overrides the requested disabled state";
            return false;
        }
        if (!expectedEnabled) {
            for (const auto& option : conflictingOptionsWhenDisabled) {
                if (PamProviderInspector::hasArgument(rule, option) ||
                    PamProviderInspector::argumentValue(rule, option).has_value()) {
                    error = rule.source.string() + ":" +
                        std::to_string(rule.line) + ": PAM argument " + option +
                        " conflicts with the requested disabled state";
                    return false;
                }
            }
        }
    }
    return true;
}

bool passwdqcCapability(const PamProviderInspection& inspection,
                        const fic::platform::PamCapabilityConfig&,
                        bool requireSecurityEnforcement,
                        PamProviderSemanticFailure& failure,
                        std::string& error)
{
    for (const auto& rule : inspection.providerRules) {
        PasswdqcEffectiveState state;
        if (!PasswdqcConfigEvaluator::evaluateInvocation(
                rule.arguments, rule.source, rule.line, state, error)) {
            failure = PamProviderSemanticFailure::Broken;
            return false;
        }
        if (requireSecurityEnforcement && state.enforce == "none") {
            failure = PamProviderSemanticFailure::Ineffective;
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": pam_passwdqc password quality enforcement is disabled "
                "by effective enforce=none";
            return false;
        }
    }
    failure = PamProviderSemanticFailure::None;
    error.clear();
    return true;
}

bool passwdqcOption(const PamProviderInspection& inspection,
                    const fic::platform::PamCapabilityConfig& capability,
                    const std::string& option,
                    const std::string& expectedValue,
                    std::string& error)
{
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        PasswdqcEffectiveState state;
        if (!PasswdqcConfigEvaluator::evaluateInvocation(
                rule.arguments, rule.source, rule.line, state, error)) {
            return false;
        }
        std::string effectiveValue;
        if (!state.managedValue(option, effectiveValue, error)) {
            return false;
        }
        if (effectiveValue != expectedValue) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": effective passwdqc " + option +
                " is " + effectiveValue + ", expected " + expectedValue;
            return false;
        }
    }
    return true;
}

bool passwdqcFlag(const PamProviderInspection& inspection,
                  const fic::platform::PamCapabilityConfig& capability,
                  const std::string& flag,
                  bool expectedEnabled,
                  const std::vector<std::string>& conflicts,
                  std::string& error)
{
    return genericFlag(
        inspection, capability, flag, expectedEnabled, conflicts, error);
}

fic::platform::PamProviderConfigTopology pwqualityTopology(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability)
{
    if (capability.configTopology.has_value()) {
        return *capability.configTopology;
    }
    return pamProviderDescriptor(inspection.provider).defaultConfigTopology;
}

bool evaluatePwquality(const PamProviderInspection& inspection,
                       const fic::platform::PamCapabilityConfig& capability,
                       const PamRule& rule,
                       PwqualityEffectiveState& state,
                       std::string& error)
{
    const auto topology = pwqualityTopology(inspection, capability);
    if (!topology.primaryPath.has_value() ||
        *topology.primaryPath != capability.configPath ||
        topology.explicitConfig !=
            fic::platform::PamExplicitConfigSemantics::Unsupported) {
        error = "invalid pam_pwquality platform configuration topology";
        return false;
    }
    return PwqualityConfigEvaluator::evaluateInvocation(
        rule.arguments, rule.source, rule.line,
        topology, state, error);
}

bool pwqualityCapability(const PamProviderInspection& inspection,
                         const fic::platform::PamCapabilityConfig& capability,
                         bool requireSecurityEnforcement,
                         PamProviderSemanticFailure& failure,
                         std::string& error)
{
    for (const auto& rule : inspection.providerRules) {
        PwqualityEffectiveState state;
        if (!evaluatePwquality(inspection, capability, rule, state, error)) {
            failure = PamProviderSemanticFailure::Broken;
            return false;
        }
        if (requireSecurityEnforcement && state.enforcing == 0) {
            failure = PamProviderSemanticFailure::Ineffective;
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": pam_pwquality password quality enforcement is disabled "
                "by effective enforcing=0";
            return false;
        }
    }
    failure = PamProviderSemanticFailure::None;
    error.clear();
    return true;
}

bool pwqualityOption(const PamProviderInspection& inspection,
                     const fic::platform::PamCapabilityConfig& capability,
                     const std::string& option,
                     const std::string& expectedValue,
                     std::string& error)
{
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        PwqualityEffectiveState state;
        if (!evaluatePwquality(inspection, capability, rule, state, error)) {
            return false;
        }
        std::string effectiveValue;
        if (!state.managedValue(option, effectiveValue, error)) {
            return false;
        }
        if (option == "minlen" &&
            (state.dcredit > 0 || state.ucredit > 0 ||
             state.lcredit > 0 || state.ocredit > 0)) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": effective pwquality credits can reduce the actual "
                "minimum password length below minlen=" + expectedValue;
            return false;
        }
        if (effectiveValue != expectedValue) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": effective pwquality " + option +
                " is " + effectiveValue + ", expected " + expectedValue;
            return false;
        }
    }
    return true;
}

bool pwqualityFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>&,
    std::string& error)
{
    if (flag != "enforce_for_root") {
        error = "unsupported managed pwquality flag " + flag;
        return false;
    }
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        PwqualityEffectiveState state;
        if (!evaluatePwquality(inspection, capability, rule, state, error)) {
            return false;
        }
        if (state.enforceForRoot != expectedEnabled) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": effective pwquality enforce_for_root is " +
                (state.enforceForRoot ? "enabled" : "disabled") +
                ", expected " + (expectedEnabled ? "enabled" : "disabled");
            return false;
        }
    }
    return true;
}

const SemanticBackend& backendFor(PamProviderSemanticBackendKind kind)
{
    static const SemanticBackend generic{
        genericCapability, genericOption, genericFlag};
    static const SemanticBackend pwquality{
        pwqualityCapability, pwqualityOption, pwqualityFlag};
    static const SemanticBackend passwdqc{
        passwdqcCapability, passwdqcOption, passwdqcFlag};
    switch (kind) {
    case PamProviderSemanticBackendKind::Generic:
        return generic;
    case PamProviderSemanticBackendKind::Pwquality:
        return pwquality;
    case PamProviderSemanticBackendKind::Passwdqc:
        return passwdqc;
    }
    return generic;
}

const SemanticBackend& backendFor(const PamProviderInspection& inspection)
{
    return backendFor(pamProviderDescriptor(inspection.provider).semanticBackend);
}

} // namespace

bool PamProviderSemanticVerifier::verifyCapability(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    bool requireSecurityEnforcement,
    PamProviderSemanticFailure& failure,
    std::string& error)
{
    return backendFor(inspection).verifyCapability(
        inspection, capability, requireSecurityEnforcement, failure, error);
}

bool PamProviderSemanticVerifier::verifyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    return backendFor(inspection).verifyOption(
        inspection, capability, option, expectedValue, error);
}

bool PamProviderSemanticVerifier::verifyFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    return backendFor(inspection).verifyFlag(
        inspection, capability, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
}

} // namespace fic::identity::pam
