#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"

#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PasswdqcConfigFile.h"
#include "modules/identity_access/pam/PamPwhistoryArguments.h"
#include "modules/identity_access/pam/PwqualityConfigFile.h"
#include "modules/identity_access/pam/PwhistoryConfigFile.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string_view>

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
using CanApplyOptionVerifier = OptionVerifier;
using CanApplyFlagVerifier = FlagVerifier;

struct SemanticBackend {
    CapabilityVerifier verifyCapability = nullptr;
    OptionVerifier verifyOption = nullptr;
    FlagVerifier verifyFlag = nullptr;
    CanApplyOptionVerifier canApplyOption = nullptr;
    CanApplyFlagVerifier canApplyFlag = nullptr;
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

bool verifyNoUnmanagedGenericInputs(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    std::string& error);

bool genericCapability(const PamProviderInspection& inspection,
                       const fic::platform::PamCapabilityConfig& capability,
                       bool,
                       PamProviderSemanticFailure& failure,
                       std::string& error)
{
    if (!verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        failure = PamProviderSemanticFailure::Broken;
        return false;
    }
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

bool verifyGenericOptionArguments(
    const PamProviderInspection& inspection,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
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
    error.clear();
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
    return verifyGenericOptionArguments(
        inspection, option, expectedValue, error);
}

bool verifyGenericFlagArguments(
    const PamProviderInspection& inspection,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
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
    error.clear();
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
    return verifyGenericFlagArguments(
        inspection, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
}

bool genericCanApplyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig&,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    return verifyGenericOptionArguments(
        inspection, option, expectedValue, error);
}

bool genericCanApplyFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig&,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    return verifyGenericFlagArguments(
        inspection, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
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

bool typedManagedConfigCanApplyOption(
    const PamProviderInspection&,
    const fic::platform::PamCapabilityConfig&,
    const std::string&,
    const std::string&,
    std::string& error)
{
    error.clear();
    return true;
}

bool typedManagedConfigCanApplyFlag(
    const PamProviderInspection&,
    const fic::platform::PamCapabilityConfig&,
    const std::string&,
    bool,
    const std::vector<std::string>&,
    std::string& error)
{
    error.clear();
    return true;
}

bool pwhistoryArgumentsCapability(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig&,
    bool requireSecurityEnforcement,
    PamProviderSemanticFailure& failure,
    std::string& error)
{
    for (const auto& rule : inspection.providerRules) {
        PamPwhistoryArgumentState state;
        if (!PamPwhistoryArguments::evaluate(rule, state, error)) {
            failure = PamProviderSemanticFailure::Broken;
            return false;
        }
        if (requireSecurityEnforcement && state.effectiveRemember() == 0) {
            failure = PamProviderSemanticFailure::Ineffective;
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": pam_pwhistory effective remember is disabled";
            return false;
        }
    }
    failure = PamProviderSemanticFailure::None;
    error.clear();
    return true;
}

bool pwhistoryArgumentsOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig&,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    PamProviderPolicyBinding binding;
    binding.option = option;
    binding.syntax = PamNativeOptionSyntax::Assignment;
    return PamPwhistoryArguments::hasExpectedState(
        inspection, binding, expectedValue, false, error);
}

bool pwhistoryArgumentsFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig&,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>&,
    std::string& error)
{
    PamProviderPolicyBinding binding;
    binding.option = flag;
    binding.syntax = PamNativeOptionSyntax::Flag;
    return PamPwhistoryArguments::hasExpectedState(
        inspection, binding, {}, expectedEnabled, error);
}

bool pwhistoryArgumentsCanApplyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string&,
    const std::string&,
    std::string& error)
{
    PamProviderSemanticFailure failure = PamProviderSemanticFailure::None;
    return pwhistoryArgumentsCapability(
        inspection, capability, false, failure, error);
}

bool pwhistoryArgumentsCanApplyFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string&,
    bool,
    const std::vector<std::string>&,
    std::string& error)
{
    PamProviderSemanticFailure failure = PamProviderSemanticFailure::None;
    return pwhistoryArgumentsCapability(
        inspection, capability, false, failure, error);
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
        if (requireSecurityEnforcement && state.localUsersOnly &&
            capability.subjectScope ==
                fic::platform::PamIdentitySubjectScope::AllPamSubjects) {
            failure = PamProviderSemanticFailure::Ineffective;
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": pam_pwquality is restricted to local users but the "
                "password-quality capability covers all PAM subjects";
            return false;
        }
    }
    failure = PamProviderSemanticFailure::None;
    error.clear();
    return true;
}

bool pwqualityStateSatisfiesOption(
    const PwqualityEffectiveState& state,
    const PamRule& rule,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
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
        if (!pwqualityStateSatisfiesOption(
                state, rule, option, expectedValue, error)) {
            return false;
        }
    }
    return true;
}

bool pwqualityStateSatisfiesFlag(
    const PwqualityEffectiveState& state,
    const PamRule& rule,
    const std::string& flag,
    bool expectedEnabled,
    std::string& error)
{
    if (flag != "enforce_for_root") {
        error = "unsupported managed pwquality flag " + flag;
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
    error.clear();
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
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        PwqualityEffectiveState state;
        if (!evaluatePwquality(inspection, capability, rule, state, error)) {
            return false;
        }
        if (!pwqualityStateSatisfiesFlag(
                state, rule, flag, expectedEnabled, error)) {
            return false;
        }
    }
    return true;
}

bool pwqualityCanApplyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    PamProviderSemanticFailure failure = PamProviderSemanticFailure::None;
    if (!pwqualityCapability(
            inspection, capability, true, failure, error)) {
        return false;
    }
    const auto topology = pwqualityTopology(inspection, capability);
    for (const auto& rule : inspection.providerRules) {
        PwqualityEffectiveState state;
        if (!PwqualityConfigEvaluator::evaluateInvocationWithManagedOption(
                rule.arguments, rule.source, rule.line, topology,
                option, expectedValue, state, error) ||
            !pwqualityStateSatisfiesOption(
                state, rule, option, expectedValue, error)) {
            return false;
        }
    }
    error.clear();
    return true;
}

bool pwqualityCanApplyFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>&,
    std::string& error)
{
    PamProviderSemanticFailure failure = PamProviderSemanticFailure::None;
    if (!pwqualityCapability(
            inspection, capability, true, failure, error)) {
        return false;
    }
    const auto topology = pwqualityTopology(inspection, capability);
    for (const auto& rule : inspection.providerRules) {
        PwqualityEffectiveState state;
        if (!PwqualityConfigEvaluator::evaluateInvocationWithManagedFlag(
                rule.arguments, rule.source, rule.line, topology,
                flag, expectedEnabled, state, error) ||
            !pwqualityStateSatisfiesFlag(
                state, rule, flag, expectedEnabled, error)) {
            return false;
        }
    }
    error.clear();
    return true;
}

// ---------------------------------------------------------------------------
// Step 7D: typed pwhistory config-file backend
// (PamProviderSemanticBackendKind::Pwhistory). Models the REAL upstream
// effective semantics:
//
//   * config file first-match per key (pam_modutil_search_key — case-
//     insensitive, '#' comments, space/tab/'=' separators);
//   * PAM module argv applied AFTER the config file (last-wins override);
//   * missing primary → fail closed (vendor fallback cannot be proven);
//   * external conf= contract through verifyExternalConfigContract
//     (wrong/duplicate conf= is a preflight refusal, never a mutation).
//
// The Debian 12 ModuleArguments backend (pwhistoryArguments) keeps
// priority in backendFor() and is never reached through this path.
// ---------------------------------------------------------------------------

fic::platform::PamProviderConfigTopology pwhistoryTopology(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability)
{
    if (capability.configTopology.has_value()) {
        return *capability.configTopology;
    }
    return pamProviderDescriptor(inspection.provider).defaultConfigTopology;
}

// Prepares the topology for evaluating ONE provider rule. The external
// conf= contract (verifyExternalConfigContract) already proves that the
// module reads exactly capability.configPath — for rules that omit conf=
// because the capability path must equal the default primary, and for
// rules that pin conf= explicitly. The evaluated primary is therefore
// ALWAYS capability.configPath (synthetic inspection capabilities without
// a configTopology stay correct). Upstream missing-file semantics:
//   * an explicitly conf=-selected missing file yields the BUILT-IN
//     defaults (no vendor fallback for explicit conf=);
//   * a missing DEFAULT primary may activate the VENDOR fallback, which
//     FIC cannot prove → fail closed.
bool preparePwhistoryRuleTopology(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const PamRule& rule,
    fic::platform::PamProviderConfigTopology& topology,
    std::string& error)
{
    topology = pwhistoryTopology(inspection, capability);
    topology.primaryPath = capability.configPath;
    bool primaryExists = false;
    if (!pathExists(capability.configPath, primaryExists, error)) {
        return false;
    }
    if (primaryExists) {
        return true;
    }
    const auto& descriptor = pamProviderDescriptor(inspection.provider);
    const bool explicitConfSelected =
        PamProviderInspector::argumentValue(
            rule, descriptor.externalConfigArgument).has_value();
    if (!explicitConfSelected) {
        error = "pam_pwhistory default primary configuration is absent: " +
            capability.configPath.string() +
            "; the vendor fallback topology cannot be proven (fail closed)";
        return false;
    }
    // Explicit conf= to a missing file: upstream uses the built-in
    // defaults — model that by evaluating no config file at all.
    topology.primaryPath.reset();
    return true;
}

bool evaluatePwhistory(const PamProviderInspection& inspection,
                       const fic::platform::PamCapabilityConfig& capability,
                       const PamRule& rule,
                       PwhistoryEffectiveState& state,
                       std::string& error)
{
    fic::platform::PamProviderConfigTopology topology;
    if (!preparePwhistoryRuleTopology(
            inspection, capability, rule, topology, error)) {
        return false;
    }
    return PwhistoryConfigEvaluator::evaluateInvocation(
        rule.arguments, rule.source, rule.line, topology, state, error);
}

bool pwhistoryCapability(const PamProviderInspection& inspection,
                         const fic::platform::PamCapabilityConfig& capability,
                         bool requireSecurityEnforcement,
                         PamProviderSemanticFailure& failure,
                         std::string& error)
{
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        failure = PamProviderSemanticFailure::Broken;
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        PwhistoryEffectiveState state;
        if (!evaluatePwhistory(inspection, capability, rule, state, error)) {
            failure = PamProviderSemanticFailure::Broken;
            return false;
        }
        if (requireSecurityEnforcement && state.remember == 0) {
            failure = PamProviderSemanticFailure::Ineffective;
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": pam_pwhistory effective remember is disabled "
                "(PAM_IGNORE upstream)";
            return false;
        }
    }
    failure = PamProviderSemanticFailure::None;
    error.clear();
    return true;
}

bool pwhistoryStateSatisfiesOption(
    const PwhistoryEffectiveState& state,
    const PamRule& rule,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    std::string effectiveValue;
    if (!state.managedValue(option, effectiveValue, error)) {
        return false;
    }
    if (effectiveValue != expectedValue) {
        error = rule.source.string() + ":" +
            std::to_string(rule.line) + ": effective pwhistory " + option +
            " is " + effectiveValue + ", expected " + expectedValue;
        return false;
    }
    error.clear();
    return true;
}

bool pwhistoryOption(const PamProviderInspection& inspection,
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
        PwhistoryEffectiveState state;
        if (!evaluatePwhistory(inspection, capability, rule, state, error)) {
            return false;
        }
        if (!pwhistoryStateSatisfiesOption(
                state, rule, option, expectedValue, error)) {
            return false;
        }
    }
    return true;
}

bool pwhistoryFlag(const PamProviderInspection& inspection,
                   const fic::platform::PamCapabilityConfig& capability,
                   const std::string& flag,
                   bool expectedEnabled,
                   const std::vector<std::string>&,
                   std::string& error)
{
    if (flag != "enforce_for_root") {
        error = "unsupported managed pwhistory flag " + flag;
        return false;
    }
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        PwhistoryEffectiveState state;
        if (!evaluatePwhistory(inspection, capability, rule, state, error)) {
            return false;
        }
        if (state.enforceForRoot != expectedEnabled) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": effective pwhistory enforce_for_root is " +
                (state.enforceForRoot ? "enabled" : "disabled") +
                ", expected " +
                (expectedEnabled ? "enabled" : "disabled") +
                ": a PAM module argument or foreign config entry overrides "
                "the requested state";
            return false;
        }
    }
    return true;
}

bool pwhistoryCanApplyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    // Structural + unmanaged-input preflight; the effective-remember
    // security check is subsumed by the prospective exact-value proof
    // below (the managed BOF entry is the FIRST match after the
    // mutation, so a CURRENT foreign remember value is never a rejection
    // reason — only PAM argv overrides and unsafe inputs are).
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        return false;
    }
    for (const auto& rule : inspection.providerRules) {
        fic::platform::PamProviderConfigTopology topology;
        if (!preparePwhistoryRuleTopology(
                inspection, capability, rule, topology, error)) {
            return false;
        }
        PwhistoryEffectiveState state;
        if (!PwhistoryConfigEvaluator::evaluateInvocationWithManagedOption(
                rule.arguments, rule.source, rule.line, topology,
                option, expectedValue, state, error) ||
            !pwhistoryStateSatisfiesOption(
                state, rule, option, expectedValue, error)) {
            return false;
        }
    }
    error.clear();
    return true;
}

// ASCII-only case-insensitive helpers for the typed pwhistory conflicting
// option check below (mirrors the evaluator's internal upstream
// strcasecmp / pam_str_skip_icase_prefix semantics; the evaluator's own
// helpers are internal to its translation unit).
char pwhistoryIcaseLower(char character)
{
    return character >= 'A' && character <= 'Z'
        ? static_cast<char>(character - 'A' + 'a')
        : character;
}

bool pwhistoryIcaseEquals(std::string_view left, std::string_view right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (pwhistoryIcaseLower(left[index]) !=
            pwhistoryIcaseLower(right[index])) {
            return false;
        }
    }
    return true;
}

bool pwhistoryIcaseStartsWith(std::string_view value,
                              std::string_view prefix)
{
    if (value.size() < prefix.size()) {
        return false;
    }
    return pwhistoryIcaseEquals(value.substr(0, prefix.size()), prefix);
}

// Typed pwhistory replacement for verifyGenericFlagArguments. Upstream
// pam_pwhistory.c matches the presence flags debug / enforce_for_root
// with strcasecmp over the WHOLE token, so the flag proof here is fully
// case-insensitive:
//   * a valued token naming the flag ("debug=x", "enforce_for_root=")
//     fails closed (never an enabled flag);
//   * case-variant duplicates fail closed;
//   * with a requested DISABLED state, ANY case-variant flag occurrence
//     ("EnFoRcE_FoR_RoOt" included) is an unreachable override for the
//     legacy config writer and fails the preflight closed;
//   * with a requested ENABLED state a flag occurrence is never a
//     conflict (the effective state is already true through argv);
//   * conflicting options, when declared, are checked case-insensitively
//     (whole token or "<option>=" prefix) — no generic case-sensitive
//     fallback.
bool verifyPwhistoryFlagArguments(
    const PamProviderInspection& inspection,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    for (const auto& rule : inspection.providerRules) {
        PwhistoryFlagArgumentScan scan;
        PwhistoryConfigEvaluator::scanFlagArguments(
            rule.arguments, flag, scan);
        if (!scan.valuedArgument.empty()) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": pwhistory PAM flag " +
                scan.valuedArgument + " must not have a value";
            return false;
        }
        if (scan.occurrences > 1) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": duplicate pwhistory flag " +
                flag;
            return false;
        }
        if (!expectedEnabled && scan.occurrences > 0) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) + ": pwhistory PAM flag " +
                scan.firstArgument + " (case-insensitive " + flag +
                ") overrides the requested disabled state";
            return false;
        }
        if (!expectedEnabled) {
            for (const auto& option : conflictingOptionsWhenDisabled) {
                for (const auto& argument : rule.arguments) {
                    if (pwhistoryIcaseEquals(argument, option) ||
                        pwhistoryIcaseStartsWith(argument, option + "=")) {
                        error = rule.source.string() + ":" +
                            std::to_string(rule.line) +
                            ": pwhistory PAM argument " + option +
                            " conflicts with the requested disabled state";
                        return false;
                    }
                }
            }
        }
    }
    error.clear();
    return true;
}

bool pwhistoryCanApplyFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    if (flag != "enforce_for_root") {
        error = "unsupported managed pwhistory flag " + flag;
        return false;
    }
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        return false;
    }
    // Step 7D follow-up: the same strict duplicate-argv contract as every
    // other typed pwhistory semantic operation — an ambiguous argv set
    // (duplicate known option, case variants included) must fail this
    // legacy-writer preflight closed too. conf= uniqueness stays governed
    // by verifyExternalConfigContract above.
    for (const auto& rule : inspection.providerRules) {
        if (!PwhistoryConfigEvaluator::validatePamArguments(
                rule.arguments, rule.source, rule.line, error)) {
            return false;
        }
    }
    // Step 7D semantic cleanup: the flag override proof uses the TYPED
    // case-insensitive pwhistory argv semantics (upstream
    // strcasecmp("enforce_for_root")), NOT the generic case-sensitive
    // helper — a case-variant argv override ("EnFoRcE_FoR_RoOt") must
    // fail a requested disabled state closed BEFORE any legacy config
    // mutation, while the same-effective argv must NOT block a requested
    // enabled state (the legacy writer may still add the config flag;
    // the effective state is already true through argv).
    return verifyPwhistoryFlagArguments(
        inspection, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
}

// Step 7E: managed-flag preflight for the journal-backed set-only flag
// executor (PamProviderManagedFlagExecutor). Same argv invariants as the
// legacy preflight above, PLUS the prospective first-match flag model
// (PwhistoryConfigEvaluator::evaluateInvocationWithManagedFlag): the
// executor can safely SUPPRESS every foreign primary occurrence of the
// key, so a foreign config flag line never blocks a requested disabled
// state — but a PAM argv override, a missing primary (vendor fallback
// cannot be proven), malformed known directives and broken/untrusted
// inputs still fail closed BEFORE any journal mutation.
bool pwhistoryCanApplyManagedFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    if (flag != "enforce_for_root") {
        error = "unsupported managed pwhistory flag " + flag;
        return false;
    }
    if (!PamProviderInspector::verifyExternalConfigContract(
            inspection, capability, error) ||
        !verifyNoUnmanagedGenericInputs(inspection, capability, error)) {
        return false;
    }
    // argv invariants (Step 7D): typed case-insensitive whole-token flag
    // semantics — a case-variant argv override makes a requested disabled
    // state unreachable and fails closed; the same-effective argv never
    // blocks a requested enabled state.
    if (!verifyPwhistoryFlagArguments(
            inspection, flag, expectedEnabled,
            conflictingOptionsWhenDisabled, error)) {
        return false;
    }
    // Prospective suppress/insert model of the primary under the real
    // topology + PAM argv.
    for (const auto& rule : inspection.providerRules) {
        fic::platform::PamProviderConfigTopology topology;
        if (!preparePwhistoryRuleTopology(
                inspection, capability, rule, topology, error)) {
            return false;
        }
        PwhistoryEffectiveState state;
        if (!PwhistoryConfigEvaluator::evaluateInvocationWithManagedFlag(
                rule.arguments, rule.source, rule.line, topology,
                flag, expectedEnabled, state, error)) {
            return false;
        }
        if (state.enforceForRoot != expectedEnabled) {
            error = rule.source.string() + ":" +
                std::to_string(rule.line) +
                ": prospective pwhistory enforce_for_root is " +
                (state.enforceForRoot ? "enabled" : "disabled") +
                ", expected " +
                (expectedEnabled ? "enabled" : "disabled") +
                ": an unmanaged input overrides the requested state";
            return false;
        }
    }
    error.clear();
    return true;
}

const SemanticBackend& backendFor(PamProviderSemanticBackendKind kind)
{
    static const SemanticBackend generic{
        genericCapability, genericOption, genericFlag,
        genericCanApplyOption, genericCanApplyFlag};
    static const SemanticBackend pwquality{
        pwqualityCapability, pwqualityOption, pwqualityFlag,
        pwqualityCanApplyOption, pwqualityCanApplyFlag};
    static const SemanticBackend passwdqc{
        passwdqcCapability, passwdqcOption, passwdqcFlag,
        typedManagedConfigCanApplyOption, typedManagedConfigCanApplyFlag};
    static const SemanticBackend pwhistory{
        pwhistoryCapability, pwhistoryOption, pwhistoryFlag,
        pwhistoryCanApplyOption, pwhistoryCanApplyFlag};
    switch (kind) {
    case PamProviderSemanticBackendKind::Generic:
        return generic;
    case PamProviderSemanticBackendKind::Pwquality:
        return pwquality;
    case PamProviderSemanticBackendKind::Passwdqc:
        return passwdqc;
    case PamProviderSemanticBackendKind::Pwhistory:
        return pwhistory;
    }
    return generic;
}

const SemanticBackend& backendFor(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability)
{
    static const SemanticBackend pwhistoryArguments{
        pwhistoryArgumentsCapability,
        pwhistoryArgumentsOption,
        pwhistoryArgumentsFlag,
        pwhistoryArgumentsCanApplyOption,
        pwhistoryArgumentsCanApplyFlag};
    if (capability.configurationMode ==
        fic::platform::PamCapabilityConfigurationMode::ModuleArguments) {
        return pwhistoryArguments;
    }
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
    return backendFor(inspection, capability).verifyCapability(
        inspection, capability, requireSecurityEnforcement, failure, error);
}

bool PamProviderSemanticVerifier::verifyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    return backendFor(inspection, capability).verifyOption(
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
    return backendFor(inspection, capability).verifyFlag(
        inspection, capability, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
}

bool PamProviderSemanticVerifier::canApplyOption(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    return backendFor(inspection, capability).canApplyOption(
        inspection, capability, option, expectedValue, error);
}

bool PamProviderSemanticVerifier::canApplyFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    return backendFor(inspection, capability).canApplyFlag(
        inspection, capability, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
}

bool PamProviderSemanticVerifier::canApplyManagedProviderFlag(
    const PamProviderInspection& inspection,
    const fic::platform::PamCapabilityConfig& capability,
    const std::string& flag,
    bool expectedEnabled,
    const std::vector<std::string>& conflictingOptionsWhenDisabled,
    std::string& error)
{
    // Per-provider dispatch of the managed set-only flag preflight
    // (Step 7E §52). pwquality: the existing prospective evaluator already
    // models primary suppression + drop-in enforcement. pwhistory: the
    // dedicated managed preflight with the new prospective flag evaluator.
    // faillock and every other Generic provider: the generic argv-only
    // check — the primary conflicting-directive proof (root_unlock_time)
    // stays the caller's provider-correct scanner responsibility.
    const auto kind =
        pamProviderDescriptor(inspection.provider).semanticBackend;
    if (kind == PamProviderSemanticBackendKind::Pwhistory &&
        capability.configurationMode !=
            fic::platform::PamCapabilityConfigurationMode::ModuleArguments) {
        return pwhistoryCanApplyManagedFlag(
            inspection, capability, flag, expectedEnabled,
            conflictingOptionsWhenDisabled, error);
    }
    return backendFor(inspection, capability).canApplyFlag(
        inspection, capability, flag, expectedEnabled,
        conflictingOptionsWhenDisabled, error);
}

} // namespace fic::identity::pam
