#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "modules/identity_access/pam/PwqualityConfigFile.h"
#include "modules/identity_access/pam/PwhistoryConfigFile.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using namespace fic::identity::pam;
using fic::platform::PamCapabilityConfigurationMode;
using fic::platform::PamPolicyFeature;
using fic::platform::PamProviderKind;
using fic::rollback::MutationId;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAction;
using fic::rollback::UndoOwnPamProviderContainer;
using fic::rollback::UndoRemovePamProviderManagedEntry;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

bool endsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
        value.compare(value.size() - suffix.size(), suffix.size(), suffix) ==
            0;
}

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/fic-pam-entry-executor-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        directory = created;
    }
    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
    std::filesystem::path directory;
};

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

struct Harness {
    TempDir temp;
    std::filesystem::path journalPath;
    std::filesystem::path configPath = temp.directory / "faillock.conf";
    // Step 7C: the pam_pwquality provider primary of the same harness (the
    // drop-in directory sits next to it as a FOREIGN topology input).
    std::filesystem::path pwqualityConfigPath =
        temp.directory / "pwquality.conf";
    std::filesystem::path pwqualityDropInDirectory() const {
        return pwqualityConfigPath.parent_path() / "pwquality.conf.d";
    }
    // Step 7D: the pam_pwhistory provider primary of the same harness.
    std::filesystem::path pwhistoryConfigPath =
        temp.directory / "pwhistory.conf";
    MutationJournal journal;
    std::string error;
    // Semantic verification sequence: the executor must pass the EXACT
    // expected native value of the state being proven — the durable journal
    // target first during Prepared recovery, the current desired value for
    // fresh applies/refreshes. Regression harness for the
    // "durable target first" invariant.
    std::vector<std::string> verifiedValues;
    // Injected semantic failures (by expected value) to test recoverable
    // failure states between two transitions.
    std::set<std::string> failSemanticFor;

    Harness() : Harness(std::filesystem::path{}) {}

    // journalFile: reuse an existing persistent journal document (restart
    // recovery tests); empty = fresh journal in the temp directory.
    explicit Harness(std::filesystem::path journalFile)
        : journalPath(journalFile.empty()
                  ? temp.directory / "mutations.json"
                  : std::move(journalFile)),
          journal(journalPath) {
        require(journal.load(error), "journal load failed: " + error);
    }

    PamProviderManagedEntryRequest request(const std::string& policyName,
        const std::string& key, const std::string& value,
        PamProviderAbsentContainerDecision absentDecision =
            PamProviderAbsentContainerDecision::FailClosed) const {
        PamProviderManagedEntryRequest request;
        request.policyName = policyName;
        request.provider = PamProviderKind::PamFaillock;
        request.providerName = "pam_faillock";
        request.managedKey = key;
        request.nativeValue = value;
        request.configPath = configPath;
        request.placement = PamProviderBlockPlacementRequest::End;
        request.absentDecision = absentDecision;
        return request;
    }

    // Step 7C: the pam_pwquality provider variant of the same request
    // against the pwquality primary of this harness.
    PamProviderManagedEntryRequest pwqualityRequest(
        const std::string& policyName, const std::string& key,
        const std::string& value,
        PamProviderAbsentContainerDecision absentDecision =
            PamProviderAbsentContainerDecision::FailClosed) const {
        PamProviderManagedEntryRequest request;
        request.policyName = policyName;
        request.provider = PamProviderKind::PamPwquality;
        request.providerName = "pam_pwquality";
        request.managedKey = key;
        request.nativeValue = value;
        request.configPath = pwqualityConfigPath;
        request.placement = PamProviderBlockPlacementRequest::End;
        request.absentDecision = absentDecision;
        return request;
    }

    // Step 7D: the pam_pwhistory provider variant of the same request
    // against the pwhistory primary of this harness. The upstream
    // pam_modutil_search_key first-match semantics require BOF placement.
    PamProviderManagedEntryRequest pwhistoryRequest(
        const std::string& policyName, const std::string& key,
        const std::string& value,
        PamProviderAbsentContainerDecision absentDecision =
            PamProviderAbsentContainerDecision::FailClosed) const {
        PamProviderManagedEntryRequest request;
        request.policyName = policyName;
        request.provider = PamProviderKind::PamPwhistory;
        request.providerName = "pam_pwhistory";
        request.managedKey = key;
        request.nativeValue = value;
        request.configPath = pwhistoryConfigPath;
        request.placement = PamProviderBlockPlacementRequest::Beginning;
        request.absentDecision = absentDecision;
        return request;
    }

    bool apply(const PamProviderManagedEntryRequest& request,
        PamProviderManagedEntryOutcome& outcome) {
        verifiedValues.clear();
        error.clear();
        return PamProviderManagedEntryExecutor::apply(request, journal,
            [this](const std::string& expectedNativeValue,
                std::string& semanticError) {
                if (failSemanticFor.count(expectedNativeValue) != 0) {
                    semanticError = "injected semantic failure for '" +
                        expectedNativeValue + "'";
                    return false;
                }
                verifiedValues.push_back(expectedNativeValue);
                return true;
            },
            outcome, error);
    }

    // Convenience overload for tests that do not assert the outcome kind.
    bool apply(const PamProviderManagedEntryRequest& request) {
        PamProviderManagedEntryOutcome outcome;
        return this->apply(request, outcome);
    }

    std::vector<MutationRecord> entryRecords(const std::string& policyName) {
        return journal.activeRecords({"IDENTITY_ACCESS", "PAM", policyName});
    }

    std::vector<MutationRecord> containerRecords(
        const std::string& providerName = "pam_faillock") {
        return journal.activeRecords(
            {"IDENTITY_ACCESS", "PAM_CONTAINER", providerName});
    }

    MutationRecord soleEntryRecord(const std::string& policyName,
        const std::string& context) {
        auto records = entryRecords(policyName);
        require(records.size() == 1,
            context + ": expected exactly one entry record, got " +
                std::to_string(records.size()));
        return records.front();
    }

    MutationRecord soleContainerRecord(const std::string& context,
        const std::string& providerName = "pam_faillock") {
        auto records = containerRecords(providerName);
        require(records.size() == 1,
            context + ": expected exactly one container record, got " +
                std::to_string(records.size()));
        return records.front();
    }

    PamProviderBlockParseResult parse(
        const std::filesystem::path& path = std::filesystem::path{}) {
        return parsePamProviderManagedBlock(
            readFile(path.empty() ? configPath : path));
    }
};

// Applies one production-like apply (fresh journal), creating the FIC-owned
// container explicitly.
Harness appliedPolicy(const std::string& policyName, const std::string& key,
    const std::string& value) {
    Harness harness;
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request(policyName, key, value,
                              PamProviderAbsentContainerDecision::
                                  CreateFicOwned),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "fresh apply must be Applied");
    return harness;
}

// Hand-prepares an entry journal record (crash-state construction for the
// recovery matrix). previousBody empty = fresh create. Defaults to the
// pam_faillock provider primary; Step 7C pwquality tests pass
// "pam_pwquality" + the pwquality primary explicitly.
MutationId prepareEntryRecord(Harness& harness,
    const std::string& policyName, const std::string& appliedBody,
    const std::string& previousBody,
    const std::string& providerName = "pam_faillock",
    const std::filesystem::path& configPath = std::filesystem::path{},
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End) {
    UndoRemovePamProviderManagedEntry payload;
    payload.policyName = policyName;
    payload.providerName = providerName;
    payload.configPath =
        (configPath.empty() ? harness.configPath : configPath).string();
    payload.managedKey = appliedBody.substr(0, appliedBody.find(" = "));
    payload.appliedBody = appliedBody;
    payload.previousAppliedBody = previousBody;
    payload.placement =
        placement == PamProviderBlockPlacementRequest::Beginning
        ? fic::rollback::PamProviderBlockPlacementContract::Beginning
        : fic::rollback::PamProviderBlockPlacementContract::End;

    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", policyName};
    record.resource = payload.configPath;
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, payload};

    MutationId id = 0;
    require(harness.journal.prepareMutation(record, id, harness.error),
        harness.error);
    return id;
}

// Writes the physical entry for (policy, key) with the given id directly
// (crash simulation: physical write happened, journal completion not).
// Defaults to the pam_faillock primary; pwquality tests pass the provider
// name and the pwquality primary path explicitly.
void writePhysicalEntry(Harness& harness, const std::string& baseContent,
    const std::string& policyName, const std::string& key,
    const std::string& value, MutationId id,
    const std::string& providerName = "pam_faillock",
    const std::filesystem::path& configPath = std::filesystem::path{},
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End) {
    auto spec = PamProviderEntrySpec{providerName, policyName, key, value,
        static_cast<std::uint64_t>(id)};
    auto mutation = setPamProviderManagedEntry(baseContent, spec, placement);
    require(mutation.ok, mutation.error);
    writeFile(configPath.empty() ? harness.configPath : configPath,
        mutation.content);
}

// Re-prepares the ACTIVE entry record as an update transaction (same id):
// journal refresh previous→target, status back to Prepared (crash between
// journal refresh and physical completion). Defaults to the pam_faillock
// primary; pwquality tests pass the provider name and path explicitly.
MutationId prepareUpdateTransaction(Harness& harness,
    const std::string& policyName, const std::string& key,
    const std::string& previousBody, const std::string& targetBody,
    const std::string& providerName = "pam_faillock",
    const std::filesystem::path& configPath = std::filesystem::path{},
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End) {
    UndoRemovePamProviderManagedEntry payload;
    payload.policyName = policyName;
    payload.providerName = providerName;
    payload.configPath =
        (configPath.empty() ? harness.configPath : configPath).string();
    payload.managedKey = key;
    payload.appliedBody = targetBody;
    payload.previousAppliedBody = previousBody;
    payload.placement =
        placement == PamProviderBlockPlacementRequest::Beginning
        ? fic::rollback::PamProviderBlockPlacementContract::Beginning
        : fic::rollback::PamProviderBlockPlacementContract::End;
    MutationRecord update;
    update.policy = {"IDENTITY_ACCESS", "PAM", policyName};
    update.resource = payload.configPath;
    update.undo = UndoAction{fic::rollback::MutationBackend::Pam, payload};
    MutationId id = 0;
    require(harness.journal.prepareMutation(update, id, harness.error),
        harness.error);
    require(harness.journal.setStatus(
                id, MutationStatus::Prepared, harness.error),
        harness.error);
    return id;
}

// Hand-prepares the container provenance record (crash-state construction:
// container Prepared committed, lifecycle completion not).
MutationId prepareContainerRecord(Harness& harness) {
    UndoOwnPamProviderContainer payload;
    payload.providerName = "pam_faillock";
    payload.configPath = harness.configPath.string();

    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER", "pam_faillock"};
    record.resource = harness.configPath.string();
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, payload};
    MutationId id = 0;
    require(harness.journal.prepareMutation(record, id, harness.error),
        harness.error);
    return id;
}

// ---------------------------------------------------------------------------
// §33 + routing decision
// ---------------------------------------------------------------------------

void testRoutingDecision() {
    // Locally-built minimal descriptor/binding fixtures (the catalog itself
    // is not linked into this unit test).
    PamProviderDescriptor provider;
    provider.kind = PamProviderKind::PamFaillock;
    provider.name = "pam_faillock";
    provider.defaultConfigTopology.explicitConfig =
        fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology;

    auto assignmentBinding = [](PamPolicyFeature feature,
                               const std::string& option) {
        PamProviderPolicyBinding binding;
        binding.feature = feature;
        binding.option = option;
        binding.syntax = PamNativeOptionSyntax::Assignment;
        binding.encoding = PamNativeValueEncoding::Direct;
        return binding;
    };

    fic::platform::PamCapabilityConfig capability;
    capability.provider = PamProviderKind::PamFaillock;
    capability.configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    capability.configPath = "/etc/security/faillock.conf";

    const auto deny = assignmentBinding(
        PamPolicyFeature::FailedAuthenticationAttempts, "deny");
    require(usesPamProviderManagedEntry(provider, capability, deny,
                PamPolicyFeature::FailedAuthenticationAttempts),
        "deny must use the managed entry path");
    const auto interval = assignmentBinding(
        PamPolicyFeature::FailedAuthenticationCountingPeriod,
        "fail_interval");
    require(usesPamProviderManagedEntry(provider, capability, interval,
                PamPolicyFeature::FailedAuthenticationCountingPeriod),
        "fail_interval must use the managed entry path");
    const auto unlock = assignmentBinding(
        PamPolicyFeature::FailedAuthenticationUnlockTime, "unlock_time");
    require(usesPamProviderManagedEntry(provider, capability, unlock,
                PamPolicyFeature::FailedAuthenticationUnlockTime),
        "unlock_time must use the managed entry path");

    // A Flag-syntax binding (even_deny_root) routes through Step 7E ONLY
    // for the EnforceForRoot feature; the scalar Attempts feature stays
    // legacy even with flag syntax.
    auto flag = deny;
    flag.syntax = PamNativeOptionSyntax::Flag;
    require(!usesPamProviderManagedEntry(provider, capability, flag,
                PamPolicyFeature::FailedAuthenticationAttempts),
        "flag syntax with a scalar feature must stay on the legacy path");
    require(usesPamProviderManagedEntry(provider, capability, flag,
                PamPolicyFeature::FailedAuthenticationEnforceForRoot),
        "even_deny_root flag must use the managed flag path");

    // Module-arguments mode stays legacy.
    auto arguments = capability;
    arguments.configurationMode =
        PamCapabilityConfigurationMode::ModuleArguments;
    require(!usesPamProviderManagedEntry(provider, arguments, deny,
                PamPolicyFeature::FailedAuthenticationAttempts),
        "module-arguments mode must stay on the legacy path");

    // Step 7C: the nine pam_pwquality scalar Assignment features use the
    // managed entry path; the enforce_for_root flag (Step 7E), the passwdqc
    // provider (ALT topology) and wrong capability modes do not.
    PamProviderDescriptor pwquality;
    pwquality.kind = PamProviderKind::PamPwquality;
    pwquality.name = "pam_pwquality";
    pwquality.defaultConfigTopology.primaryPath =
        "/etc/security/pwquality.conf";
    pwquality.defaultConfigTopology.dropInDirectories = {
        "/etc/security/pwquality.conf.d"};
    pwquality.defaultConfigTopology.explicitConfig =
        fic::platform::PamExplicitConfigSemantics::Unsupported;

    fic::platform::PamCapabilityConfig pwqualityCapability;
    pwqualityCapability.provider = PamProviderKind::PamPwquality;
    pwqualityCapability.configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    pwqualityCapability.configPath = "/etc/security/pwquality.conf";
    // ModuleArguments pwquality variant for the total-placement matrix.
    auto pwqualityArgumentsCapability = pwqualityCapability;
    pwqualityArgumentsCapability.configurationMode =
        PamCapabilityConfigurationMode::ModuleArguments;

    const std::vector<std::pair<PamPolicyFeature, const char*>> pwqualityScalars{
        {PamPolicyFeature::PasswordMinLength, "minlen"},
        {PamPolicyFeature::PasswordMinClasses, "minclass"},
        {PamPolicyFeature::PasswordCheckUsername, "usercheck"},
        {PamPolicyFeature::PasswordCheckGecos, "gecoscheck"},
        {PamPolicyFeature::PasswordMinChangedCharacters, "difok"},
        {PamPolicyFeature::PasswordMinLowercase, "lcredit"},
        {PamPolicyFeature::PasswordMinUppercase, "ucredit"},
        {PamPolicyFeature::PasswordMinDigits, "dcredit"},
        {PamPolicyFeature::PasswordMinOther, "ocredit"}};
    for (const auto& [feature, option] : pwqualityScalars) {
        require(usesPamProviderManagedEntry(pwquality, pwqualityCapability,
                    assignmentBinding(feature, option), feature),
            std::string("pwquality scalar ") + option +
                " must use the managed entry path");
    }

    // enforce_for_root: Assignment syntax is unroutable (Step 7E flags are
    // owned only through Flag-syntax bindings); the Flag syntax routes.
    const auto enforceForRoot = assignmentBinding(
        PamPolicyFeature::PasswordQualityEnforceForRoot, "enforce_for_root");
    require(!usesPamProviderManagedEntry(pwquality, pwqualityCapability,
                enforceForRoot,
                PamPolicyFeature::PasswordQualityEnforceForRoot),
        "pwquality enforce_for_root assignment syntax must stay legacy");
    auto pwqualityFlag = enforceForRoot;
    pwqualityFlag.syntax = PamNativeOptionSyntax::Flag;
    require(usesPamProviderManagedEntry(pwquality, pwqualityCapability,
                pwqualityFlag,
                PamPolicyFeature::PasswordQualityEnforceForRoot),
        "pwquality enforce_for_root flag must use the managed flag path");

    // Step 7D: pam_pwhistory password_history_depth uses the managed
    // entry path ONLY for the current Debian 13 / Ubuntu 24.04 / Ubuntu
    // 26.04-style typed contract (ProviderConfigFile + PamAuthUpdate).
    // Debian 12 (ModuleArguments), ALT p11 (AltTcbManaged) and the
    // enforce_for_root flag (Step 7E) stay outside the route. No distro
    // name is ever consulted — the typed topology/configuration contract
    // is the whole decision.
    PamProviderDescriptor pwhistory;
    pwhistory.kind = PamProviderKind::PamPwhistory;
    pwhistory.name = "pam_pwhistory";
    pwhistory.defaultConfigTopology.explicitConfig =
        fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology;
    fic::platform::PamCapabilityConfig pwhistoryCapability;
    pwhistoryCapability.provider = PamProviderKind::PamPwhistory;
    pwhistoryCapability.configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    pwhistoryCapability.topology =
        fic::platform::PamTopologyStrategyKind::PamAuthUpdate;
    pwhistoryCapability.configPath = "/etc/security/pwhistory.conf";

    const auto depth = assignmentBinding(
        PamPolicyFeature::PasswordHistoryDepth, "remember");
    require(usesPamProviderManagedEntry(pwhistory, pwhistoryCapability,
                depth, PamPolicyFeature::PasswordHistoryDepth),
        "pwhistory depth must use the managed entry path on "
        "ProviderConfigFile + PamAuthUpdate platforms");

    // ALT p11: AltTcbManaged topology keeps the legacy
    // /etc/security/fic-pwhistory.conf ownership (Step 7D routing false).
    auto altPwhistoryCapability = pwhistoryCapability;
    altPwhistoryCapability.topology =
        fic::platform::PamTopologyStrategyKind::AltTcbManaged;
    altPwhistoryCapability.configPath =
        "/etc/security/fic-pwhistory.conf";
    require(!usesPamProviderManagedEntry(pwhistory, altPwhistoryCapability,
                depth, PamPolicyFeature::PasswordHistoryDepth),
        "ALT AltTcbManaged pwhistory must stay on the legacy path");

    // Debian 12: ModuleArguments keeps the Step 6 joint coordinator.
    auto argumentsPwhistoryCapability = pwhistoryCapability;
    argumentsPwhistoryCapability.configurationMode =
        PamCapabilityConfigurationMode::ModuleArguments;
    require(!usesPamProviderManagedEntry(pwhistory,
                argumentsPwhistoryCapability, depth,
                PamPolicyFeature::PasswordHistoryDepth),
        "Debian 12 ModuleArguments pwhistory must stay on the Step 6 "
        "coordinator path");

    // enforce_for_root (Flag) routes through Step 7E on the managed
    // D13/U24/U26 contract; the Assignment syntax stays legacy.
    const auto historyEnforceForRoot = assignmentBinding(
        PamPolicyFeature::PasswordHistoryEnforceForRoot,
        "enforce_for_root");
    require(!usesPamProviderManagedEntry(pwhistory, pwhistoryCapability,
                historyEnforceForRoot,
                PamPolicyFeature::PasswordHistoryEnforceForRoot),
        "pwhistory enforce_for_root assignment syntax must stay legacy");
    auto historyFlag = historyEnforceForRoot;
    historyFlag.syntax = PamNativeOptionSyntax::Flag;
    require(usesPamProviderManagedEntry(pwhistory, pwhistoryCapability,
                historyFlag,
                PamPolicyFeature::PasswordHistoryEnforceForRoot),
        "pwhistory enforce_for_root flag must use the managed flag path");
    require(!usesPamProviderManagedEntry(pwhistory, altPwhistoryCapability,
                historyFlag,
                PamPolicyFeature::PasswordHistoryEnforceForRoot),
        "ALT AltTcbManaged pwhistory flag must stay on the legacy path");

    // Faillock whitelist must not accept pwquality features and vice versa.
    const auto minLength = assignmentBinding(
        PamPolicyFeature::PasswordMinLength, "minlen");
    require(!usesPamProviderManagedEntry(provider, capability, minLength,
                PamPolicyFeature::PasswordMinLength),
        "faillock must not route pwquality features");

    // ALT Linux: passwdqc assignments stay legacy (Step 7C never touches
    // the passwdqc topology).
    PamProviderDescriptor passwdqc;
    passwdqc.kind = PamProviderKind::PamPasswdqc;
    passwdqc.name = "pam_passwdqc";
    const auto passwdqcMin = assignmentBinding(
        PamPolicyFeature::PasswdqcStrengthThresholds, "min");
    require(!usesPamProviderManagedEntry(passwdqc, pwqualityCapability,
                passwdqcMin, PamPolicyFeature::PasswdqcStrengthThresholds),
        "passwdqc must stay on the legacy path");

    // Typed placement contract (TOTAL helper, no silent End fallback):
    // faillock/pwquality scalars are last-wins → EOF; the pwhistory
    // depth is first-match → BOF; every unroutable combination has NO
    // placement.
    require(pamProviderManagedEntryPlacement(provider, capability, deny,
                PamPolicyFeature::FailedAuthenticationAttempts) ==
                PamProviderBlockPlacementRequest::End,
        "faillock managed placement must be EOF");
    require(pamProviderManagedEntryPlacement(pwquality, pwqualityCapability,
                minLength, PamPolicyFeature::PasswordMinLength) ==
                PamProviderBlockPlacementRequest::End,
        "pwquality managed placement must be EOF");
    require(pamProviderManagedEntryPlacement(pwhistory, pwhistoryCapability,
                depth, PamPolicyFeature::PasswordHistoryDepth) ==
                PamProviderBlockPlacementRequest::Beginning,
        "pwhistory depth managed placement must be BOF (upstream "
        "pam_modutil_search_key first-match semantics)");
    // TOTAL contract matrix: the placement helper itself refuses every
    // unroutable combination — configuration mode, binding syntax,
    // provider kind, feature and pwhistory topology are all evaluated in
    // one place (no hidden routing checks remain in
    // usesPamProviderManagedEntry).
    // Configuration mode gate (ModuleArguments → no placement):
    require(!pamProviderManagedEntryPlacement(provider, arguments, deny,
                PamPolicyFeature::FailedAuthenticationAttempts).has_value(),
        "faillock ModuleArguments must have NO placement contract");
    require(!pamProviderManagedEntryPlacement(pwquality,
                pwqualityArgumentsCapability, minLength,
                PamPolicyFeature::PasswordMinLength).has_value(),
        "pwquality ModuleArguments must have NO placement contract");
    require(!pamProviderManagedEntryPlacement(pwhistory,
                argumentsPwhistoryCapability, depth,
                PamPolicyFeature::PasswordHistoryDepth).has_value(),
        "pwhistory ModuleArguments (Debian 12, Step 6 coordinator) must "
        "have NO placement contract");
    // Binding syntax gate (Flag → no placement, even for a whitelisted
    // scalar feature):
    auto flagSyntaxBinding = deny;
    flagSyntaxBinding.syntax = PamNativeOptionSyntax::Flag;
    require(!pamProviderManagedEntryPlacement(provider, capability,
                flagSyntaxBinding,
                PamPolicyFeature::FailedAuthenticationAttempts).has_value(),
        "faillock Flag binding must have NO placement contract");
    require(!pamProviderManagedEntryPlacement(pwquality,
                pwqualityCapability, flagSyntaxBinding,
                PamPolicyFeature::PasswordMinLength).has_value(),
        "pwquality Flag binding must have NO placement contract");
    auto historyFlagBinding = depth;
    historyFlagBinding.syntax = PamNativeOptionSyntax::Flag;
    require(!pamProviderManagedEntryPlacement(pwhistory,
                pwhistoryCapability, historyFlagBinding,
                PamPolicyFeature::PasswordHistoryDepth).has_value(),
        "pwhistory Flag binding must have NO placement contract");
    // Topology gate (ALT AltTcbManaged → no placement):
    require(!pamProviderManagedEntryPlacement(pwhistory,
                altPwhistoryCapability, depth,
                PamPolicyFeature::PasswordHistoryDepth).has_value(),
        "the ALT AltTcbManaged pwhistory combination must have NO "
        "placement contract");
    // Unrouted feature / provider gates:
    auto historyEnforceForRootFlag =
        assignmentBinding(PamPolicyFeature::PasswordHistoryEnforceForRoot,
            "enforce_for_root");
    historyEnforceForRootFlag.syntax = PamNativeOptionSyntax::Flag;
    require(pamProviderManagedEntryPlacement(pwhistory,
                pwhistoryCapability, historyEnforceForRootFlag,
                PamPolicyFeature::PasswordHistoryEnforceForRoot) ==
                PamProviderBlockPlacementRequest::Beginning,
        "the pwhistory flag combination must use the Step 7E BOF placement");
    require(!pamProviderManagedEntryPlacement(provider, capability,
                minLength, PamPolicyFeature::PasswordMinLength).has_value(),
        "an unrouted faillock feature must have NO placement contract");
    require(!pamProviderManagedEntryPlacement(passwdqc, pwqualityCapability,
                passwdqcMin,
                PamPolicyFeature::PasswdqcStrengthThresholds).has_value(),
        "passwdqc must have NO placement contract");

    // ROUTING EQUALITY INVARIANT: usesPamProviderManagedEntry is a thin
    // wrapper — for the representative matrix its result must be exactly
    // placement.has_value() (no hidden routing checks on either side).
    const std::vector<std::tuple<PamProviderDescriptor,
        fic::platform::PamCapabilityConfig, PamProviderPolicyBinding,
        PamPolicyFeature>> routingMatrix{
        {provider, capability, deny,
            PamPolicyFeature::FailedAuthenticationAttempts},
        {provider, arguments, deny,
            PamPolicyFeature::FailedAuthenticationAttempts},
        {provider, capability, flagSyntaxBinding,
            PamPolicyFeature::FailedAuthenticationAttempts},
        {pwquality, pwqualityCapability, minLength,
            PamPolicyFeature::PasswordMinLength},
        {pwquality, pwqualityArgumentsCapability, minLength,
            PamPolicyFeature::PasswordMinLength},
        {pwquality, pwqualityCapability, enforceForRoot,
            PamPolicyFeature::PasswordQualityEnforceForRoot},
        {pwhistory, pwhistoryCapability, depth,
            PamPolicyFeature::PasswordHistoryDepth},
        {pwhistory, argumentsPwhistoryCapability, depth,
            PamPolicyFeature::PasswordHistoryDepth},
        {pwhistory, altPwhistoryCapability, depth,
            PamPolicyFeature::PasswordHistoryDepth},
        {pwhistory, pwhistoryCapability, historyFlagBinding,
            PamPolicyFeature::PasswordHistoryDepth},
        {pwhistory, pwhistoryCapability, historyEnforceForRootFlag,
            PamPolicyFeature::PasswordHistoryEnforceForRoot},
        {passwdqc, pwqualityCapability, passwdqcMin,
            PamPolicyFeature::PasswdqcStrengthThresholds}};
    for (const auto& [matrixProvider, matrixCapability, matrixBinding,
             matrixFeature] : routingMatrix) {
        const bool routed = usesPamProviderManagedEntry(matrixProvider,
            matrixCapability, matrixBinding, matrixFeature);
        const bool placed = pamProviderManagedEntryPlacement(matrixProvider,
            matrixCapability, matrixBinding, matrixFeature).has_value();
        require(routed == placed,
            "routing/placement invariant violated for provider " +
                std::string(matrixProvider.name));
    }

    require(pamProviderAbsentContainerDecision(provider) ==
                PamProviderAbsentContainerDecision::FailClosed,
        "pam_faillock absent-container decision must fail closed");
    require(pamProviderAbsentContainerDecision(pwquality) ==
                PamProviderAbsentContainerDecision::FailClosed,
        "pam_pwquality absent-container decision must fail closed (no "
        "production proof contract for a missing pwquality primary)");
}

void testAbsentContainerFailClosed() {
    Harness harness;
    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        "absent container with FailClosed decision must refuse");
    require(!harness.error.empty(), "typed error must be reported");
    require(harness.entryRecords("failed_authentication_attempts").empty() &&
                harness.containerRecords().empty(),
        "a refused absent-container apply must prepare NO journal records");
    require(!std::filesystem::exists(harness.configPath),
        "absent container must not be created");
}

void testFreshCreateFicOwnedContainer() {
    Harness harness;
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5",
                               PamProviderAbsentContainerDecision::
                                   CreateFicOwned),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "fresh create must be Applied");

    // Physical: exactly the FIC serialization, block proven.
    auto parse = harness.parse();
    require(parse.ok && parse.view.present, "block must be present");
    require(parse.view.provider == "pam_faillock", "provider mismatch");
    require(parse.view.entries.size() == 1, "one entry expected");
    require(parse.view.entries.front().body == "deny = 5",
        "entry body mismatch");

    // Journal: entry Applied + FIC-owned container provenance Applied.
    const auto entry = harness.soleEntryRecord(
        "failed_authentication_attempts", "fresh create");
    require(entry.status == MutationStatus::Applied,
        "entry record must be Applied");
    const auto* payload = std::get_if<UndoRemovePamProviderManagedEntry>(
        &entry.undo.payload);
    require(payload != nullptr, "entry payload type mismatch");
    require(payload->appliedBody == "deny = 5", "payload body mismatch");
    require(payload->previousAppliedBody.empty(),
        "fresh create must carry no previous body");

    const auto container = harness.soleContainerRecord("fresh create");
    require(container.status == MutationStatus::Applied,
        "container record must be Applied");
    const auto* containerPayload =
        std::get_if<UndoOwnPamProviderContainer>(&container.undo.payload);
    require(containerPayload != nullptr, "container payload type mismatch");
    require(containerPayload->providerName == "pam_faillock",
        "container payload provider mismatch");
}

void testAppliedNoOpIsProven() {
    auto harness = appliedPolicy(
        "failed_authentication_attempts", "deny", "5");
    const std::string before = readFile(harness.configPath);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::AppliedNoOp,
        "proven exact state must be a no-op");
    require(readFile(harness.configPath) == before,
        "a no-op must not touch the file");
    require(harness.entryRecords("failed_authentication_attempts").size() ==
            1,
        "a no-op must not allocate a second record");
}

void testSecondPolicyReusesContainerProvenance() {
    auto harness = appliedPolicy(
        "failed_authentication_attempts", "deny", "5");
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request(
                               "failed_authentication_counting_period",
                               "fail_interval", "15"),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "second policy apply must be Applied");
    require(harness.containerRecords().size() == 1,
        "the second policy must reuse the Applied container provenance, "
        "never fabricate a second one");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 2,
        "both entries must live in one block");
}

// ---------------------------------------------------------------------------
// §19 crash-recovery matrix
// ---------------------------------------------------------------------------

// Prepared fresh record, physical entry absent → continue (same id).
void testRecoveryPreparedFreshAbsent() {
    auto harness = appliedPolicy("failed_authentication_counting_period",
        "fail_interval", "15");
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "recovery continuation must be Applied");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "recovery");
    require(record.id == id, "recovery must keep the prepared record id");
    require(record.status == MutationStatus::Applied,
        "record must be completed as Applied");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 2,
        "both policies must be proven after recovery");
}

// Prepared fresh record, physical target present → adopt (same id).
void testRecoveryPreparedFreshTargetPresent() {
    Harness harness;
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");

    // Crash simulation: physical write happened, journal completion not.
    writeFile(harness.configPath, "# admin tweak\n");
    writePhysicalEntry(harness, readFile(harness.configPath),
        "failed_authentication_attempts", "deny", "5", id);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        harness.error);
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "adopt");
    require(record.id == id, "adoption must keep the prepared record id");
    require(record.status == MutationStatus::Applied,
        "adopted record must be Applied");
}

// Prepared update record, previous body present → continue (same id).
void testRecoveryPreparedUpdatePreviousPresent() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId appliedId =
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id;

    // Crash between journal refresh and physical completion.
    prepareUpdateTransaction(harness, "failed_authentication_attempts",
        "deny", "deny = 5", "deny = 10");

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "10"),
                outcome),
        harness.error);
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "update recovery");
    require(record.id == appliedId, "update recovery must keep the id");
    require(record.status == MutationStatus::Applied,
        "update recovery must complete as Applied");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 10",
        "physical entry must carry the target body");
}

// Prepared update record, target body present → adopt (same id).
void testRecoveryPreparedUpdateTargetPresent() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId appliedId =
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id;

    // Journal refreshed to the update transaction, physical refresh
    // happened, crash before Applied.
    prepareUpdateTransaction(harness, "failed_authentication_attempts",
        "deny", "deny = 5", "deny = 10");
    writePhysicalEntry(harness, readFile(harness.configPath),
        "failed_authentication_attempts", "deny", "10", appliedId);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "10"),
                outcome),
        harness.error);
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "update adopt");
    require(record.id == appliedId &&
                record.status == MutationStatus::Applied,
        "target-present adoption must complete the same record");
}

// Prepared fresh record + conflicting physical state → fail closed.
void testPreparedConflictRefused() {
    auto harness = appliedPolicy("failed_authentication_counting_period",
        "fail_interval", "15");
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");

    // Foreign physical entry with the SAME id but a different body.
    writePhysicalEntry(harness, "", "failed_authentication_attempts",
        "deny", "7", id);
    const std::string before = readFile(harness.configPath);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        "PreparedConflict must fail closed");
    require(readFile(harness.configPath) == before,
        "a refused conflict must not touch the file");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "conflict");
    require(record.id == id && record.status == MutationStatus::Prepared,
        "the prepared provenance must be kept recoverable");
}

// Applied record + physically missing owned entry → fail closed.
void testAppliedMissingRefused() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    writeFile(harness.configPath, "# entry externally released\n");

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        "AppliedMissing must fail closed");
    require(harness.error.find("AppliedMissing") != std::string::npos,
        "typed AppliedMissing diagnostic expected, got: " + harness.error);
    require(readFile(harness.configPath) == "# entry externally released\n",
        "drifted/externally released state must never be recreated");
}

// Applied record + manually drifted body (same id) → fail closed.
void testAppliedDriftedRefused() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId id =
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id;
    // Manual drift under the SAME id (body edited, identity kept).
    writePhysicalEntry(harness, readFile(harness.configPath),
        "failed_authentication_attempts", "deny", "99", id);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        "AppliedDrifted must fail closed");
    require(harness.error.find("AppliedDrifted") != std::string::npos,
        "typed AppliedDrifted diagnostic expected, got: " + harness.error);
}

// ---------------------------------------------------------------------------
// §20 update lifecycle + physical id conflict
// ---------------------------------------------------------------------------

void testUpdateLifecycleSameId() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId firstId =
        harness.soleEntryRecord("failed_authentication_attempts", "first")
            .id;

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "10"),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "value update must be Applied");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "update");
    require(record.id == firstId, "the update must keep the journal id");
    require(record.status == MutationStatus::Applied,
        "the record must be Applied after the update");
    const auto* payload = std::get_if<UndoRemovePamProviderManagedEntry>(
        &record.undo.payload);
    require(payload != nullptr && payload->appliedBody == "deny = 10",
        "the journal must carry the new target body");

    // Re-apply the new value: proven no-op.
    outcome = PamProviderManagedEntryOutcome::Applied;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "10"),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::AppliedNoOp,
        "re-applying the applied value must be a no-op");
}

void testForeignMutationIdConflictRefused() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    // Forge a foreign id under the same (policy, key): ABA protection.
    std::string drifted = readFile(harness.configPath);
    const std::string marker = "mutation=";
    auto position = drifted.find(marker);
    require(position != std::string::npos, "entry marker must exist");
    const std::string idToken = std::to_string(
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id);
    require(drifted.compare(position + marker.size(), idToken.size(),
                idToken) == 0,
        "physical id must match the journal id before forging");
    drifted.replace(position + marker.size(), idToken.size(), "9");
    writeFile(harness.configPath, drifted);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "10"),
                outcome),
        "a foreign physical mutation id must fail closed");
    require(readFile(harness.configPath) == drifted,
        "the forged state must not be rewritten");
}

// ---------------------------------------------------------------------------
// §30–§32: three policies, one block, byte-exact foreign bytes
// ---------------------------------------------------------------------------

void testThreePoliciesOneBlockForeignBytesExact() {
    const std::string foreign = "deny = 3\n# admin tweak";
    Harness harness;
    writeFile(harness.configPath, foreign);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        harness.error);
    require(harness.apply(harness.request(
                               "failed_authentication_counting_period",
                               "fail_interval", "15"),
                outcome),
        harness.error);
    require(harness.apply(harness.request(
                               "failed_authentication_unlock_time",
                               "unlock_time", "600"),
                outcome),
        harness.error);

    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 3,
        "all three policies must live in one block");
    require(parse.view.leadOwnedNewline,
        "the block appended after non-empty foreign bytes must declare "
        "lead=newline");
    // Foreign bytes byte-exact (the lead LF is FIC-owned serialization).
    const std::string content = readFile(harness.configPath);
    require(content.compare(0, foreign.size(), foreign) == 0,
        "foreign bytes must survive byte-exact");

    // Neighbor ids stable across a no-op re-apply.
    const auto idsBefore = parse.view.entries;
    outcome = PamProviderManagedEntryOutcome::Applied;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::AppliedNoOp,
        "no-op re-apply expected");
    auto after = harness.parse();
    require(after.ok && after.view.entries.size() == 3,
        "block must stay intact");
    for (std::size_t index = 0; index < 3; ++index) {
        require(after.view.entries[index].mutationId ==
                    idsBefore[index].mutationId,
            "neighbor mutation ids must stay stable");
        require(after.view.entries[index].body == idsBefore[index].body,
            "neighbor bodies must stay stable");
    }
}

// §30: daemon restart — a fresh journal object over the same persistent
// state recovers the prepared transaction.
void testRestartRecovery() {
    auto harness = appliedPolicy("failed_authentication_counting_period",
        "fail_interval", "15");
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");

    // Fresh MutationJournal over the same persistent document = restart.
    Harness restarted(harness.journalPath);
    restarted.configPath = harness.configPath;
    require(restarted.journal.load(restarted.error),
        "restart journal load failed: " + restarted.error);

    PamProviderManagedEntryOutcome outcome;
    require(restarted.apply(restarted.request(
                                "failed_authentication_attempts", "deny",
                                "5"),
                outcome),
        restarted.error);
    const auto record = restarted.soleEntryRecord(
        "failed_authentication_attempts", "restart recovery");
    require(record.id == id && record.status == MutationStatus::Applied,
        "restart recovery must complete the prepared transaction");
}

// ---------------------------------------------------------------------------
// Step 7B follow-up: durable-target-first recovery + prepared container
// provenance witness regressions
// ---------------------------------------------------------------------------

// §8/§30: Prepared 5→10, physical still 5, current desired 20. The durable
// transaction MUST complete first: semantic sequence [10, 20], same id,
// final Applied target 20 — never a direct 5→20 write.
void testRecoveryDesiredChangedPreviousPresent() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId id =
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id;
    prepareUpdateTransaction(harness, "failed_authentication_attempts",
        "deny", "deny = 5", "deny = 10");

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "20"),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 2 &&
                harness.verifiedValues[0] == "10" &&
                harness.verifiedValues[1] == "20",
        "semantic verification must prove the durable target 10 first, "
        "then the current desired 20");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "changed desired");
    require(record.id == id, "both transitions must keep the same id");
    require(record.status == MutationStatus::Applied,
        "the final state must be Applied");
    const auto* payload = std::get_if<UndoRemovePamProviderManagedEntry>(
        &record.undo.payload);
    require(payload != nullptr && payload->appliedBody == "deny = 20",
        "the journal target must be the current desired body");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 20" &&
                parse.view.entries.front().mutationId == id,
        "physical entry must carry the desired body under the same id");
}

// §29: Prepared 5→10, physical already 10, current desired 20. Adoption
// first (semantic 10, no rewrite), then refresh 10→20: semantic sequence
// [10, 20], same id.
void testRecoveryDesiredChangedTargetPresent() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId id =
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id;
    prepareUpdateTransaction(harness, "failed_authentication_attempts",
        "deny", "deny = 5", "deny = 10");
    writePhysicalEntry(harness, readFile(harness.configPath),
        "failed_authentication_attempts", "deny", "10", id);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "20"),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 2 &&
                harness.verifiedValues[0] == "10" &&
                harness.verifiedValues[1] == "20",
        "adoption must verify the durable target 10 before the desired 20");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "target adoption");
    require(record.id == id && record.status == MutationStatus::Applied,
        "adoption + refresh must keep the same record id");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 20" &&
                parse.view.entries.front().mutationId == id,
        "final physical state must be the desired body under the same id");
}

// §31: fresh Prepared transaction (target=5, physical entry absent) with
// current desired 7 in an existing container: 5 is completed first
// (semantic [5, 7]), same id.
void testRecoveryDesiredChangedFreshPrepared() {
    auto harness = appliedPolicy("failed_authentication_counting_period",
        "fail_interval", "15");
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "7"),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 2 &&
                harness.verifiedValues[0] == "5" &&
                harness.verifiedValues[1] == "7",
        "the fresh durable target 5 must be completed before the desired 7");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "fresh changed desired");
    require(record.id == id && record.status == MutationStatus::Applied,
        "both transitions must keep the same record id");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 2,
        "both policies must be present");
    for (const auto& entry : parse.view.entries) {
        if (entry.policy == "failed_authentication_attempts") {
            require(entry.body == "deny = 7" && entry.mutationId == id,
                "the refreshed entry must carry the desired body");
        }
    }
}

// §31 FIC-created container variant: fresh Prepared entry + Prepared
// container provenance + absent file, current desired changed. The
// exclusive create completes the durable target 5 first, then refreshes
// to 7; the container provenance is completed by the creation itself.
void testRecoveryDesiredChangedFreshCreatedContainer() {
    Harness harness;
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");
    prepareContainerRecord(harness);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "7",
                               PamProviderAbsentContainerDecision::
                                   CreateFicOwned),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 2 &&
                harness.verifiedValues[0] == "5" &&
                harness.verifiedValues[1] == "7",
        "the FIC-created container flow must complete the durable target "
        "5 before the desired 7");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "fresh created container");
    require(record.id == id && record.status == MutationStatus::Applied,
        "same id through both transitions");
    require(harness.containerRecords().size() == 1 &&
                harness.containerRecords().front().status ==
                    MutationStatus::Applied,
        "the container provenance must be Applied after the create");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 7",
        "the created entry must carry the desired body");
}

// Crash window INSIDE the fresh FIC-created container lifecycle: the entry
// Prepared record was durably committed, but the crash happened BEFORE the
// container provenance record was prepared and before the physical create.
// This intermediate journal state (entry Prepared + NO container record +
// absent file) is legitimate and must be recovered: recovery prepares the
// missing container provenance itself, physically creates the DURABLE
// journal target first, and only then reconciles the changed current
// desired value through a fresh trusted read — same entry id throughout.
void testRecoveryFreshCreatedContainerProvenanceMissing() {
    Harness harness;
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");
    // NOTE: no prepareContainerRecord(harness) — the crash window is
    // before the container provenance was durably prepared.
    require(harness.containerRecords().empty(),
        "the crash state must have no container provenance record");
    require(!std::filesystem::exists(harness.configPath),
        "the crash state must have an absent physical container");

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "7",
                               PamProviderAbsentContainerDecision::
                                   CreateFicOwned),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 2 &&
                harness.verifiedValues[0] == "5" &&
                harness.verifiedValues[1] == "7",
        "the durable journal target 5 must be created before the desired 7");
    // Entry journal: exactly one active record, same id, Applied, final
    // desired body.
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "provenance-missing recovery");
    require(record.id == id && record.status == MutationStatus::Applied,
        "the same entry record id must carry both transitions");
    const auto* payload =
        std::get_if<UndoRemovePamProviderManagedEntry>(
            &record.undo.payload);
    require(payload != nullptr && payload->appliedBody == "deny = 7",
        "the entry record must be Applied with the desired body");
    // Container journal: exactly one active record (created by THIS
    // recovery, no duplicates), Applied.
    require(harness.containerRecords().size() == 1 &&
                harness.containerRecords().front().status ==
                    MutationStatus::Applied,
        "the recovery must prepare exactly one container provenance and "
        "complete it as Applied");
    // Physical state: strict parse, one exact entry with the same id.
    auto parse = harness.parse();
    require(parse.ok, "strict parse of the recovered container failed: " +
            parse.error);
    require(parse.view.provider == "pam_faillock" &&
                parse.view.entries.size() == 1 &&
                parse.view.entries.front().policy ==
                    "failed_authentication_attempts" &&
                parse.view.entries.front().body == "deny = 7" &&
                parse.view.entries.front().mutationId == id &&
                // EOF placement contract: the created block is a lone
                // FIC-owned block (nothing after the END marker), which
                // satisfies EOF per the grammar contract (the
                // single-valued effectivePlacement diagnostic reports
                // BOF for a lone block — "BOF wins").
                parse.view.atEnd,
        "the physical state must be exactly one FIC-owned entry with the "
        "same mutation id at EOF");
}

// Same crash window with the current desired value UNCHANGED: the recovery
// completes the durable target (which equals the desired value) in a single
// transition — one semantic verification, one physical create, entry and
// container Applied with the same entry id.
void testRecoveryFreshCreatedContainerProvenanceMissingDesiredUnchanged() {
    Harness harness;
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");
    require(harness.containerRecords().empty(),
        "the crash state must have no container provenance record");
    require(!std::filesystem::exists(harness.configPath),
        "the crash state must have an absent physical container");

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5",
                               PamProviderAbsentContainerDecision::
                                   CreateFicOwned),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 1 &&
                harness.verifiedValues[0] == "5",
        "the desired value equals the durable target: exactly one semantic "
        "verification of the created state");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "provenance-missing no-change");
    require(record.id == id && record.status == MutationStatus::Applied,
        "the entry must be Applied with the same id");
    require(harness.containerRecords().size() == 1 &&
                harness.containerRecords().front().status ==
                    MutationStatus::Applied,
        "exactly one container provenance record must be Applied");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 5" &&
                parse.view.entries.front().mutationId == id &&
                parse.view.atEnd,
        "the physical state must carry the durable target with the same id");
}


// §9: the second transition (10→20) fails after the durable transaction
// (5→10) was completed. The journal must hold a normal recoverable
// Prepared previous=10 target=20 — never the stale 5→10 provenance.
void testFailureBetweenTransitionsIsRecoverable() {
    auto harness = appliedPolicy("failed_authentication_attempts", "deny",
        "5");
    const MutationId id =
        harness.soleEntryRecord("failed_authentication_attempts", "base")
            .id;
    prepareUpdateTransaction(harness, "failed_authentication_attempts",
        "deny", "deny = 5", "deny = 10");
    harness.failSemanticFor.insert("20");

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "20"),
                outcome),
        "the injected semantic failure must fail the apply");
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "between transitions");
    require(record.id == id, "the failed refresh keeps the same id");
    require(record.status == MutationStatus::Prepared,
        "the failed refresh must be recoverable (Prepared)");
    const auto* payload = std::get_if<UndoRemovePamProviderManagedEntry>(
        &record.undo.payload);
    require(payload != nullptr &&
                payload->previousAppliedBody == "deny = 10" &&
                payload->appliedBody == "deny = 20",
        "the journal must hold the NEW 10→20 transition, not the stale "
        "5→10 provenance");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 20",
        "the physical write of the new transition already happened");

    // The failed state is normally recoverable: the physical target is
    // adopted on the next apply.
    harness.failSemanticFor.clear();
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "20"),
                outcome),
        harness.error);
    require(harness.verifiedValues.size() == 1 &&
                harness.verifiedValues[0] == "20",
        "the recovery must adopt the already-written target");
    const auto recovered = harness.soleEntryRecord(
        "failed_authentication_attempts", "recovered between");
    require(recovered.id == id && recovered.status == MutationStatus::Applied,
        "the next apply must complete the same record");
}

// §16/§19: container Prepared, file carries a canonical FIC block with an
// entry id that has NO active journal record — markers alone are never
// creation proof. Fail closed BEFORE any mutation: file byte-exact,
// container stays Prepared, no new entry record, no new physical entry.
void testPreparedContainerWithoutWitnessRefused() {
    Harness harness;
    const MutationId containerId = prepareContainerRecord(harness);

    // Hand-built physical state: FIC block + entry id 42, no journal
    // record for it (copied file / stale block / external creation).
    const std::string foreign = "# administrator bytes\n";
    writePhysicalEntry(harness, foreign, "failed_authentication_attempts",
        "deny", "5", 42);
    const std::string before = readFile(harness.configPath);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        "a Prepared container without an exact creation witness must fail "
        "closed");
    require(harness.error.find("witness") != std::string::npos,
        "typed missing-witness diagnostic expected, got: " + harness.error);
    require(readFile(harness.configPath) == before,
        "a refused witness-less apply must not touch the file");
    const auto containers = harness.containerRecords();
    require(containers.size() == 1 && containers.front().id == containerId &&
                containers.front().status == MutationStatus::Prepared,
        "the container provenance must stay Prepared");
    require(harness.entryRecords("failed_authentication_attempts").empty(),
        "no entry journal record may be created without a witness");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().mutationId == 42,
        "the pre-existing physical state must be untouched");
}

// §17 (apply A): crash after the physical create of the creator entry but
// before the entry/container completion. The PRE-EXISTING physical creator
// entry proves the container creation witness; the recovery completes both.
void testPreparedContainerCreatorWitnessCompletes() {
    Harness harness;
    prepareContainerRecord(harness);
    const MutationId id = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");
    writePhysicalEntry(harness, "", "failed_authentication_attempts",
        "deny", "5", id);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5"),
                outcome),
        harness.error);
    const auto record = harness.soleEntryRecord(
        "failed_authentication_attempts", "creator recovery");
    require(record.id == id && record.status == MutationStatus::Applied,
        "the creator entry must be completed with the same id");
    require(harness.containerRecords().size() == 1 &&
                harness.containerRecords().front().status ==
                    MutationStatus::Applied,
        "the container provenance must be reconciled from the proven "
        "witness");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "deny = 5" &&
                parse.view.entries.front().mutationId == id,
        "the adopted entry must be untouched");
}

// §25: crash during policy A; the first policy applied after restart is B.
// B must prove the historical creation transaction A (exact journal↔physical
// witness), reconcile the container provenance, and only then mutate — B
// itself never becomes the creation evidence.
void testPreparedContainerCrossPolicyWitness() {
    Harness harness;
    prepareContainerRecord(harness);
    const MutationId creatorId = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");
    writePhysicalEntry(harness, "", "failed_authentication_attempts",
        "deny", "5", creatorId);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request(
                               "failed_authentication_counting_period",
                               "fail_interval", "15"),
                outcome),
        harness.error);
    require(harness.containerRecords().size() == 1 &&
                harness.containerRecords().front().status ==
                    MutationStatus::Applied,
        "B must reconcile the container provenance from A's witness");
    const auto creator = harness.soleEntryRecord(
        "failed_authentication_attempts", "cross-policy creator");
    require(creator.id == creatorId &&
                creator.status == MutationStatus::Prepared,
        "the creator transaction stays untouched and recoverable");
    auto parse = harness.parse();
    require(parse.ok && parse.view.entries.size() == 2,
        "both the creator entry and the new policy entry must exist");
    for (const auto& entry : parse.view.entries) {
        if (entry.policy == "failed_authentication_attempts") {
            require(entry.body == "deny = 5" &&
                        entry.mutationId == creatorId,
                "the creator entry must survive byte-exact");
        }
    }
}

// Applied-exact creator entry is also an accepted witness state.
void testPreparedContainerAppliedWitness() {
    Harness harness;
    prepareContainerRecord(harness);
    const MutationId creatorId = prepareEntryRecord(harness,
        "failed_authentication_attempts", "deny = 5", "");
    writePhysicalEntry(harness, "", "failed_authentication_attempts",
        "deny", "5", creatorId);
    require(harness.journal.setStatus(
                creatorId, MutationStatus::Applied, harness.error),
        harness.error);

    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.request(
                               "failed_authentication_counting_period",
                               "fail_interval", "15"),
                outcome),
        harness.error);
    require(harness.containerRecords().front().status ==
                MutationStatus::Applied,
        "an Applied-exact creator entry proves the container creation");
}

// §18: wrong creator identity (foreign physical id or drifted body under
// the creator id) is never a witness: fail closed, container stays
// Prepared, no physical mutation.
void testPreparedContainerWrongCreatorIdentityRefused() {
    // Variant 1: creator body present under a FOREIGN physical id.
    {
        Harness harness;
        prepareContainerRecord(harness);
        prepareEntryRecord(harness, "failed_authentication_attempts",
            "deny = 5", "");
        writePhysicalEntry(harness, "", "failed_authentication_attempts",
            "deny", "5", 99);
        const std::string before = readFile(harness.configPath);

        PamProviderManagedEntryOutcome outcome;
        require(!harness.apply(harness.request(
                                    "failed_authentication_attempts", "deny",
                                    "5"),
                        outcome),
            "a foreign physical id must not witness the creation");
        require(readFile(harness.configPath) == before,
            "no physical mutation may happen");
        require(harness.containerRecords().front().status ==
                    MutationStatus::Prepared,
            "the container provenance must stay Prepared");
    }
    // Variant 2: creator id present but a drifted body.
    {
        Harness harness;
        prepareContainerRecord(harness);
        const MutationId id = prepareEntryRecord(harness,
            "failed_authentication_attempts", "deny = 5", "");
        writePhysicalEntry(harness, "", "failed_authentication_attempts",
            "deny", "7", id);
        const std::string before = readFile(harness.configPath);

        PamProviderManagedEntryOutcome outcome;
        require(!harness.apply(harness.request(
                                    "failed_authentication_attempts", "deny",
                                    "5"),
                        outcome),
            "a drifted creator body must not witness the creation");
        require(readFile(harness.configPath) == before,
            "no physical mutation may happen");
        require(harness.containerRecords().front().status ==
                    MutationStatus::Prepared,
            "the container provenance must stay Prepared");
    }
}

// ---------------------------------------------------------------------------
// Step 7C: pam_pwquality scalars on the shared managed-entry executor.
// ---------------------------------------------------------------------------

// The nine pwquality scalar features with their (managed key, encoding,
// logical value, native body) expectations for the canonical logical values
// used in the shared-block test. Native bodies are produced by the
// EXISTING codec layer: Direct → verbatim; YesNoInteger yes/no → 1/0;
// MinimumCredit N → -N (0 → 0).
struct PwqualityScalarSpec {
    const char* policyName;
    const char* managedKey;
    PamNativeValueEncoding encoding;
    const char* logicalValue;
    const char* nativeBody;
};

const PwqualityScalarSpec pwqualityScalarSpecs[] = {
    {"password_min_length", "minlen", PamNativeValueEncoding::Direct, "14",
        "minlen = 14"},
    {"password_min_classes", "minclass", PamNativeValueEncoding::Direct, "4",
        "minclass = 4"},
    {"password_check_username", "usercheck",
        PamNativeValueEncoding::YesNoInteger, "yes", "usercheck = 1"},
    {"password_check_gecos", "gecoscheck",
        PamNativeValueEncoding::YesNoInteger, "yes", "gecoscheck = 1"},
    {"password_min_changed_characters", "difok",
        PamNativeValueEncoding::Direct, "3", "difok = 3"},
    {"password_min_lowercase", "lcredit",
        PamNativeValueEncoding::MinimumCredit, "2", "lcredit = -2"},
    {"password_min_uppercase", "ucredit",
        PamNativeValueEncoding::MinimumCredit, "2", "ucredit = -2"},
    {"password_min_digits", "dcredit",
        PamNativeValueEncoding::MinimumCredit, "2", "dcredit = -2"},
    {"password_min_other", "ocredit",
        PamNativeValueEncoding::MinimumCredit, "1", "ocredit = -1"},
};

// Encodes a logical policy value through the production codec (the same
// encodePamNativeValue call PamOptionPolicy::applyPam performs before the
// managed routing) — the executor must only ever see native values.
std::string encodePwqualityLogical(const PwqualityScalarSpec& spec) {
    std::string native;
    std::string error;
    require(encodePamNativeValue(spec.encoding, spec.logicalValue, native,
                error),
        std::string("codec rejected ") + spec.managedKey + "=" +
            spec.logicalValue + ": " + error);
    return native;
}

// Builds the §22 foreign topology: two foreign drop-ins (they override the
// primary in the DropInsThenPrimary evaluator model until FIC writes EOF)
// and a foreign primary with an earlier admin assignment.
void writePwqualityForeignTopology(Harness& harness) {
    const auto dropInDirectory = harness.pwqualityDropInDirectory();
    std::filesystem::create_directories(dropInDirectory);
    writeFile(dropInDirectory / "10-vendor.conf", "minlen = 8\n");
    writeFile(dropInDirectory / "90-admin.conf",
        "usercheck = 0\nminclass = 1\n");
    writeFile(harness.pwqualityConfigPath,
        "# administrator primary\nminclass = 2\n");
}

// §22 + §24: nine pwquality scalars share ONE provider block in the
// primary; drop-ins and foreign primary bytes stay byte-exact; no
// container provenance for a pre-existing primary; native encoding
// (yes/no→1/0, minimum N→-N) is applied by the existing codec layer.
void testPwqualitySharedBlockNinePolicies() {
    Harness harness;
    writePwqualityForeignTopology(harness);
    const std::string dropInVendorBefore =
        readFile(harness.pwqualityDropInDirectory() / "10-vendor.conf");
    const std::string dropInAdminBefore =
        readFile(harness.pwqualityDropInDirectory() / "90-admin.conf");
    const std::string primaryBefore =
        readFile(harness.pwqualityConfigPath);

    for (const auto& spec : pwqualityScalarSpecs) {
        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(
                    harness.pwqualityRequest(spec.policyName, spec.managedKey,
                        encodePwqualityLogical(spec)),
                    outcome),
            harness.error);
    }

    // One shared pam_pwquality block with nine FIC entries at EOF.
    auto parse = harness.parse(harness.pwqualityConfigPath);
    require(parse.ok, "strict parse of the shared pwquality block failed: " +
            parse.error);
    require(parse.view.provider == "pam_pwquality" &&
                parse.view.entries.size() == 9,
        "exactly one provider=pam_pwquality block with nine entries");
    require(parse.view.atEnd,
        "the shared pwquality block must satisfy the EOF placement");
    for (const auto& spec : pwqualityScalarSpecs) {
        bool found = false;
        for (const auto& entry : parse.view.entries) {
            if (entry.policy == spec.policyName) {
                require(!found,
                    std::string("duplicate entry for ") + spec.policyName);
                found = true;
                require(entry.body == spec.nativeBody,
                    std::string("native body of ") + spec.policyName +
                        " must be the encoded value, got " + entry.body);
            }
        }
        require(found, std::string("missing entry for ") + spec.policyName);
    }

    // Foreign topology byte-exact: drop-ins untouched, primary foreign
    // bytes preserved outside the FIC serialization.
    require(readFile(harness.pwqualityDropInDirectory() / "10-vendor.conf") ==
                dropInVendorBefore,
        "drop-in 10-vendor.conf must stay byte-exact");
    require(readFile(harness.pwqualityDropInDirectory() / "90-admin.conf") ==
                dropInAdminBefore,
        "drop-in 90-admin.conf must stay byte-exact");
    const std::string primaryAfter = readFile(harness.pwqualityConfigPath);
    require(primaryAfter.find("# administrator primary") !=
                std::string::npos &&
                primaryAfter.find("\nminclass = 2\n") != std::string::npos &&
                primaryAfter.substr(0, primaryBefore.size()) ==
                    primaryBefore,
        "foreign primary bytes must survive byte-exact before the block");

    // Pre-existing primary: FIC owns only its entries — no container
    // provenance is fabricated.
    require(harness.containerRecords("pam_pwquality").empty(),
        "a pre-existing pwquality primary must never receive container "
        "provenance");
    for (const auto& spec : pwqualityScalarSpecs) {
        const auto record = harness.soleEntryRecord(
            spec.policyName, "pwquality shared block");
        require(record.status == MutationStatus::Applied,
            std::string("journal record of ") + spec.policyName +
                " must be Applied");
        const auto* payload =
            std::get_if<UndoRemovePamProviderManagedEntry>(
                &record.undo.payload);
        require(payload != nullptr &&
                    payload->providerName == "pam_pwquality" &&
                    payload->configPath ==
                        harness.pwqualityConfigPath.string() &&
                    payload->managedKey == spec.managedKey &&
                    payload->appliedBody == spec.nativeBody,
            std::string("journal identity of ") + spec.policyName +
                " must bind provider/path/key/native body");
    }
}

// §23: refreshing ONE pwquality scalar keeps the other eight journal ids,
// bodies, the foreign primary bytes and the drop-ins untouched.
void testPwqualityNeighborIdStability() {
    Harness harness;
    writePwqualityForeignTopology(harness);
    std::map<std::string, MutationId> idsBefore;
    for (const auto& spec : pwqualityScalarSpecs) {
        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(
                    harness.pwqualityRequest(spec.policyName, spec.managedKey,
                        encodePwqualityLogical(spec)),
                    outcome),
            harness.error);
        idsBefore[spec.managedKey] =
            harness.soleEntryRecord(spec.policyName, "neighbors base").id;
    }
    const std::string dropInVendorBefore =
        readFile(harness.pwqualityDropInDirectory() / "10-vendor.conf");
    const std::string primaryBefore =
        readFile(harness.pwqualityConfigPath);

    // Change ONLY difok: 3 → 5.
    require(harness.apply(harness.pwqualityRequest(
                              "password_min_changed_characters", "difok",
                              "5")),
        harness.error);
    for (const auto& spec : pwqualityScalarSpecs) {
        const auto record = harness.soleEntryRecord(
            spec.policyName, "neighbors after difok refresh");
        require(record.id == idsBefore[spec.managedKey],
            std::string("mutation id of ") + spec.managedKey +
                " must stay stable across a neighbor refresh");
        const auto* payload =
            std::get_if<UndoRemovePamProviderManagedEntry>(
                &record.undo.payload);
        require(payload != nullptr,
            "journal payload kind must stay unchanged");
        if (std::string(spec.managedKey) == "difok") {
            require(payload->appliedBody == "difok = 5",
                "the refreshed difok body must carry the new desired value");
        } else {
            require(payload->appliedBody == spec.nativeBody,
                std::string("the body of neighbor ") + spec.managedKey +
                    " must stay unchanged");
        }
    }
    auto parse = harness.parse(harness.pwqualityConfigPath);
    require(parse.ok && parse.view.entries.size() == 9,
        "the refreshed primary must still hold exactly nine entries");
    for (const auto& entry : parse.view.entries) {
        if (entry.policy == "password_min_changed_characters") {
            require(entry.body == "difok = 5",
                "the physical difok entry must be refreshed");
        }
    }
    require(readFile(harness.pwqualityDropInDirectory() / "10-vendor.conf") ==
                dropInVendorBefore,
        "drop-ins must stay byte-exact across a neighbor refresh");
    const std::string primaryAfter = readFile(harness.pwqualityConfigPath);
    // Foreign bytes = everything before the FIC block start marker; the
    // block itself may (and did) refresh difok 3→5.
    const std::string foreignPrefix = primaryBefore.substr(0,
        primaryBefore.find("# FIC_PAM_PROVIDER_BLOCK_BEGIN"));
    require(!foreignPrefix.empty() &&
                primaryAfter.substr(0, foreignPrefix.size()) ==
                    foreignPrefix,
        "foreign primary bytes must stay byte-exact across a refresh");
}

// §24: one full apply + update per encoding kind through the EXISTING
// codec layer (logical GUI value → native journal/physical body).
void testPwqualityEncodingKinds() {
    // YesNoInteger: yes→1, then update no→0 with the same id. The native
    // values come from the production codec.
    {
        Harness harness;
        writeFile(harness.pwqualityConfigPath, "# admin\n");
        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(harness.pwqualityRequest(
                                  "password_check_username", "usercheck",
                                  encodePwqualityLogical(
                                      {"password_check_username",
                                          "usercheck",
                                          PamNativeValueEncoding::
                                              YesNoInteger,
                                          "yes",
                                          "usercheck = 1"})),
                    outcome),
            harness.error);
        const MutationId id = harness.soleEntryRecord(
            "password_check_username", "enc base").id;
        auto parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "usercheck = 1",
            "logical yes must encode to native usercheck = 1");
        require(harness.apply(harness.pwqualityRequest(
                                  "password_check_username", "usercheck",
                                  encodePwqualityLogical(
                                      {"password_check_username",
                                          "usercheck",
                                          PamNativeValueEncoding::
                                              YesNoInteger,
                                          "no",
                                          "usercheck = 0"}))),
            harness.error);
        parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok &&
                    parse.view.entries.front().body == "usercheck = 0",
            "logical no must encode to native usercheck = 0");
        const auto record = harness.soleEntryRecord(
            "password_check_username", "enc update");
        require(record.id == id,
            "the yes→no update must keep the same journal id");
    }
    // MinimumCredit: 0→0, then update 4→-4 with the same id. Positive
    // native credits (different semantics) are never stored.
    {
        Harness harness;
        writeFile(harness.pwqualityConfigPath, "# admin\n");
        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_lowercase", "lcredit",
                                  encodePwqualityLogical(
                                      {"password_min_lowercase", "lcredit",
                                          PamNativeValueEncoding::
                                              MinimumCredit,
                                          "0",
                                          "lcredit = 0"})),
                    outcome),
            harness.error);
        const MutationId id = harness.soleEntryRecord(
            "password_min_lowercase", "enc base").id;
        auto parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok &&
                    parse.view.entries.front().body == "lcredit = 0",
            "logical minimum 0 must encode to native lcredit = 0");
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_lowercase", "lcredit",
                                  encodePwqualityLogical(
                                      {"password_min_lowercase", "lcredit",
                                          PamNativeValueEncoding::
                                              MinimumCredit,
                                          "4",
                                          "lcredit = -4"}))),
            harness.error);
        parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok &&
                    parse.view.entries.front().body == "lcredit = -4",
            "logical minimum 4 must encode to native lcredit = -4 (never a "
            "positive credit)");
        const auto record = harness.soleEntryRecord(
            "password_min_lowercase", "enc update");
        require(record.id == id,
            "the 0→4 credit update must keep the same journal id");
    }
    // Direct: minlen applies verbatim (covered by the shared-block test).
}

// §25: after the managed mutation the PwqualityConfigEvaluator with the
// real DropInsThenPrimary topology proves the FIC EOF assignment is
// EFFECTIVE over both the drop-ins and the earlier foreign primary value.
void testPwqualityEffectiveTopologyOrdering() {
    Harness harness;
    writePwqualityForeignTopology(harness);
    require(harness.apply(harness.pwqualityRequest("password_min_length",
                               "minlen", "14")),
        harness.error);

    fic::platform::PamProviderConfigTopology topology;
    topology.primaryPath = harness.pwqualityConfigPath;
    topology.dropInDirectories = {harness.pwqualityDropInDirectory()};
    topology.precedence =
        fic::platform::PamConfigPrecedence::DropInsThenPrimary;
    PwqualityEffectiveState state;
    std::string error;
    require(PwqualityConfigEvaluator::evaluateInvocation(
                {}, harness.pwqualityConfigPath, 1, topology, state, error),
        "pwquality topology evaluation failed: " + error);
    require(state.minlen == 14,
        "the FIC EOF assignment must outrank the drop-in (8) and the "
        "foreign primary (10) values; effective minlen is " +
            std::to_string(state.minlen));
    require(state.usercheck == 0,
        "the foreign drop-in usercheck = 0 stays effective (FIC did not "
        "touch it)");
}

// §30: provider-specific crash-recovery smoke on pwquality.
// a) Applied 12 → Prepared 12→14, physical still 12 → apply 14: same id,
//    physical 14, Applied.
// b) Applied 12 → Prepared 12→14, physical 12, current desired 16:
//    semantic sequence [14, 16], same id, physical 16.
void testPwqualityCrashRecoverySmoke() {
    // (a) plain recovery to the durable target.
    {
        Harness harness;
        writeFile(harness.pwqualityConfigPath, "# admin\n");
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_length", "minlen", "12")),
            harness.error);
        const MutationId id = harness.soleEntryRecord(
            "password_min_length", "smoke base").id;
        prepareUpdateTransaction(harness, "password_min_length", "minlen",
            "minlen = 12", "minlen = 14", "pam_pwquality",
            harness.pwqualityConfigPath);

        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_length", "minlen", "14"),
                    outcome),
            harness.error);
        const auto record = harness.soleEntryRecord(
            "password_min_length", "pwquality recovery");
        require(record.id == id && record.status == MutationStatus::Applied,
            "pwquality recovery must complete the same record as Applied");
        auto parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "minlen = 14" &&
                    parse.view.entries.front().mutationId == id,
            "the recovered physical entry must carry the durable target");
    }
    // (b) desired changed during recovery: durable target 14 first, then
    // the desired 16 via a fresh read + same-id refresh.
    {
        Harness harness;
        writeFile(harness.pwqualityConfigPath, "# admin\n");
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_length", "minlen", "12")),
            harness.error);
        const MutationId id = harness.soleEntryRecord(
            "password_min_length", "smoke base").id;
        prepareUpdateTransaction(harness, "password_min_length", "minlen",
            "minlen = 12", "minlen = 14", "pam_pwquality",
            harness.pwqualityConfigPath);

        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_length", "minlen", "16"),
                    outcome),
            harness.error);
        require(harness.verifiedValues.size() == 2 &&
                    harness.verifiedValues[0] == "14" &&
                    harness.verifiedValues[1] == "16",
            "pwquality recovery must prove the durable target 14 first, "
            "then the desired 16");
        const auto record = harness.soleEntryRecord(
            "password_min_length", "pwquality desired-changed");
        require(record.id == id && record.status == MutationStatus::Applied,
            "both transitions must keep the same pwquality record id");
        auto parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "minlen = 16" &&
                    parse.view.entries.front().mutationId == id,
            "the physical entry must end at the desired value");
    }
}

// §31: physical drift under an Applied pwquality record (same id, wrong
// body) is never rewritten — fail closed.
void testPwqualityAppliedDriftSmoke() {
    Harness harness;
    writeFile(harness.pwqualityConfigPath, "# admin\n");
    require(harness.apply(harness.pwqualityRequest(
                              "password_min_length", "minlen", "14")),
        harness.error);
    const MutationId id =
        harness.soleEntryRecord("password_min_length", "drift base").id;

    // Same id, drifted body: minlen = 15.
    writePhysicalEntry(harness, readFile(harness.pwqualityConfigPath),
        "password_min_length", "minlen", "15", id, "pam_pwquality",
        harness.pwqualityConfigPath);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.pwqualityRequest(
                               "password_min_length", "minlen", "14"),
                       outcome),
        "drifted pwquality physical state must fail closed");
    require(!harness.error.empty(), "typed drift error must be reported");
    auto parse = harness.parse(harness.pwqualityConfigPath);
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "minlen = 15" &&
                parse.view.entries.front().mutationId == id,
        "the drifted physical state must not be rewritten");
    const auto record =
        harness.soleEntryRecord("password_min_length", "drift journal");
    require(record.status == MutationStatus::Applied,
        "the journal record stays Applied (no fabricated lifecycle "
        "transition)");
}

// §32 vs §17: a pre-existing EMPTY pwquality primary is a legitimate
// foreign container (FIC appends its block, no container provenance); an
// ABSENT primary stays fail closed with no file creation.
void testPwqualityEmptyAndAbsentPrimary() {
    // Pre-existing empty primary → success, no container record.
    {
        Harness harness;
        writeFile(harness.pwqualityConfigPath, "");
        require(harness.apply(harness.pwqualityRequest(
                                  "password_min_length", "minlen", "14")),
            harness.error);
        auto parse = harness.parse(harness.pwqualityConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "minlen = 14" &&
                    parse.view.atEnd,
            "the FIC block must be created at EOF of the empty primary");
        require(harness.containerRecords("pam_pwquality").empty(),
            "an existing (even empty) primary is PreExisting — no container "
            "provenance");
    }
    // Absent primary → FailClosed, no create, no records.
    {
        Harness harness;
        PamProviderManagedEntryOutcome outcome;
        require(!harness.apply(harness.pwqualityRequest(
                                   "password_min_length", "minlen", "14"),
                             outcome),
            "an absent pwquality primary must fail closed");
        require(!std::filesystem::exists(harness.pwqualityConfigPath),
            "an absent pwquality primary must not be created");
        require(harness.entryRecords("password_min_length").empty() &&
                    harness.containerRecords("pam_pwquality").empty(),
            "a refused absent-primary apply must prepare NO journal "
            "records");
    }
}

// §33: existing primary metadata (mode 0600) is preserved by the managed
// mutation (Step 7A PreserveExisting primitive).
void testPwqualityMetadataPreservation() {
    Harness harness;
    writeFile(harness.pwqualityConfigPath, "# admin\nminclass = 2\n");
    std::filesystem::permissions(harness.pwqualityConfigPath,
        std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_write);
    require(harness.apply(harness.pwqualityRequest(
                              "password_min_length", "minlen", "14")),
        harness.error);
    const auto permissions =
        std::filesystem::status(harness.pwqualityConfigPath).permissions();
    require(permissions == (std::filesystem::perms::owner_read |
                               std::filesystem::perms::owner_write),
        "the existing primary mode 0600 must be preserved, got " +
            std::to_string(static_cast<unsigned int>(permissions)));
}

// §19: foreign duplicate same-key directives in the primary are never
// canonicalized or removed — FIC only appends its own entry.
void testPwqualityForeignDuplicatesPreserved() {
    Harness harness;
    writeFile(harness.pwqualityConfigPath,
        "# administrator\nminlen = 8\nminlen = 10\n# keep me\n");
    require(harness.apply(harness.pwqualityRequest(
                              "password_min_length", "minlen", "14")),
        harness.error);
    const std::string content = readFile(harness.pwqualityConfigPath);
    require(content.find("# administrator\nminlen = 8\nminlen = 10\n"
                         "# keep me\n") == 0,
        "foreign duplicate directives and comments must stay byte-exact "
        "before the FIC block");
    auto parse = harness.parse(harness.pwqualityConfigPath);
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "minlen = 14",
        "the FIC block must carry exactly its own minlen entry");
}

// §29: faillock and pwquality journal provenances coexist in ONE
// MutationJournal without identity collision (different providers, paths,
// blocks); the generic executor has no provider-name hardcode.
void testProviderSeparationFaillockPwqualityCoexist() {
    Harness harness;
    // pwquality: pre-existing foreign primary.
    writeFile(harness.pwqualityConfigPath, "# admin pwquality\n");

    require(harness.apply(harness.request("failed_authentication_attempts",
                               "deny", "5",
                               PamProviderAbsentContainerDecision::
                                   CreateFicOwned)),
        harness.error);
    require(harness.apply(harness.pwqualityRequest("password_min_length",
                               "minlen", "14")),
        harness.error);

    // Both providers own their entries in their own primaries.
    auto faillockParse = harness.parse();
    require(faillockParse.ok &&
                faillockParse.view.provider == "pam_faillock" &&
                faillockParse.view.entries.size() == 1 &&
                faillockParse.view.entries.front().body == "deny = 5",
        "the faillock block must stay in faillock.conf");
    auto pwqualityParse = harness.parse(harness.pwqualityConfigPath);
    require(pwqualityParse.ok &&
                pwqualityParse.view.provider == "pam_pwquality" &&
                pwqualityParse.view.entries.size() == 1 &&
                pwqualityParse.view.entries.front().body == "minlen = 14",
        "the pwquality block must stay in pwquality.conf");

    // Journal: a container record exists only for the FIC-created
    // container; pwquality has a pre-existing primary → entry record only.
    require(harness.containerRecords("pam_faillock").size() == 1,
        "the FIC-created faillock container keeps its provenance record");
    require(harness.containerRecords("pam_pwquality").empty(),
        "the pre-existing pwquality primary has no container record");
    require(harness.soleEntryRecord("failed_authentication_attempts",
                "coexist faillock")
                    .status == MutationStatus::Applied,
        "the faillock entry record stays Applied");
    require(harness.soleEntryRecord("password_min_length",
                "coexist pwquality")
                    .status == MutationStatus::Applied,
        "the pwquality entry record stays Applied");
}

// ---------------------------------------------------------------------------
// Step 7D: pam_pwhistory managed entries at BOF placement.
// ---------------------------------------------------------------------------

// Evaluates the REAL upstream pwhistory semantics over the harness primary
// (first-match per key + module argv last-wins) — the same evaluator the
// production semantic backend uses.
PwhistoryEffectiveState evaluatePwhistoryHarness(
    const Harness& harness, const std::vector<std::string>& arguments = {},
    bool managedRememberOverride = false,
    const std::string& managedValue = {}) {
    fic::platform::PamProviderConfigTopology topology;
    topology.primaryPath = harness.pwhistoryConfigPath;
    topology.explicitConfig =
        fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology;
    PwhistoryEffectiveState state;
    std::string error;
    const bool ok = managedRememberOverride
        ? PwhistoryConfigEvaluator::evaluateInvocationWithManagedOption(
              arguments, harness.pwhistoryConfigPath, 1, topology,
              "remember", managedValue, state, error)
        : PwhistoryConfigEvaluator::evaluateInvocation(
              arguments, harness.pwhistoryConfigPath, 1, topology, state,
              error);
    require(ok, "pwhistory topology evaluation failed: " + error);
    return state;
}

// §24: the FIRST production BOF consumer of the managed-entry executor.
// The FIC block lands at the beginning of an existing foreign primary,
// foreign bytes survive byte-exact AFTER the block, exactly one entry
// carries the journal mutation id, no container provenance is fabricated
// for the pre-existing primary, and the real evaluator proves effective
// remember == 10 over the foreign duplicates.
void testPwhistoryBeginningBlockIntegration() {
    Harness harness;
    const std::string foreign =
        "# admin comment\nremember = 3\nretry = 4\nremember = 7\n";
    writeFile(harness.pwhistoryConfigPath, foreign);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10"),
                          outcome),
        harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "fresh pwhistory apply must be Applied");

    // Physical: block at BOF, one entry, foreign bytes byte-exact after.
    auto parse = harness.parse(harness.pwhistoryConfigPath);
    require(parse.ok && parse.view.present,
        "strict parse of the pwhistory block failed: " + parse.error);
    require(parse.view.provider == "pam_pwhistory", "provider mismatch");
    require(parse.view.atBeginning,
        "the pwhistory block must sit at the beginning of the file");
    require(parse.view.entries.size() == 1,
        "exactly one pwhistory FIC entry expected");
    require(parse.view.entries.front().body == "remember = 10",
        "the entry body must carry the native remember value");
    require(endsWith(readFile(harness.pwhistoryConfigPath), foreign),
        "the foreign bytes must survive byte-exact after the FIC block");

    // Journal: entry Applied at Beginning placement, NO container record
    // for the pre-existing primary.
    const auto record = harness.soleEntryRecord(
        "password_history_depth", "pwhistory BOF integration");
    require(record.status == MutationStatus::Applied,
        "the pwhistory entry record must be Applied");
    const auto* payload = std::get_if<UndoRemovePamProviderManagedEntry>(
        &record.undo.payload);
    require(payload != nullptr, "entry payload type mismatch");
    require(payload->appliedBody == "remember = 10", "payload body mismatch");
    require(payload->placement ==
                fic::rollback::PamProviderBlockPlacementContract::Beginning,
        "the journal placement contract must be Beginning");
    require(harness.containerRecords("pam_pwhistory").empty(),
        "a pre-existing pwhistory primary must never receive container "
        "provenance");

    // Semantic: the REAL evaluator proves the first-match effective value.
    const auto state = evaluatePwhistoryHarness(harness);
    require(state.remember == 10,
        "effective first-match remember must be 10, got " +
            std::to_string(state.remember));
    require(state.retry == 4,
        "the foreign retry = 4 must stay effective (FIC never touched it)");
}

// §25: BOF foreign separator ownership — insertion/refresh must not lose
// foreign bytes or normalize foreign line endings, for BOTH a file with a
// terminal LF and a file WITHOUT a terminal LF.
void testPwhistoryForeignSeparatorOwnership() {
    // File with a normal terminal newline.
    {
        Harness harness;
        writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 3\n");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "10")),
            harness.error);
        require(endsWith(readFile(harness.pwhistoryConfigPath),
                    "# admin\nremember = 3\n"),
            "foreign bytes must survive the BOF insertion byte-exact");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "20")),
            harness.error);
        require(endsWith(readFile(harness.pwhistoryConfigPath),
                    "# admin\nremember = 3\n"),
            "foreign bytes must survive the refresh byte-exact");
        auto parse = harness.parse(harness.pwhistoryConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "remember = 20" &&
                    parse.view.atBeginning,
            "the refreshed entry must stay exact-owned at BOF");
    }
    // File WITHOUT a terminal newline.
    {
        Harness harness;
        writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 3");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "10")),
            harness.error);
        const std::string afterInsert =
            readFile(harness.pwhistoryConfigPath);
        require(endsWith(afterInsert, "# admin\nremember = 3") &&
                    !endsWith(afterInsert, "remember = 3\n"),
            "the missing terminal LF is foreign byte ownership: FIC must "
            "not normalize it");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "20")),
            harness.error);
        const std::string afterRefresh =
            readFile(harness.pwhistoryConfigPath);
        require(endsWith(afterRefresh, "# admin\nremember = 3") &&
                    !endsWith(afterRefresh, "remember = 3\n"),
            "the refresh must keep the foreign no-final-newline shape");
        auto parse = harness.parse(harness.pwhistoryConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "remember = 20" &&
                    parse.view.atBeginning,
            "the strict block grammar must survive the refresh");
    }
}

// §32/§34: an existing (even EMPTY) primary is PreExisting — success with
// no container provenance; an ABSENT primary is FailClosed (vendor
// fallback risk): no create, no records, no false ownership.
void testPwhistoryEmptyAndAbsentPrimary() {
    // Pre-existing empty primary → success, block at BOF, no records.
    {
        Harness harness;
        writeFile(harness.pwhistoryConfigPath, "");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "10")),
            harness.error);
        auto parse = harness.parse(harness.pwhistoryConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "remember = 10" &&
                    parse.view.atBeginning,
            "the FIC block must be created at BOF of the empty primary");
        require(harness.containerRecords("pam_pwhistory").empty(),
            "an existing (even empty) primary is PreExisting — no "
            "container provenance");
    }
    // Absent primary → FailClosed, no create, no records.
    {
        Harness harness;
        PamProviderManagedEntryOutcome outcome;
        require(!harness.apply(harness.pwhistoryRequest(
                                   "password_history_depth", "remember",
                                   "10"),
                             outcome),
            "an absent pwhistory primary must fail closed (vendor "
            "fallback cannot be proven)");
        require(!std::filesystem::exists(harness.pwhistoryConfigPath),
            "an absent pwhistory primary must not be created");
        require(harness.entryRecords("password_history_depth").empty() &&
                    harness.containerRecords("pam_pwhistory").empty(),
            "a refused absent-primary apply must prepare NO journal "
            "records");
    }
}

// §33: existing primary metadata (mode 0600) is preserved by the managed
// BOF mutation (Step 7A PreserveExisting primitive).
void testPwhistoryMetadataPreservation() {
    Harness harness;
    writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 3\n");
    std::filesystem::permissions(harness.pwhistoryConfigPath,
        std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_write);
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const auto permissions =
        std::filesystem::status(harness.pwhistoryConfigPath).permissions();
    require(permissions == (std::filesystem::perms::owner_read |
                               std::filesystem::perms::owner_write),
        "the existing pwhistory primary mode 0600 must be preserved, got " +
            std::to_string(static_cast<unsigned int>(permissions)));
}

// §26/§28: block displacement at BOF. After a successful apply the
// administrator prepends `REMEMBER = 2` (case-variant foreign key —
// upstream search is case-insensitive, so the effective remember becomes
// 2 while the FIC entry stays exact-owned). The next SAME-desired apply
// must: prove exact ownership, see the placement violation, safely
// relocate the owned block back to BOF, keep ALL foreign bytes byte-exact
// and in order, keep the SAME journal record id, and prove effective
// remember == 10 afterwards.
void testPwhistoryDisplacementRelocation() {
    Harness harness;
    const std::string foreign = "# admin\nremember = 3\nremember = 7\n";
    writeFile(harness.pwhistoryConfigPath, foreign);
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const MutationId id = harness.soleEntryRecord(
        "password_history_depth", "displacement base").id;

    // The administrator prepends a case-variant foreign key.
    writeFile(harness.pwhistoryConfigPath,
        "REMEMBER = 2\n" +
            readFile(harness.pwhistoryConfigPath));

    // Semantic postcondition BEFORE relocation: the effective first-match
    // remember is the foreign 2 (case-insensitive first match), even
    // though the FIC entry is still physically exact-owned.
    {
        const auto displaced = evaluatePwhistoryHarness(harness);
        require(displaced.remember == 2,
            "the displaced case-variant foreign key must be effective "
            "before relocation, got " + std::to_string(displaced.remember));
    }

    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);

    const std::string relocated = readFile(harness.pwhistoryConfigPath);
    // Block relocated to BOF; the foreign prepend and the original
    // foreign bytes survive byte-exact and in the same mutual order.
    require(relocated.find(
                "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 "
                "provider=pam_pwhistory") == 0,
        "the owned block must be relocated back to the beginning");
    require(endsWith(relocated, "REMEMBER = 2\n" + foreign),
        "the foreign prepend and foreign bytes must survive byte-exact "
        "and in order");
    auto parse = harness.parse(harness.pwhistoryConfigPath);
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "remember = 10" &&
                parse.view.entries.front().mutationId == id &&
                parse.view.atBeginning,
        "the relocated entry must keep its body and SAME mutation id");
    // Same journal record, no new record, same id.
    const auto record = harness.soleEntryRecord(
        "password_history_depth", "displacement relocation");
    require(record.id == id && record.status == MutationStatus::Applied,
        "the relocation must reuse the SAME journal record id");
    // Semantic: effective remember is the FIC value again.
    const auto state = evaluatePwhistoryHarness(harness);
    require(state.remember == 10,
        "after relocation the effective first-match remember must be 10, "
        "got " + std::to_string(state.remember));
}

// §37: placement drift is NOT body drift. A DISPLACED exact-owned block
// is safely relocated (see the displacement test); a WRONG body under the
// same id is AppliedDrifted — fail closed, never relocated or rewritten
// "as if placement-only".
void testPwhistoryPlacementDriftIsNotBodyDrift() {
    Harness harness;
    writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 5\n");
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const MutationId id = harness.soleEntryRecord(
        "password_history_depth", "drift distinction base").id;

    // Foreign prepend + manual body edit of the exact-owned entry
    // (drifted body under the SAME id, also displaced).
    std::string content = "REMEMBER = 2\n" +
        readFile(harness.pwhistoryConfigPath);
    const std::size_t bodyPosition =
        content.find("remember = 10\n# FIC_PAM_ENTRY_END");
    require(bodyPosition != std::string::npos,
        "test fixture corruption: FIC entry body not found");
    content.replace(bodyPosition, std::string("remember = 10").size(),
        "remember = 11");
    writeFile(harness.pwhistoryConfigPath, content);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.pwhistoryRequest(
                               "password_history_depth", "remember", "10"),
                           outcome),
        "a wrong body under the same id must fail closed even when the "
        "block is also displaced");
    require(harness.error.find("Drifted") != std::string::npos ||
                harness.error.find("drift") != std::string::npos,
        "the drift diagnostic must be typed: " + harness.error);
    const std::string after = readFile(harness.pwhistoryConfigPath);
    require(after.find("remember = 11") != std::string::npos &&
                after.find("REMEMBER = 2\n") == 0,
        "the drifted body and foreign prepend must stay untouched (no "
        "rewrite, no relocation of a drifted block)");
    const auto record = harness.soleEntryRecord(
        "password_history_depth", "drift distinction");
    require(record.id == id && record.status == MutationStatus::Applied,
        "the Applied record must stay untouched (never rewritten)");
}

// §27: first-match duplicate regression. `remember = 2` followed by
// `remember = 40` is effective 2 upstream; after the FIC BOF apply the
// effective value MUST be 10, not the LAST foreign duplicate 40. A
// last-match evaluator implementation would fail this test.
void testPwhistoryFirstMatchDuplicates() {
    Harness harness;
    writeFile(harness.pwhistoryConfigPath,
        "remember = 2\nremember = 40\n");
    {
        const auto before = evaluatePwhistoryHarness(harness);
        require(before.remember == 2,
            "the evaluator must use FIRST-match, got " +
                std::to_string(before.remember));
    }
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const auto state = evaluatePwhistoryHarness(harness);
    require(state.remember == 10,
        "the FIC BOF entry must outrank BOTH foreign duplicates "
        "(effective 10, not last-match 40), got " +
            std::to_string(state.remember));
}

// §28: case-insensitive first-match regression. `REMEMBER = 2` /
// `ReMeMbEr = 40` must be effective 2 upstream (strcasecmp), the foreign
// casing is never canonicalized, and the FIC BOF `remember = 10` outranks
// both.
void testPwhistoryCaseInsensitiveFirstMatch() {
    Harness harness;
    writeFile(harness.pwhistoryConfigPath,
        "REMEMBER = 2\nReMeMbEr = 40\n");
    {
        const auto before = evaluatePwhistoryHarness(harness);
        require(before.remember == 2,
            "the evaluator must match keys case-insensitively, got " +
                std::to_string(before.remember));
    }
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const std::string content = readFile(harness.pwhistoryConfigPath);
    require(endsWith(content, "REMEMBER = 2\nReMeMbEr = 40\n"),
        "foreign key casing must never be canonicalized");
    const auto state = evaluatePwhistoryHarness(harness);
    require(state.remember == 10,
        "the FIC BOF entry must outrank the case-variant foreign keys, "
        "got " + std::to_string(state.remember));
}

// §35: crash-recovery smoke for the BOF pwhistory placement.
// a) Applied remember=5 (id=A) → Prepared update 5→10 at Beginning,
//    physical still 5 → apply 10: SAME id, physical 10 at BOF, Applied.
// b) Prepared 5→10, physical 5, current desired 20: the DURABLE target
//    10 is completed first (semantic sequence [10, 20]), SAME id, final
//    physical remember=20 at BOF.
void testPwhistoryCrashRecoverySmoke() {
    // (a) plain recovery to the durable target.
    {
        Harness harness;
        writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 5\n");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "5")),
            harness.error);
        const MutationId id = harness.soleEntryRecord(
            "password_history_depth", "pwhistory smoke base").id;
        prepareUpdateTransaction(harness, "password_history_depth",
            "remember", "remember = 5", "remember = 10", "pam_pwhistory",
            harness.pwhistoryConfigPath,
            PamProviderBlockPlacementRequest::Beginning);

        PamProviderManagedEntryOutcome outcome;
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "10"),
                              outcome),
            harness.error);
        require(outcome == PamProviderManagedEntryOutcome::Applied,
            "the BOF recovery must be a physical mutation");
        const auto record = harness.soleEntryRecord(
            "password_history_depth", "pwhistory recovery");
        require(record.id == id && record.status == MutationStatus::Applied,
            "pwhistory recovery must complete the SAME record as Applied");
        auto parse = harness.parse(harness.pwhistoryConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "remember = 10" &&
                    parse.view.entries.front().mutationId == id &&
                    parse.view.atBeginning,
            "the recovered physical entry must carry the durable target "
            "at BOF");
    }
    // (b) desired changed during recovery: durable target 10 first, then
    // the desired 20 via a fresh read + same-id refresh.
    {
        Harness harness;
        writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 5\n");
        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "5")),
            harness.error);
        const MutationId id = harness.soleEntryRecord(
            "password_history_depth", "pwhistory smoke base b").id;
        prepareUpdateTransaction(harness, "password_history_depth",
            "remember", "remember = 5", "remember = 10", "pam_pwhistory",
            harness.pwhistoryConfigPath,
            PamProviderBlockPlacementRequest::Beginning);

        require(harness.apply(harness.pwhistoryRequest(
                                  "password_history_depth", "remember",
                                  "20")),
            harness.error);
        // The durable target 10 was proven first, then the desired 20.
        require((harness.verifiedValues ==
                    std::vector<std::string>{"10", "20"}),
            "the recovery must complete the DURABLE target first, then "
            "the current desired value");
        const auto record = harness.soleEntryRecord(
            "password_history_depth", "pwhistory recovery b");
        require(record.id == id && record.status == MutationStatus::Applied,
            "the desired-changed recovery must keep the SAME id");
        auto parse = harness.parse(harness.pwhistoryConfigPath);
        require(parse.ok && parse.view.entries.size() == 1 &&
                    parse.view.entries.front().body == "remember = 20" &&
                    parse.view.atBeginning,
            "the final physical entry must be the desired 20 at BOF");
    }
}

// §36: Applied drift BOF smoke. Journal Applied (id=A, body
// remember=10, Beginning); the physical entry under the SAME id carries
// remember=11 → AppliedDrifted, fail closed, NO rewrite.
void testPwhistoryAppliedDriftSmoke() {
    Harness harness;
    writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 10\n");
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const MutationId id = harness.soleEntryRecord(
        "password_history_depth", "drift smoke base").id;

    std::string content = readFile(harness.pwhistoryConfigPath);
    const std::size_t bodyPosition =
        content.find("remember = 10\n# FIC_PAM_ENTRY_END");
    require(bodyPosition != std::string::npos,
        "test fixture corruption: FIC entry body not found");
    content.replace(bodyPosition, std::string("remember = 10").size(),
        "remember = 11");
    writeFile(harness.pwhistoryConfigPath, content);

    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(harness.pwhistoryRequest(
                               "password_history_depth", "remember", "10"),
                           outcome),
        "a drifted BOF entry body must fail closed");
    require(readFile(harness.pwhistoryConfigPath).find("remember = 11") !=
            std::string::npos,
        "the drifted body must not be rewritten");
    const auto record = harness.soleEntryRecord(
        "password_history_depth", "drift smoke");
    require(record.id == id && record.status == MutationStatus::Applied,
        "the Applied record must stay untouched on drift");
}

// §38: semantic failure AFTER the physical BOF write. The injected
// postcondition failure must return false, keep the journal recoverable
// (Prepared), keep the physical FIC entry and the foreign bytes — and
// NEVER restore a whole-file snapshot. The next apply adopts the exact
// target-present state through the generic state machine.
void testPwhistorySemanticFailureNoSnapshotRollback() {
    Harness harness;
    writeFile(harness.pwhistoryConfigPath, "# admin\nremember = 5\n");
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "5")),
        harness.error);
    const MutationId id = harness.soleEntryRecord(
        "password_history_depth", "semantic failure base").id;
    prepareUpdateTransaction(harness, "password_history_depth", "remember",
        "remember = 5", "remember = 10", "pam_pwhistory",
        harness.pwhistoryConfigPath,
        PamProviderBlockPlacementRequest::Beginning);

    harness.failSemanticFor.insert("10");
    require(!harness.apply(harness.pwhistoryRequest(
                               "password_history_depth", "remember", "10")),
        "the injected semantic failure must fail the apply");
    require(harness.error.find("semantic postcondition failed") !=
            std::string::npos,
        "the semantic failure must be reported: " + harness.error);

    // Journal stays recoverable (Prepared), physical FIC entry stays.
    const auto record = harness.soleEntryRecord(
        "password_history_depth", "semantic failure");
    require(record.id == id && record.status == MutationStatus::Prepared,
        "the transaction must stay Prepared (recoverable, no snapshot "
        "rollback)");
    auto parse = harness.parse(harness.pwhistoryConfigPath);
    require(parse.ok && parse.view.entries.size() == 1 &&
                parse.view.entries.front().body == "remember = 10" &&
                parse.view.entries.front().mutationId == id &&
                parse.view.atBeginning,
        "the physical FIC entry must remain (no whole-file restore)");
    require(endsWith(readFile(harness.pwhistoryConfigPath),
                "# admin\nremember = 5\n"),
        "the foreign bytes must survive the failed apply byte-exact");

    // Next apply: exact target-present state recovers/adopts (same id).
    harness.failSemanticFor.clear();
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);
    const auto recovered = harness.soleEntryRecord(
        "password_history_depth", "semantic failure recovery");
    require(recovered.id == id &&
                recovered.status == MutationStatus::Applied,
        "the next apply must adopt the exact target-present state with "
        "the SAME id");
}

// §44: three providers (faillock/pwquality/pwhistory) coexist in ONE
// MutationJournal without collision — different providers, paths, and
// placements (EOF, EOF, BOF).
void testProviderSeparationAllThreeCoexist() {
    Harness harness;
    writeFile(harness.configPath, "# faillock admin\n");
    writeFile(harness.pwqualityConfigPath, "# pwquality admin\n");
    writeFile(harness.pwhistoryConfigPath, "# pwhistory admin\n");
    require(harness.apply(harness.request(
                              "failed_authentication_attempts", "deny",
                              "5")),
        harness.error);
    require(harness.apply(harness.pwqualityRequest(
                              "password_min_length", "minlen", "14")),
        harness.error);
    require(harness.apply(harness.pwhistoryRequest(
                              "password_history_depth", "remember", "10")),
        harness.error);

    auto faillockParse = harness.parse(harness.configPath);
    require(faillockParse.ok &&
                faillockParse.view.provider == "pam_faillock" &&
                faillockParse.view.entries.size() == 1 &&
                faillockParse.view.entries.front().body == "deny = 5" &&
                faillockParse.view.atEnd,
        "the faillock block must stay at EOF of faillock.conf");
    auto pwqualityParse = harness.parse(harness.pwqualityConfigPath);
    require(pwqualityParse.ok &&
                pwqualityParse.view.provider == "pam_pwquality" &&
                pwqualityParse.view.entries.size() == 1 &&
                pwqualityParse.view.entries.front().body == "minlen = 14" &&
                pwqualityParse.view.atEnd,
        "the pwquality block must stay at EOF of pwquality.conf");
    auto pwhistoryParse = harness.parse(harness.pwhistoryConfigPath);
    require(pwhistoryParse.ok &&
                pwhistoryParse.view.provider == "pam_pwhistory" &&
                pwhistoryParse.view.entries.size() == 1 &&
                pwhistoryParse.view.entries.front().body ==
                    "remember = 10" &&
                pwhistoryParse.view.atBeginning,
        "the pwhistory block must stay at BOF of pwhistory.conf");

    // Journal: three independent entry records + one FIC-created
    // faillock container (the other two primaries are pre-existing).
    require(harness.soleEntryRecord("failed_authentication_attempts",
                "coexist faillock")
                    .status == MutationStatus::Applied,
        "the faillock entry record stays Applied");
    require(harness.soleEntryRecord("password_min_length",
                "coexist pwquality")
                    .status == MutationStatus::Applied,
        "the pwquality entry record stays Applied");
    require(harness.soleEntryRecord("password_history_depth",
                "coexist pwhistory")
                    .status == MutationStatus::Applied,
        "the pwhistory entry record stays Applied");
    // All three primaries were pre-existing (even if only a comment):
    // FIC owns only its entries — no container provenance anywhere.
    require(harness.containerRecords("pam_faillock").empty() &&
                harness.containerRecords("pam_pwquality").empty() &&
                harness.containerRecords("pam_pwhistory").empty(),
        "pre-existing primaries never receive container provenance");
}

} // namespace

int main() {
    try {
        testRoutingDecision();
        testAbsentContainerFailClosed();
        testFreshCreateFicOwnedContainer();
        testAppliedNoOpIsProven();
        testSecondPolicyReusesContainerProvenance();
        testRecoveryPreparedFreshAbsent();
        testRecoveryPreparedFreshTargetPresent();
        testRecoveryPreparedUpdatePreviousPresent();
        testRecoveryPreparedUpdateTargetPresent();
        testPreparedConflictRefused();
        testAppliedMissingRefused();
        testAppliedDriftedRefused();
        testUpdateLifecycleSameId();
        testForeignMutationIdConflictRefused();
        testThreePoliciesOneBlockForeignBytesExact();
        testRestartRecovery();
        testRecoveryDesiredChangedPreviousPresent();
        testRecoveryDesiredChangedTargetPresent();
        testRecoveryDesiredChangedFreshPrepared();
        testRecoveryDesiredChangedFreshCreatedContainer();
        testRecoveryFreshCreatedContainerProvenanceMissing();
        testRecoveryFreshCreatedContainerProvenanceMissingDesiredUnchanged();
        testFailureBetweenTransitionsIsRecoverable();
        testPreparedContainerWithoutWitnessRefused();
        testPreparedContainerCreatorWitnessCompletes();
        testPreparedContainerCrossPolicyWitness();
        testPreparedContainerAppliedWitness();
        testPreparedContainerWrongCreatorIdentityRefused();

        // Step 7C: pam_pwquality scalars on the shared executor.
        testPwqualitySharedBlockNinePolicies();
        testPwqualityNeighborIdStability();
        testPwqualityEncodingKinds();
        testPwqualityEffectiveTopologyOrdering();
        testPwqualityCrashRecoverySmoke();
        testPwqualityAppliedDriftSmoke();
        testPwqualityEmptyAndAbsentPrimary();
        testPwqualityMetadataPreservation();
        testPwqualityForeignDuplicatesPreserved();
        testProviderSeparationFaillockPwqualityCoexist();

        // Step 7D: pam_pwhistory depth on the shared executor (BOF).
        testPwhistoryBeginningBlockIntegration();
        testPwhistoryForeignSeparatorOwnership();
        testPwhistoryEmptyAndAbsentPrimary();
        testPwhistoryMetadataPreservation();
        testPwhistoryDisplacementRelocation();
        testPwhistoryPlacementDriftIsNotBodyDrift();
        testPwhistoryFirstMatchDuplicates();
        testPwhistoryCaseInsensitiveFirstMatch();
        testPwhistoryCrashRecoverySmoke();
        testPwhistoryAppliedDriftSmoke();
        testPwhistorySemanticFailureNoSnapshotRollback();
        testProviderSeparationAllThreeCoexist();
    } catch (const std::exception& exception) {
        std::cerr << "FAILED: " << exception.what() << "\n";
        return 1;
    }
    std::cout << "PamProviderManagedEntryExecutor tests passed\n";
    return 0;
}
