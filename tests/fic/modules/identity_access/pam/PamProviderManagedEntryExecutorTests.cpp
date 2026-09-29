#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
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

    bool apply(const PamProviderManagedEntryRequest& request,
        PamProviderManagedEntryOutcome& outcome) {
        verifiedValues.clear();
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

    std::vector<MutationRecord> entryRecords(const std::string& policyName) {
        return journal.activeRecords({"IDENTITY_ACCESS", "PAM", policyName});
    }

    std::vector<MutationRecord> containerRecords() {
        return journal.activeRecords(
            {"IDENTITY_ACCESS", "PAM_CONTAINER", "pam_faillock"});
    }

    MutationRecord soleEntryRecord(const std::string& policyName,
        const std::string& context) {
        auto records = entryRecords(policyName);
        require(records.size() == 1,
            context + ": expected exactly one entry record, got " +
                std::to_string(records.size()));
        return records.front();
    }

    MutationRecord soleContainerRecord(const std::string& context) {
        auto records = containerRecords();
        require(records.size() == 1,
            context + ": expected exactly one container record, got " +
                std::to_string(records.size()));
        return records.front();
    }

    PamProviderBlockParseResult parse() {
        return parsePamProviderManagedBlock(readFile(configPath));
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
// recovery matrix). previousBody empty = fresh create.
MutationId prepareEntryRecord(Harness& harness,
    const std::string& policyName, const std::string& appliedBody,
    const std::string& previousBody) {
    UndoRemovePamProviderManagedEntry payload;
    payload.policyName = policyName;
    payload.providerName = "pam_faillock";
    payload.configPath = harness.configPath.string();
    payload.managedKey = appliedBody.substr(0, appliedBody.find(" = "));
    payload.appliedBody = appliedBody;
    payload.previousAppliedBody = previousBody;
    payload.placement =
        fic::rollback::PamProviderBlockPlacementContract::End;

    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", policyName};
    record.resource = harness.configPath.string();
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, payload};

    MutationId id = 0;
    require(harness.journal.prepareMutation(record, id, harness.error),
        harness.error);
    return id;
}

// Writes the physical entry for (policy, key) with the given id directly
// (crash simulation: physical write happened, journal completion not).
void writePhysicalEntry(Harness& harness, const std::string& baseContent,
    const std::string& policyName, const std::string& key,
    const std::string& value, MutationId id) {
    auto spec = PamProviderEntrySpec{"pam_faillock", policyName, key, value,
        static_cast<std::uint64_t>(id)};
    auto mutation = setPamProviderManagedEntry(baseContent, spec,
        PamProviderBlockPlacementRequest::End);
    require(mutation.ok, mutation.error);
    writeFile(harness.configPath, mutation.content);
}

// Re-prepares the ACTIVE entry record as an update transaction (same id):
// journal refresh previous→target, status back to Prepared (crash between
// journal refresh and physical completion).
MutationId prepareUpdateTransaction(Harness& harness,
    const std::string& policyName, const std::string& key,
    const std::string& previousBody, const std::string& targetBody) {
    UndoRemovePamProviderManagedEntry payload;
    payload.policyName = policyName;
    payload.providerName = "pam_faillock";
    payload.configPath = harness.configPath.string();
    payload.managedKey = key;
    payload.appliedBody = targetBody;
    payload.previousAppliedBody = previousBody;
    payload.placement =
        fic::rollback::PamProviderBlockPlacementContract::End;
    MutationRecord update;
    update.policy = {"IDENTITY_ACCESS", "PAM", policyName};
    update.resource = harness.configPath.string();
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

    // A Flag-syntax binding (even_deny_root, Step 7E) stays legacy.
    auto flag = deny;
    flag.syntax = PamNativeOptionSyntax::Flag;
    require(!usesPamProviderManagedEntry(provider, capability, flag,
                PamPolicyFeature::FailedAuthenticationAttempts),
        "flag syntax must stay on the legacy path");

    // Module-arguments mode stays legacy.
    auto arguments = capability;
    arguments.configurationMode =
        PamCapabilityConfigurationMode::ModuleArguments;
    require(!usesPamProviderManagedEntry(provider, arguments, deny,
                PamPolicyFeature::FailedAuthenticationAttempts),
        "module-arguments mode must stay on the legacy path");

    // Other providers stay legacy.
    PamProviderDescriptor pwquality;
    pwquality.kind = PamProviderKind::PamPwquality;
    pwquality.name = "pam_pwquality";
    const auto minLength = assignmentBinding(
        PamPolicyFeature::PasswordMinLength, "minlen");
    require(!usesPamProviderManagedEntry(pwquality, capability, minLength,
                PamPolicyFeature::PasswordMinLength),
        "pwquality must stay on the legacy path");

    require(pamProviderAbsentContainerDecision(provider) ==
                PamProviderAbsentContainerDecision::FailClosed,
        "pam_faillock absent-container decision must fail closed");
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
        testFailureBetweenTransitionsIsRecoverable();
        testPreparedContainerWithoutWitnessRefused();
        testPreparedContainerCreatorWitnessCompletes();
        testPreparedContainerCrossPolicyWitness();
        testPreparedContainerAppliedWitness();
        testPreparedContainerWrongCreatorIdentityRefused();
    } catch (const std::exception& exception) {
        std::cerr << "FAILED: " << exception.what() << "\n";
        return 1;
    }
    std::cout << "PamProviderManagedEntryExecutor tests passed\n";
    return 0;
}
