#include "modules/identity_access/pam/PamProviderRollback.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace fic::identity::pam;
using fic::platform::PamCapabilityConfig;
using fic::platform::PamCapabilityConfigurationMode;
using fic::platform::PamPlatformConfig;
using fic::platform::PamPolicyFeature;
using fic::platform::PamProviderKind;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAction;
using fic::rollback::UndoOwnPamProviderContainer;
using fic::rollback::UndoRemovePamProviderManagedEntry;
using fic::rollback::UndoRemovePamProviderManagedFlag;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/fic-pam-provider-rollback-XXXXXX";
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

const char* kProvider = "pam_faillock";
const char* kPolicy = "failed_authentication_attempts";
const char* kKey = "deny";

struct Harness {
    TempDir temp;
    std::filesystem::path configPath = temp.directory / "faillock.conf";
    std::filesystem::path journalPath = temp.directory / "journal.json";
    MutationJournal journal{journalPath};
    PamPlatformConfig platform;

    Harness() {
        std::string error;
        require(journal.initializeOrLoad(error), "journal init: " + error);
        PamCapabilityConfig capability;
        capability.capability = fic::platform::PamCapability::AuthenticationLockout;
        capability.provider = PamProviderKind::PamFaillock;
        capability.configurationMode =
            PamCapabilityConfigurationMode::ProviderConfigFile;
        capability.configPath = configPath;
        fic::platform::PamProviderConfigTopology topology;
        topology.primaryPath = configPath;
        capability.configTopology = topology;
        platform.capabilities.push_back(capability);
    }

    PamProviderRollbackOptions options() const {
        PamProviderRollbackOptions result;
        result.platform = platform;
        return result;
    }
};

// Foreign content kept byte-exact through every fixture.
const char* kForeign = "# admin comment\ndeny = 3\n";

std::string appliedBody(const std::string& value) {
    return pamProviderEntryBody(kKey, value);
}

UndoRemovePamProviderManagedEntry entryUndo(const std::string& applied,
                                            const std::string& previous) {
    UndoRemovePamProviderManagedEntry undo;
    undo.policyName = kPolicy;
    undo.providerName = kProvider;
    undo.configPath = ""; // set by caller (temp path differs per test)
    undo.managedKey = kKey;
    undo.appliedBody = applied;
    undo.previousAppliedBody = previous;
    undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
    return undo;
}

// Writes a physical state with exactly one FIC entry under the given id.
void writeEntryState(const std::filesystem::path& path,
                     std::uint64_t mutationId, const std::string& body,
                     const std::string& foreign = kForeign) {
    PamProviderEntrySpec spec;
    spec.provider = kProvider;
    spec.policy = kPolicy;
    spec.managedKey = kKey;
    const auto parsed =
        parseCanonicalPamProviderEntryBody(body, spec.managedKey,
                                           spec.value)
            ? spec
            : spec;
    (void)parsed;
    // Derive value from the canonical body.
    std::string key;
    std::string value;
    require(parseCanonicalPamProviderEntryBody(body, key, value),
            "fixture body must be canonical assignment");
    spec.managedKey = key;
    spec.value = value;
    spec.mutationId = mutationId;
    PamProviderMutationResult result =
        setPamProviderManagedEntry(foreign, spec,
                                   PamProviderBlockPlacementRequest::End);
    require(result.ok, "fixture entry apply: " + result.error);
    writeFile(path, result.content);
}

MutationRecord makeEntryRecord(Harness& harness, std::uint64_t id,
                               const std::string& applied,
                               const std::string& previous,
                               MutationStatus status) {
    UndoRemovePamProviderManagedEntry undo =
        entryUndo(applied, previous);
    undo.configPath = harness.configPath.string();
    MutationRecord record;
    record.id = id;
    record.policy = {"IDENTITY_ACCESS", "PAM", kPolicy};
    record.resource = harness.configPath.string();
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = status;
    return record;
}

// ---------------------------------------------------------------------
// Assignment matrix (Step 7F §83).
// ---------------------------------------------------------------------

void testAppliedExactRelease() {
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("8"));
    const std::string before = readFile(harness.configPath);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && !result.nothingToDo && result.changedSystemState,
            "applied exact must release: " + result.message);
    require(readFile(harness.configPath) == kForeign,
            "foreign bytes must survive byte-exact");
    require(before.find("FIC_PAM_ENTRY_BEGIN") != std::string::npos,
            "fixture must have had an entry");
}

void testAppliedMissingIsNothingToDo() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && result.nothingToDo,
            "missing entry is externally released state");
    require(readFile(harness.configPath) == kForeign,
            "nothing must be reconstructed");
}

void testBodyDriftConflict() {
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("9"));
    const std::string before = readFile(harness.configPath);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(!result.ok && result.conflict, "body drift must conflict");
    require(readFile(harness.configPath) == before,
            "drifted file must stay unchanged");
}

void testWrongMutationIdConflict() {
    Harness harness;
    writeEntryState(harness.configPath, 8, appliedBody("8"));
    const std::string before = readFile(harness.configPath);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(!result.ok && result.conflict,
            "wrong physical mutation id must conflict (ABA)");
    require(readFile(harness.configPath) == before, "file unchanged");
}

void testPreparedFreshAbsent() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Prepared);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && result.nothingToDo,
            "prepared fresh absent: the system was never mutated");
}

void testPreparedFreshTargetPresent() {
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("8"));
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Prepared);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && result.changedSystemState,
            "prepared fresh target present: release the target");
    require(readFile(harness.configPath) == kForeign, "foreign exact");
}

void testPreparedUpdatePreviousAndTarget() {
    // previous side physically present -> release previous.
    {
        Harness harness;
        writeEntryState(harness.configPath, 7, appliedBody("5"));
        MutationRecord record = makeEntryRecord(
            harness, 7, appliedBody("8"), appliedBody("5"),
            MutationStatus::Prepared);
        const PamProviderRollbackResult result = undoPamProviderManagedEntry(
            harness.options(), harness.journal, record,
            std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
        require(result.ok && result.changedSystemState,
            "prepared update previous present: release previous (rollback "
            "releases whichever durable side is proven, it does NOT finish "
            "the target)");
        require(readFile(harness.configPath) == kForeign, "foreign exact");
    }
    // target side physically present -> release target.
    {
        Harness harness;
        writeEntryState(harness.configPath, 7, appliedBody("8"));
        MutationRecord record = makeEntryRecord(
            harness, 7, appliedBody("8"), appliedBody("5"),
            MutationStatus::Prepared);
        const PamProviderRollbackResult result = undoPamProviderManagedEntry(
            harness.options(), harness.journal, record,
            std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
        require(result.ok && result.changedSystemState,
                "prepared update target present: release target");
        require(readFile(harness.configPath) == kForeign, "foreign exact");
    }
    // neither side -> conflict.
    {
        Harness harness;
        writeEntryState(harness.configPath, 7, appliedBody("6"));
        MutationRecord record = makeEntryRecord(
            harness, 7, appliedBody("8"), appliedBody("5"),
            MutationStatus::Prepared);
        const PamProviderRollbackResult result = undoPamProviderManagedEntry(
            harness.options(), harness.journal, record,
            std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
        require(!result.ok && result.conflict,
                "neither previous nor target proven must conflict");
    }
}

void testDisplacedBlockOwnershipSurvives() {
    // A valid FIC block displaced by foreign content is still owned:
    // placement is not ownership (§12).
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("8"));
    // Admin prepends a foreign line (block no longer at BOF/EOF effective
    // placement for a BOF-contract file).
    const std::string displaced = "top_rule = x\n" +
        readFile(harness.configPath);
    writeFile(harness.configPath, displaced);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && result.changedSystemState,
            "displaced block must still be releasable");
    require(readFile(harness.configPath) == std::string("top_rule = x\n") + kForeign,
            "foreign bytes (prepended + original) must survive byte-exact");
}

void testPlatformIdentityProof() {
    // The journal claims a config path the current profile does not confirm.
    Harness harness;
    UndoRemovePamProviderManagedEntry undo = entryUndo(appliedBody("8"), "");
    undo.configPath = "/elsewhere/faillock.conf";
    MutationRecord record;
    record.id = 7;
    record.policy = {"IDENTITY_ACCESS", "PAM", kPolicy};
    record.resource = undo.configPath;
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = MutationStatus::Applied;
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record, undo);
    require(!result.ok && result.conflict,
            "unconfirmed platform identity must conflict (no blind path "
            "execution)");
}

// ---------------------------------------------------------------------
// Flag matrix (Step 7F §84).
// ---------------------------------------------------------------------

const char* kFlagPolicy = "failed_authentication_enforce_for_root";
const char* kFlagKey = "even_deny_root";

UndoRemovePamProviderManagedFlag flagUndo(const Harness& harness,
                                          bool appliedEnabled,
                                          std::vector<std::string> ids) {
    UndoRemovePamProviderManagedFlag undo;
    undo.policyName = kFlagPolicy;
    undo.providerName = kProvider;
    undo.configPath = harness.configPath.string();
    undo.managedKey = kFlagKey;
    undo.appliedEnabled = appliedEnabled;
    undo.suppressionIds = std::move(ids);
    undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
    return undo;
}

MutationRecord makeFlagRecord(const Harness& harness, std::uint64_t id,
                              const UndoRemovePamProviderManagedFlag& undo,
                              MutationStatus status) {
    MutationRecord record;
    record.id = id;
    record.policy = {"IDENTITY_ACCESS", "PAM", undo.policyName};
    record.resource = undo.configPath;
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = status;
    return record;
}

// Physical disabled-flag state: FIC sentinel entry + authorized wrappers.
std::string renderDisabledState(const std::vector<std::string>& ids) {
    std::string content = kForeign;
    for (const std::string& id : ids) {
        content += pamProviderSuppressionWrapperLine(
            kProvider, kFlagPolicy, kFlagKey, 9, id, "even_deny_root");
        content += "\n";
    }
    PamProviderFlagSpec spec;
    spec.provider = kProvider;
    spec.policy = kFlagPolicy;
    spec.managedKey = kFlagKey;
    spec.enabled = false;
    spec.mutationId = 9;
    spec.keepSuppressionIds = ids;
    PamProviderFlagMutationResult result = setPamProviderManagedFlagTransition(
        content, spec, PamProviderBlockPlacementRequest::End);
    require(result.ok, "fixture disabled flag state: " + result.error);
    return result.content;
}

void testFlagAppliedFalseReleasesWrappers() {
    Harness harness;
    writeFile(harness.configPath,
              renderDisabledState({"s1", "s2", "s3"}));
    const std::string before = readFile(harness.configPath);
    UndoRemovePamProviderManagedFlag undo =
        flagUndo(harness, /*appliedEnabled=*/false, {"s1", "s2", "s3"});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok && result.changedSystemState,
            "applied false: sentinel removed + wrappers unwrapped: " +
                result.message);
    const std::string after = readFile(harness.configPath);
    require(after.find("FIC_PAM_") == std::string::npos,
            "no FIC serialization may remain");
    require(after.find("even_deny_root") != std::string::npos,
            "foreign raw lines restored");
    require(before.find("raw=even_deny_root") != std::string::npos,
            "fixture had wrappers");
}

void testFlagMissingAuthorizedWrapperSubset() {
    Harness harness;
    // s2 vanished externally: release must unwrap only s1/s3 and NEVER
    // reconstruct s2 (§21).
    std::string content = renderDisabledState({"s1", "s2", "s3"});
    const std::string wrapperS2 = pamProviderSuppressionWrapperLine(
        kProvider, kFlagPolicy, kFlagKey, 9, "s2", "even_deny_root");
    const auto position = content.find(wrapperS2 + "\n");
    require(position != std::string::npos, "fixture wrapper s2 present");
    content.erase(position, wrapperS2.size() + 1);
    writeFile(harness.configPath, content);

    UndoRemovePamProviderManagedFlag undo =
        flagUndo(harness, false, {"s1", "s2", "s3"});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok, "missing authorized wrapper subset is releasable: " +
                result.message);
    const std::string after = readFile(harness.configPath);
    require(after.find("FIC_PAM_") == std::string::npos,
            "no FIC serialization after release");
}

void testFlagUnknownWrapperConflict() {
    Harness harness;
    writeFile(harness.configPath, renderDisabledState({"s1", "s99"}));
    const std::string before = readFile(harness.configPath);
    UndoRemovePamProviderManagedFlag undo =
        flagUndo(harness, false, {"s1", "s2"});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(!result.ok && result.conflict,
            "unknown wrapper id must conflict (fail closed)");
    require(readFile(harness.configPath) == before, "file unchanged");
}

void testFlagWrongMutationWrapperConflict() {
    Harness harness;
    // Wrapper of the same identity but a foreign mutation id (11).
    std::string content = kForeign +
        pamProviderSuppressionWrapperLine(kProvider, kFlagPolicy, kFlagKey,
                                          11, "s1", "even_deny_root") +
        "\n";
    writeFile(harness.configPath, content);
    UndoRemovePamProviderManagedFlag undo =
        flagUndo(harness, false, {"s1"});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(!result.ok && result.conflict,
            "wrong-mutation wrapper must conflict (§23)");
}

void testFlagEnabledWithWrapperConflict() {
    Harness harness;
    // Journal claims enabled target; a physical wrapper of this record
    // exists (Step 7E drift invariant, §24).
    writeFile(harness.configPath,
              kForeign + pamProviderSuppressionWrapperLine(
                             kProvider, kFlagPolicy, kFlagKey, 9, "s1",
                             "even_deny_root") + "\n");
    UndoRemovePamProviderManagedFlag undo = flagUndo(harness, true, {});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(!result.ok && result.conflict,
            "enabled state with a matching wrapper must conflict");
}

// Physical enabled-flag state: FIC FlagEnabled entry, ZERO wrappers (the
// normal routed shape when no foreign active occurrence existed before).
std::string renderEnabledState() {
    PamProviderFlagSpec spec;
    spec.provider = kProvider;
    spec.policy = kFlagPolicy;
    spec.managedKey = kFlagKey;
    spec.enabled = true;
    spec.mutationId = 9;
    spec.keepSuppressionIds = {};
    PamProviderFlagMutationResult result = setPamProviderManagedFlagTransition(
        kForeign, spec, PamProviderBlockPlacementRequest::End);
    require(result.ok, "fixture enabled flag state: " + result.error);
    return result.content;
}

// Step 7F follow-up: an ENABLED applied state with an EMPTY suppression set
// is a valid owned state — the candidate matches the physical entry even
// though authorizedUnion stays empty. The release must SUCCESS, not fail
// with "entry kind не совпадает ни с одной авторизованной ownership state".
void testFlagAppliedEnabledZeroWrappers() {
    Harness harness;
    writeFile(harness.configPath, renderEnabledState());
    const std::string before = readFile(harness.configPath);
    UndoRemovePamProviderManagedFlag undo = flagUndo(harness, true, {});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok && result.changedSystemState,
            "applied enabled zero-wrapper state must release: " +
                result.message);
    const std::string after = readFile(harness.configPath);
    require(after == kForeign, "foreign bytes must survive byte-exact");
    require(after.find("FIC_PAM_") == std::string::npos,
            "no FIC serialization may remain");
    require(before.find("FIC_PAM_ENTRY_BEGIN") != std::string::npos,
            "fixture had the enabled entry");
}

// Step 7F follow-up: a DISABLED applied state whose authorized suppression
// set is empty (no foreign active occurrence before the apply) releases the
// bare sentinel even with an empty authorizedUnion.
void testFlagAppliedDisabledZeroWrappers() {
    Harness harness;
    writeFile(harness.configPath, renderDisabledState({}));
    UndoRemovePamProviderManagedFlag undo = flagUndo(harness, false, {});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok && result.changedSystemState,
            "applied disabled zero-wrapper state must release: " +
                result.message);
    const std::string after = readFile(harness.configPath);
    require(after == kForeign, "foreign bytes must survive byte-exact");
    require(after.find("FIC_PAM_") == std::string::npos,
            "no FIC serialization may remain");
}

// Prepared target enabled: previous absent/false, target=true, the physical
// state is the target-side FlagEnabled without wrappers — releasable.
void testFlagPreparedTargetEnabledZeroWrappers() {
    Harness harness;
    writeFile(harness.configPath, renderEnabledState());
    UndoRemovePamProviderManagedFlag undo = flagUndo(harness, true, {});
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Prepared);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok && result.changedSystemState,
            "prepared target enabled zero-wrapper must release: " +
                result.message);
    require(readFile(harness.configPath) == kForeign, "foreign exact");
}

// Prepared previous enabled: target=false with an empty authorized set
// (no foreign occurrence before), previous=true, the physical state is the
// previous-side FlagEnabled without wrappers — releasable.
void testFlagPreparedPreviousEnabledZeroWrappers() {
    Harness harness;
    writeFile(harness.configPath, renderEnabledState());
    UndoRemovePamProviderManagedFlag undo = flagUndo(harness, false, {});
    undo.previousAppliedEnabled = true;
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::Prepared);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok && result.changedSystemState,
            "prepared previous enabled zero-wrapper must release: " +
                result.message);
    require(readFile(harness.configPath) == kForeign, "foreign exact");
}

void testFlagPreparedPreviousAndTargetSides() {
    // Prepared false(0) -> false(0): previous and target wrapper sets are
    // both authorized; the physical state matches both candidates.
    {
        Harness harness;
        writeFile(harness.configPath, renderDisabledState({"s1", "s2"}));
        UndoRemovePamProviderManagedFlag undo =
            flagUndo(harness, false, {"s1", "s2"});
        undo.previousAppliedEnabled = false;
        undo.previousSuppressionIds = {"s1"};
        MutationRecord record = makeFlagRecord(harness, 9, undo,
                                               MutationStatus::Prepared);
        const PamProviderRollbackResult result = undoPamProviderManagedFlag(
            harness.options(), harness.journal, record, undo);
        require(result.ok, "false->false prepared growth release: " +
                    result.message);
        require(readFile(harness.configPath).find("FIC_PAM_") ==
                std::string::npos, "fully released");
    }
    // Prepared previous=true / target=false: the disabled target side is
    // physically present and releases.
    {
        Harness harness;
        writeFile(harness.configPath, renderDisabledState({"s1"}));
        UndoRemovePamProviderManagedFlag undo =
            flagUndo(harness, false, {"s1"});
        undo.previousAppliedEnabled = true;
        MutationRecord record = makeFlagRecord(harness, 9, undo,
                                               MutationStatus::Prepared);
        const PamProviderRollbackResult result = undoPamProviderManagedFlag(
            harness.options(), harness.journal, record, undo);
        require(result.ok, "prepared target side release: " + result.message);
    }
}

void testFlagRollbackFailedTargetAuthorityOnly() {
    Harness harness;
    writeFile(harness.configPath, renderDisabledState({"s1"}));
    // previousSuppressionIds are historical provenance and must not extend
    // the release authority for a RollbackFailed record: an s99 wrapper is
    // still a conflict even though 'previous' would not authorize it either.
    UndoRemovePamProviderManagedFlag undo =
        flagUndo(harness, false, {"s1"});
    undo.previousAppliedEnabled = false;
    undo.previousSuppressionIds = {"sold"};
    MutationRecord record = makeFlagRecord(harness, 9, undo,
                                           MutationStatus::RollbackFailed);
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(result.ok, "rollbackfailed target authority releases: " +
                result.message);
}

// ---------------------------------------------------------------------
// Container provenance + crash/retry (Step 7F §85-§87).
// ---------------------------------------------------------------------

fic::rollback::MutationId prepareContainerRecord(Harness& harness) {
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER", kProvider};
    record.resource = harness.configPath.string();
    record.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoOwnPamProviderContainer{kProvider, harness.configPath.string()}};
    std::string error;
    fic::rollback::MutationId id = 0;
    require(harness.journal.prepareMutation(record, id, error),
            "container prepare: " + error);
    require(harness.journal.setStatus(id, MutationStatus::Applied, error),
            "container apply: " + error);
    return id;
}

void testFicCreatedEmptyContainerDeleted() {
    Harness harness;
    // FIC-created container: the file consists ONLY of the FIC block.
    writeEntryState(harness.configPath, 7, appliedBody("8"), "");
    const fic::rollback::MutationId containerId =
        prepareContainerRecord(harness);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && result.changedSystemState,
            "last entry + empty + proven container: conditional delete: " +
                result.message);
    require(!std::filesystem::exists(harness.configPath),
            "the FIC-created empty container must be deleted");
    bool resolved = false;
    for (const MutationRecord& current : harness.journal.records()) {
        if (current.id == containerId) {
            resolved = current.status == MutationStatus::RolledBack;
        }
    }
    require(resolved, "container provenance must be RolledBack (§38)");
    // The policy record itself is NOT resolved by the backend: the outer
    // RollbackExecutor owns that lifecycle step.
    require(record.status == MutationStatus::Applied,
            "policy record stays active until the executor resolves it");
}

void testFicCreatedWithForeignDetached() {
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("8"));
    const fic::rollback::MutationId containerId =
        prepareContainerRecord(harness);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok, "foreign-content container release: " +
                result.message);
    require(std::filesystem::exists(harness.configPath),
            "file retained with foreign bytes");
    require(readFile(harness.configPath) == kForeign, "foreign exact");
    bool detached = false;
    for (const MutationRecord& current : harness.journal.records()) {
        if (current.id == containerId) {
            detached = current.status == MutationStatus::Detached;
        }
    }
    require(detached, "foreign-only container must be Detached (§39)");
}

void testPreExistingContainerRetained() {
    Harness harness;
    // No container provenance: the (pre-existing) file is NEVER unlinked,
    // even when it becomes empty (§40).
    writeEntryState(harness.configPath, 7, appliedBody("8"), "x\n");
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok, "pre-existing container release: " + result.message);
    require(std::filesystem::exists(harness.configPath),
            "pre-existing file never deleted");
}

void testOtherFicEntryKeepsContainerActive() {
    Harness harness;
    // Two entries: removing one must NOT touch the container provenance.
    writeEntryState(harness.configPath, 7, appliedBody("8"));
    const fic::rollback::MutationId containerId =
        prepareContainerRecord(harness);
    // Add a second entry of another policy through the pure helper.
    {
        PamProviderEntrySpec spec;
        spec.provider = kProvider;
        spec.policy = "failed_authentication_unlock_time";
        spec.managedKey = "unlock_time";
        spec.value = "30";
        spec.mutationId = 8;
        PamProviderMutationResult result = setPamProviderManagedEntry(
            readFile(harness.configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(result.ok, "second entry fixture");
        writeFile(harness.configPath, result.content);
    }
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult release = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(release.ok, "first entry release: " + release.message);
    require(std::filesystem::exists(harness.configPath),
            "container kept (other FIC entries remain, §41)");
    bool active = false;
    for (const MutationRecord& current : harness.journal.records()) {
        if (current.id == containerId) {
            active = current.status == MutationStatus::Applied;
        }
    }
    require(active, "container provenance stays Applied");
}

void testFsyncFailureAfterUnlinkRecovers() {
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("8"), "");
    const fic::rollback::MutationId containerId =
        prepareContainerRecord(harness);
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    const PamProviderRollbackResult failed = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(!failed.ok,
            "unlink installed but fsync failed: NOT durable, failure");
    require(failed.changedSystemState,
            "the unlink happened — the system WAS mutated");
    bool containerResolved = false;
    for (const MutationRecord& current : harness.journal.records()) {
        if (current.id == containerId) {
            containerResolved =
                current.status == MutationStatus::Applied; // still active
        }
    }
    require(containerResolved,
            "journal ownership NOT resolved without durability (§35)");

    // Crash-recovery retry (§85): the file is gone; durable absence +
    // lifecycle completion.
    require(!std::filesystem::exists(harness.configPath),
            "the unlink from the failed attempt is visible");
    const PamProviderRollbackResult retry = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(retry.ok && retry.nothingToDo,
            "retry completes the lifecycle: " + retry.message);
    bool resolved = false;
    for (const MutationRecord& current : harness.journal.records()) {
        if (current.id == containerId) {
            resolved = current.status == MutationStatus::RolledBack;
        }
    }
    require(resolved, "retry resolves the container provenance");
}

void testNoReconstructionOnRetry() {
    // Crash after the physical release but before the policy journal
    // update (§44/§87): retry classifies as already released and never
    // recreates the managed entry.
    Harness harness;
    writeFile(harness.configPath, kForeign); // physical state already gone
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record,
        std::get<UndoRemovePamProviderManagedEntry>(record.undo.payload));
    require(result.ok && result.nothingToDo, "retry is a typed no-op");
    require(readFile(harness.configPath) == kForeign,
            "no managed entry / sentinel / wrapper reconstruction");
}

} // namespace

// ---------------------------------------------------------------------
// Step 7F final security follow-up regressions.
// ---------------------------------------------------------------------

fic::rollback::MutationId prepareContainerRecordAt(
    Harness& harness, const std::string& providerName,
    const std::string& configPath) {
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER", providerName};
    record.resource = configPath;
    record.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoOwnPamProviderContainer{providerName, configPath}};
    std::string error;
    fic::rollback::MutationId id = 0;
    require(harness.journal.prepareMutation(record, id, error),
            "container prepare: " + error);
    require(harness.journal.setStatus(id, MutationStatus::Applied, error),
            "container apply: " + error);
    return id;
}

MutationRecord journalRecordById(Harness& harness,
                                 fic::rollback::MutationId id) {
    for (const MutationRecord& current : harness.journal.records()) {
        if (current.id == id) {
            return current;
        }
    }
    throw std::runtime_error("journal record not found");
}

// The CURRENT platform profile must confirm the journaled container
// identity (provider + lexically-exact config path) through the typed SSOT
// BEFORE any journal path read/mutation: a wrong path is a Conflict, never
// a blind readForMutation of an unconfirmed location.
void testContainerWrongPathPlatformProof() {
    Harness harness;
    const std::filesystem::path foreignPath =
        harness.temp.directory / "other.conf";
    writeFile(foreignPath, kForeign);
    const fic::rollback::MutationId id =
        prepareContainerRecordAt(harness, kProvider, foreignPath.string());
    MutationRecord record = journalRecordById(harness, id);
    const PamProviderRollbackResult result = undoOwnPamProviderContainer(
        harness.options(), harness.journal, record,
        std::get<UndoOwnPamProviderContainer>(record.undo.payload));
    require(!result.ok,
            "container provenance with a wrong path must be rejected: " +
                result.message);
    require(result.message.find("platform profile") != std::string::npos,
            "rejection must name the platform identity proof: " +
                result.message);
    require(std::filesystem::exists(foreignPath),
            "the unconfirmed path must stay untouched");
    require(journalRecordById(harness, id).status == MutationStatus::Applied,
            "the rejected container record stays Applied");
}

// Same proof, wrong provider identity for the capability path.
void testContainerWrongProviderPlatformProof() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    const fic::rollback::MutationId id = prepareContainerRecordAt(
        harness, "pam_pwquality", harness.configPath.string());
    MutationRecord record = journalRecordById(harness, id);
    const PamProviderRollbackResult result = undoOwnPamProviderContainer(
        harness.options(), harness.journal, record,
        std::get<UndoOwnPamProviderContainer>(record.undo.payload));
    require(!result.ok,
            "container provenance with a wrong provider must be rejected: " +
                result.message);
    require(std::filesystem::exists(harness.configPath),
            "the capability path stays untouched on provider mismatch");
    require(journalRecordById(harness, id).status == MutationStatus::Applied,
            "the rejected container record stays Applied");
}


// A resolved (Detached) container provenance record has no second lifecycle
// owner: re-running the container sweep with the stale record copy must be
// refused BEFORE any read/mutation of the foreign-content file.
void testDetachedContainerNoSecondLifecycle() {
    Harness harness;
    writeEntryState(harness.configPath, 7, appliedBody("8"));
    const fic::rollback::MutationId containerId =
        prepareContainerRecordAt(harness, kProvider,
                                 harness.configPath.string());
    MutationRecord entryRecord = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    const PamProviderRollbackResult entryResult = undoPamProviderManagedEntry(
        harness.options(), harness.journal, entryRecord,
        std::get<UndoRemovePamProviderManagedEntry>(
            entryRecord.undo.payload));
    require(entryResult.ok, "entry release detaches the container: " +
                entryResult.message);
    MutationRecord containerCopy = journalRecordById(harness, containerId);
    require(containerCopy.status == MutationStatus::Detached,
            "fixture: container provenance Detached");
    const std::string before = readFile(harness.configPath);
    const PamProviderRollbackResult second = undoOwnPamProviderContainer(
        harness.options(), harness.journal, containerCopy,
        std::get<UndoOwnPamProviderContainer>(containerCopy.undo.payload));
    require(!second.ok,
            "a resolved container record must never be processed again: " +
                second.message);
    require(readFile(harness.configPath) == before,
            "no second lifecycle write into the detached container");
    require(journalRecordById(harness, containerId).status ==
                MutationStatus::Detached,
            "the container provenance stays Detached");
}

// Native option syntax binding: an assignment key can never travel through
// UndoRemovePamProviderManagedFlag.
void testFlagAssignmentMasqueradeConflict() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    UndoRemovePamProviderManagedFlag undo =
        flagUndo(harness, /*appliedEnabled=*/false, {"s1"});
    undo.managedKey = "deny"; // assignment key
    undo.policyName = "failed_authentication_attempts"; // canonical for "deny"
    MutationRecord record =
        makeFlagRecord(harness, 9, undo, MutationStatus::Applied);
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        harness.options(), harness.journal, record, undo);
    require(!result.ok,
            "assignment key through a flag payload must be rejected: " +
                result.message);
    require(result.message.find("syntax") != std::string::npos,
            "rejection must name the native option syntax proof: " +
                result.message);
}

// ...and a flag key can never travel through
// UndoRemovePamProviderManagedEntry.
void testEntryFlagMasqueradeConflict() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    UndoRemovePamProviderManagedEntry undo = entryUndo(appliedBody("8"), "");
    undo.configPath = harness.configPath.string();
    undo.managedKey = kFlagKey; // flag key through an entry payload
    undo.policyName = kFlagPolicy; // canonical for even_deny_root
    MutationRecord record = makeEntryRecord(
        harness, 9, appliedBody("8"), "", MutationStatus::Applied);
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record, undo);
    require(!result.ok,
            "flag key through an entry payload must be rejected: " +
                result.message);
    require(result.message.find("syntax") != std::string::npos,
            "rejection must name the native option syntax proof: " +
                result.message);
}

// Canonical policy identity binding: the routing binding of the managed key
// must belong to the journaled canonical policy — a wrong policy for a
// correct key is a Conflict.
void testWrongPolicyForCorrectKeyConflict() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    UndoRemovePamProviderManagedEntry undo = entryUndo(appliedBody("8"), "");
    undo.configPath = harness.configPath.string();
    undo.policyName = "failed_authentication_counting_period"; // wrong identity
    MutationRecord record = makeEntryRecord(
        harness, 7, appliedBody("8"), "", MutationStatus::Applied);
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        harness.options(), harness.journal, record, undo);
    require(!result.ok,
            "wrong canonical policy for a correct key must be rejected: " +
                result.message);
    require(result.message.find("policy") != std::string::npos,
            "rejection must name the canonical policy identity proof: " +
                result.message);
}

// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Step 7F security follow-up: route-aware managed primary enumeration.
// ---------------------------------------------------------------------

fic::platform::PamCapabilityConfig altShapeCapability(
    PamProviderKind provider, const std::filesystem::path& configPath,
    fic::platform::PamTopologyStrategyKind topology,
    std::optional<fic::platform::PamCapabilityConfigurationMode> mode =
        std::nullopt) {
    PamCapabilityConfig capability;
    capability.provider = provider;
    capability.configPath = configPath;
    capability.topology = topology;
    if (mode.has_value()) {
        capability.configurationMode = *mode;
    }
    return capability;
}

bool containsPath(const std::vector<std::filesystem::path>& paths,
                  const std::filesystem::path& path) {
    for (const std::filesystem::path& current : paths) {
        if (current == path) {
            return true;
        }
    }
    return false;
}

// ALT p11-shaped profile: only the faillock ProviderConfigFile capability
// actually routes a managed Step 7 policy. passwdqc (ProviderConfigFile,
// legacy Assignment-only route) and the AltTcbManaged pwhistory are NOT
// managed provider domains and must never be enumerated as primaries.
void testManagedPrimaryPathsRouteAwareAltProfile() {
    TempDir temp;
    const std::filesystem::path faillockPath =
        temp.directory / "faillock.conf";
    const std::filesystem::path passwdqcPath =
        temp.directory / "passwdqc.conf";
    const std::filesystem::path pwhistoryPath =
        temp.directory / "fic-pwhistory.conf";
    fic::platform::PamPlatformConfig platform;
    platform.capabilities.push_back(altShapeCapability(
        PamProviderKind::PamFaillock, faillockPath,
        fic::platform::PamTopologyStrategyKind::AltTcbManaged));
    platform.capabilities.push_back(altShapeCapability(
        PamProviderKind::PamPasswdqc, passwdqcPath,
        fic::platform::PamTopologyStrategyKind::StaticVerifyOnly));
    platform.capabilities.push_back(altShapeCapability(
        PamProviderKind::PamPwhistory, pwhistoryPath,
        fic::platform::PamTopologyStrategyKind::AltTcbManaged));
    const std::vector<std::filesystem::path> primaries =
        pamProviderManagedPrimaryPaths(platform);
    require(primaries.size() == 1,
            "ALT profile: exactly one managed provider primary (faillock)");
    require(primaries.front() == faillockPath,
            "ALT profile: the faillock primary is enumerated");
    require(!containsPath(primaries, passwdqcPath),
            "ALT profile: passwdqc.conf is NOT a managed provider primary");
    require(!containsPath(primaries, pwhistoryPath),
            "ALT profile: fic-pwhistory.conf is NOT a managed provider "
            "primary");
}

// D13/U24/U26-like profile: pwhistory is ProviderConfigFile +
// PamAuthUpdate — managed remember/enforce_for_root routes exist, so all
// three primaries are enumerated. D12-like profile: pwhistory is
// ModuleArguments (Step 6 joint coordinator) — never a managed primary.
void testManagedPrimaryPathsRouteAwareDebianProfiles() {
    {
        TempDir temp;
        const std::filesystem::path faillockPath =
            temp.directory / "faillock.conf";
        const std::filesystem::path pwqualityPath =
            temp.directory / "pwquality.conf";
        const std::filesystem::path pwhistoryPath =
            temp.directory / "pwhistory.conf";
        fic::platform::PamPlatformConfig platform;
        platform.capabilities.push_back(altShapeCapability(
            PamProviderKind::PamFaillock, faillockPath,
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate));
        platform.capabilities.push_back(altShapeCapability(
            PamProviderKind::PamPwquality, pwqualityPath,
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate));
        platform.capabilities.push_back(altShapeCapability(
            PamProviderKind::PamPwhistory, pwhistoryPath,
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate));
        const std::vector<std::filesystem::path> primaries =
            pamProviderManagedPrimaryPaths(platform);
        require(primaries.size() == 3,
                "D13-like profile: all three managed primaries enumerated");
        require(containsPath(primaries, faillockPath),
                "D13-like profile: faillock.conf is a managed primary");
        require(containsPath(primaries, pwqualityPath),
                "D13-like profile: pwquality.conf is a managed primary");
        require(containsPath(primaries, pwhistoryPath),
                "D13-like profile: pwhistory.conf is a managed primary");
    }
    {
        TempDir temp;
        const std::filesystem::path faillockPath =
            temp.directory / "faillock.conf";
        const std::filesystem::path pwqualityPath =
            temp.directory / "pwquality.conf";
        const std::filesystem::path pwhistoryPath =
            temp.directory / "pwhistory.conf";
        fic::platform::PamPlatformConfig platform;
        platform.capabilities.push_back(altShapeCapability(
            PamProviderKind::PamFaillock, faillockPath,
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate));
        platform.capabilities.push_back(altShapeCapability(
            PamProviderKind::PamPwquality, pwqualityPath,
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate));
        platform.capabilities.push_back(altShapeCapability(
            PamProviderKind::PamPwhistory, pwhistoryPath,
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate,
            fic::platform::PamCapabilityConfigurationMode::ModuleArguments));
        const std::vector<std::filesystem::path> primaries =
            pamProviderManagedPrimaryPaths(platform);
        require(primaries.size() == 2,
                "D12-like profile: exactly two managed primaries");
        require(!containsPath(primaries, pwhistoryPath),
                "D12-like profile: ModuleArguments pwhistory is NOT "
                "enumerated");
    }
}


// The container provenance proof uses the SAME shared managed-domain
// predicate as the primary enumeration: a ProviderConfigFile capability
// WITHOUT a managed Step 7 route (ALT passwdqc / ALT pwhistory
// AltTcbManaged) can never confirm container provenance — Conflict before
// any journal path read/mutation. The managed faillock capability stays
// provable (positive control).
void testContainerUnmanagedCapabilityConflict() {
    {
        Harness harness;
        harness.platform.capabilities.clear();
        const std::filesystem::path passwdqcPath =
            harness.temp.directory / "passwdqc.conf";
        PamCapabilityConfig capability;
        capability.provider = PamProviderKind::PamPasswdqc;
        capability.configurationMode =
            PamCapabilityConfigurationMode::ProviderConfigFile;
        capability.configPath = passwdqcPath;
        harness.platform.capabilities.push_back(capability);
        writeFile(passwdqcPath, kForeign);
        const fic::rollback::MutationId id = prepareContainerRecordAt(
            harness, "pam_passwdqc", passwdqcPath.string());
        MutationRecord record = journalRecordById(harness, id);
        const PamProviderRollbackResult result = undoOwnPamProviderContainer(
            harness.options(), harness.journal, record,
            std::get<UndoOwnPamProviderContainer>(record.undo.payload));
        require(!result.ok,
                "container provenance for an unmanaged capability must be "
                "rejected: " + result.message);
        require(result.conflict, "rejection must be a Conflict");
        require(result.message.find("managed") != std::string::npos,
                "rejection must name the managed-provider domain proof: " +
                    result.message);
        require(std::filesystem::exists(passwdqcPath),
                "the unmanaged path stays untouched");
        require(journalRecordById(harness, id).status ==
                    MutationStatus::Applied,
                "the rejected container record stays Applied");
    }
    {
        Harness harness;
        harness.platform.capabilities.clear();
        const std::filesystem::path pwhistoryPath =
            harness.temp.directory / "fic-pwhistory.conf";
        PamCapabilityConfig capability;
        capability.provider = PamProviderKind::PamPwhistory;
        capability.configurationMode =
            PamCapabilityConfigurationMode::ProviderConfigFile;
        capability.configPath = pwhistoryPath;
        capability.topology =
            fic::platform::PamTopologyStrategyKind::AltTcbManaged;
        harness.platform.capabilities.push_back(capability);
        writeFile(pwhistoryPath, kForeign);
        const fic::rollback::MutationId id = prepareContainerRecordAt(
            harness, "pam_pwhistory", pwhistoryPath.string());
        MutationRecord record = journalRecordById(harness, id);
        const PamProviderRollbackResult result = undoOwnPamProviderContainer(
            harness.options(), harness.journal, record,
            std::get<UndoOwnPamProviderContainer>(record.undo.payload));
        require(!result.ok && result.conflict,
                "ALT pwhistory container provenance must Conflict: " +
                    result.message);
        require(journalRecordById(harness, id).status ==
                    MutationStatus::Applied,
                "the rejected container record stays Applied");
    }
    {
        Harness harness;
        std::string message;
        const std::optional<PamProviderContainerRollbackRoute> route =
            pamProviderContainerRollbackRouteForPayload(
                harness.options(), kProvider, harness.configPath.string(),
                message);
        require(route.has_value(),
                "managed faillock container route still proves: " + message);
        require(route->configPath == harness.configPath,
                "managed faillock container route keeps the exact primary");
    }
}

int main() {
    try {
        testAppliedExactRelease();
        testAppliedMissingIsNothingToDo();
        testBodyDriftConflict();
        testWrongMutationIdConflict();
        testPreparedFreshAbsent();
        testPreparedFreshTargetPresent();
        testPreparedUpdatePreviousAndTarget();
        testDisplacedBlockOwnershipSurvives();
        testPlatformIdentityProof();
        testFlagAppliedFalseReleasesWrappers();
        testFlagAppliedEnabledZeroWrappers();
        testFlagAppliedDisabledZeroWrappers();
        testFlagPreparedTargetEnabledZeroWrappers();
        testFlagPreparedPreviousEnabledZeroWrappers();
        testFlagMissingAuthorizedWrapperSubset();
        testFlagUnknownWrapperConflict();
        testFlagWrongMutationWrapperConflict();
        testFlagEnabledWithWrapperConflict();
        testFlagPreparedPreviousAndTargetSides();
        testFlagRollbackFailedTargetAuthorityOnly();
        testFicCreatedEmptyContainerDeleted();
        testFicCreatedWithForeignDetached();
        testPreExistingContainerRetained();
        testOtherFicEntryKeepsContainerActive();
        testFsyncFailureAfterUnlinkRecovers();
        testNoReconstructionOnRetry();
        testContainerWrongPathPlatformProof();
        testContainerWrongProviderPlatformProof();
        testDetachedContainerNoSecondLifecycle();
        testFlagAssignmentMasqueradeConflict();
        testEntryFlagMasqueradeConflict();
        testWrongPolicyForCorrectKeyConflict();
        testManagedPrimaryPathsRouteAwareAltProfile();
        testManagedPrimaryPathsRouteAwareDebianProfiles();
        testContainerUnmanagedCapabilityConflict();
    } catch (const std::exception& error) {
        std::cerr << "PamProviderRollbackTests failed: " << error.what()
                  << '\n';
        return 1;
    }
    std::cout << "PamProviderRollbackTests passed\n";
    return 0;
}
