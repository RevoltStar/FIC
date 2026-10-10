#include "modules/identity_access/pam/PamProviderPackageRelease.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace fic::identity::pam;
using fic::platform::PamCapabilityConfig;
using fic::platform::PamCapabilityConfigurationMode;
using fic::platform::PamPlatformConfig;
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
        char pattern[] = "/tmp/fic-pam-provider-release-XXXXXX";
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
    std::filesystem::path configPath = temp.directory / "faillock.conf";
    std::filesystem::path journalPath = temp.directory / "journal.json";
    MutationJournal journal{journalPath};
    PamPlatformConfig platform;

    // capabilityTopology=false renders the PRODUCTION profile shape:
    // ProviderConfigFile route with capability.configTopology = nullopt (the
    // provider topology lives in provider.defaultConfigTopology). Fixtures
    // for Step 7F follow-up regressions must use this shape — an explicit
    // configTopology previously masked a production bug in
    // knownProviderPrimaries.
    explicit Harness(bool capabilityTopology = true) {
        std::string error;
        require(journal.initializeOrLoad(error), "journal init: " + error);
        PamCapabilityConfig capability;
        capability.provider = fic::platform::PamProviderKind::PamFaillock;
        capability.configurationMode =
            PamCapabilityConfigurationMode::ProviderConfigFile;
        capability.configPath = configPath;
        if (capabilityTopology) {
            fic::platform::PamProviderConfigTopology topology;
            topology.primaryPath = configPath;
            capability.configTopology = topology;
        }
        platform.capabilities.push_back(capability);
    }

    PamProviderPackageRelease::Options options() const {
        PamProviderPackageRelease::Options result;
        // Tests: no lock (the lock-domain behavior is exercised separately).
        return result;
    }
};

const char* kProvider = "pam_faillock";
const char* kPolicy = "failed_authentication_attempts";
const char* kForeign = "# admin comment\ndeny = 3\n";

void applyEntryFixture(Harness& harness, std::uint64_t id,
                       const std::string& value) {
    PamProviderEntrySpec spec;
    spec.provider = kProvider;
    spec.policy = kPolicy;
    spec.managedKey = "deny";
    spec.value = value;
    spec.mutationId = id;
    PamProviderMutationResult result = setPamProviderManagedEntry(
        kForeign, spec, PamProviderBlockPlacementRequest::End);
    require(result.ok, "entry fixture: " + result.error);
    writeFile(harness.configPath, result.content);
}

fic::rollback::MutationId prepareEntryRecord(Harness& harness, std::uint64_t id,
                                             const std::string& value) {
    UndoRemovePamProviderManagedEntry undo;
    undo.policyName = kPolicy;
    undo.providerName = kProvider;
    undo.configPath = harness.configPath.string();
    undo.managedKey = "deny";
    undo.appliedBody = pamProviderEntryBody("deny", value);
    undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
    MutationRecord record;
    record.id = id;
    record.policy = {"IDENTITY_ACCESS", "PAM", kPolicy};
    record.resource = harness.configPath.string();
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = MutationStatus::Applied;
    // Insert the record verbatim into the journal through the raw document
    // path used by tests: prepareMutation assigns a fresh id, so rewrite the
    // record id afterwards via a direct persisted reload is complex — tests
    // therefore prepare and rename through setStatusWithMessage only when
    // the id matches. Simplest: prepare, then check.
    std::string error;
    fic::rollback::MutationId assigned = 0;
    require(harness.journal.prepareMutation(record, assigned, error),
            "prepare: " + error);
    require(harness.journal.setStatus(assigned, MutationStatus::Applied,
                                      error),
            "apply: " + error);
    return assigned;
}

void testCleanNoop() {
    Harness harness;
    writeFile(harness.configPath, kForeign);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(release.run(PamProviderPackageRelease::Mode::Preflight, report,
                        error),
            "clean preflight: " + error);
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "clean release: " + error);
    require(!report.changedSystemState, "clean release mutates nothing");
}

void testPreflightDoesNotMutate() {
    Harness harness;
    applyEntryFixture(harness, 1, "8");
    const fic::rollback::MutationId id =
        prepareEntryRecord(harness, 1, "8");
    (void)id;
    const std::string configBefore = readFile(harness.configPath);
    const std::string journalBefore = readFile(harness.journalPath);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(release.run(PamProviderPackageRelease::Mode::Preflight, report,
                        error),
            "preflight: " + error);
    require(readFile(harness.configPath) == configBefore,
            "config bytes unchanged by preflight");
    require(readFile(harness.journalPath) == journalBefore,
            "journal bytes unchanged by preflight");
    for (const MutationRecord& record : harness.journal.records()) {
        require(record.isActive(), "statuses unchanged by preflight");
    }
}

void testActiveAssignmentRelease() {
    Harness harness;
    applyEntryFixture(harness, 1, "8");
    prepareEntryRecord(harness, 1, "8");
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "release: " + error);
    require(report.releasedRecords.size() == 1, "one record released");
    require(readFile(harness.configPath) == kForeign,
            "foreign content preserved");
    for (const MutationRecord& record : harness.journal.records()) {
        require(!record.isActive(), "record resolved");
    }
}

void testOrphanBlockRejects() {
    Harness harness;
    // Physical FIC block WITHOUT journal provenance (§68).
    applyEntryFixture(harness, 1, "8");
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "orphan block must fail the preflight closed");
    require(readFile(harness.configPath).find("FIC_PAM_") !=
                std::string::npos,
            "orphan marker untouched");
}

void testPartialReleaseAndRetry() {
    Harness harness;
    applyEntryFixture(harness, 1, "8");
    prepareEntryRecord(harness, 1, "8");
    // Second policy record whose physical entry drifted -> release blocked.
    {
        PamProviderEntrySpec spec;
        spec.provider = kProvider;
        spec.policy = "failed_authentication_unlock_time";
        spec.managedKey = "unlock_time";
        spec.value = "30";
        spec.mutationId = 2;
        PamProviderMutationResult result = setPamProviderManagedEntry(
            readFile(harness.configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(result.ok, "second entry fixture");
        writeFile(harness.configPath, result.content);
    }
    {
        UndoRemovePamProviderManagedEntry undo;
        undo.policyName = "failed_authentication_unlock_time";
        undo.providerName = kProvider;
        undo.configPath = harness.configPath.string();
        undo.managedKey = "unlock_time";
        undo.appliedBody = pamProviderEntryBody("unlock_time", "99");
        undo.placement =
            fic::rollback::PamProviderBlockPlacementContract::End;
        MutationRecord record;
        record.policy = {"IDENTITY_ACCESS", "PAM",
                         "failed_authentication_unlock_time"};
        record.resource = undo.configPath;
        record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
        record.status = MutationStatus::Applied;
        std::string error;
        fic::rollback::MutationId assigned = 0;
        require(harness.journal.prepareMutation(record, assigned, error),
                "prepare second");
        require(harness.journal.setStatus(assigned, MutationStatus::Applied,
                                          error),
                "apply second");
    }
    // Step 7F follow-up: Stage B re-runs the full Stage A preflight, and a
    // drifted record is a non-releasable binding state — the release is
    // refused WHOLE (fail closed) BEFORE any record is released. Stage A and
    // Stage B are strictly consistent: a state Stage A refuses can never
    // produce a partial package-release mutation.
    const std::string configBefore = readFile(harness.configPath);
    const std::string journalBefore = readFile(harness.journalPath);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Release, report,
                          error),
            "drifted second record blocks the whole release: " + error);
    require(error.find("non-releasable") != std::string::npos,
            "Stage B refusal must name the binding state: " + error);
    require(readFile(harness.configPath) == configBefore,
            "config untouched by the blocked release");
    require(readFile(harness.journalPath) == journalBefore,
            "journal untouched by the blocked release");
    // Retry after the external drift is fixed completes the release.
    {
        PamProviderEntrySpec spec;
        spec.provider = kProvider;
        spec.policy = "failed_authentication_unlock_time";
        spec.managedKey = "unlock_time";
        spec.value = "99";
        spec.mutationId = 2;
        PamProviderMutationResult result = setPamProviderManagedEntry(
            readFile(harness.configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(result.ok, "drift fix fixture");
        writeFile(harness.configPath, result.content);
    }
    PamProviderPackageRelease retry(harness.journal, harness.platform,
                                    harness.options());
    PamProviderPackageRelease::Report retryReport;
    require(retry.run(PamProviderPackageRelease::Mode::Release, retryReport,
                      error),
            "retry completes: " + error);
    require(readFile(harness.configPath) == kForeign,
            "final state is foreign-only");
}

// Package-level flag/container coverage (Step 7F §92). The journal record
// id is assigned by prepareMutation, so the physical state is rendered
// AFTER preparation with the assigned id (physical == journal mutation id
// is part of the ownership proof).

void renderEntryState(const std::filesystem::path& path,
                      const std::string& provider, const std::string& policy,
                      const std::string& managedKey,
                      const std::string& value, std::uint64_t mutationId,
                      const std::string& foreign) {
    PamProviderEntrySpec spec;
    spec.provider = provider;
    spec.policy = policy;
    spec.managedKey = managedKey;
    spec.value = value;
    spec.mutationId = mutationId;
    PamProviderMutationResult result =
        setPamProviderManagedEntry(foreign, spec,
                                   PamProviderBlockPlacementRequest::End);
    require(result.ok, "entry render: " + result.error);
    writeFile(path, result.content);
}

fic::rollback::MutationId prepareEntryRecordId(
    Harness& harness, const std::string& policy, const std::string& provider,
    const std::string& managedKey, const std::string& value,
    const std::string& configPath) {
    UndoRemovePamProviderManagedEntry undo;
    undo.policyName = policy;
    undo.providerName = provider;
    undo.configPath = configPath;
    undo.managedKey = managedKey;
    undo.appliedBody = pamProviderEntryBody(managedKey, value);
    undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", policy};
    record.resource = configPath;
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = MutationStatus::Prepared;
    std::string error;
    fic::rollback::MutationId assigned = 0;
    require(harness.journal.prepareMutation(record, assigned, error),
            "prepare entry: " + error);
    require(harness.journal.setStatus(assigned, MutationStatus::Applied,
                                      error),
            "apply entry: " + error);
    return assigned;
}

fic::rollback::MutationId prepareFlagRecord(Harness& harness,
                                            const std::string& policy,
                                            const std::string& managedKey,
                                            bool appliedEnabled,
                                            std::vector<std::string> ids) {
    UndoRemovePamProviderManagedFlag undo;
    undo.policyName = policy;
    undo.providerName = kProvider;
    undo.configPath = harness.configPath.string();
    undo.managedKey = managedKey;
    undo.appliedEnabled = appliedEnabled;
    undo.suppressionIds = std::move(ids);
    undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", policy};
    record.resource = undo.configPath;
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = MutationStatus::Prepared;
    std::string error;
    fic::rollback::MutationId assigned = 0;
    require(harness.journal.prepareMutation(record, assigned, error),
            "prepare flag: " + error);
    require(harness.journal.setStatus(assigned, MutationStatus::Applied,
                                      error),
            "apply flag: " + error);
    return assigned;
}

void testOrphanWrapperRejects() {
    Harness harness;
    // Physical FIC suppression wrapper WITHOUT journal provenance (§68):
    // the preflight must fail closed and never leave orphan FIC
    // serialization behind a removed package.
    writeFile(harness.configPath,
              std::string(kForeign) +
                  pamProviderSuppressionWrapperLine(
                      kProvider, "failed_authentication_enforce_for_root",
                      "even_deny_root", 5, "s1", "even_deny_root") +
                  "\n");
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "orphan wrapper must fail the preflight closed");
    require(readFile(harness.configPath).find("FIC_PAM_SUPPRESS") !=
                std::string::npos,
            "orphan wrapper untouched by the failed preflight");
}

void testActiveFlagFalseRelease() {
    Harness harness;
    const char* flagPolicy = "failed_authentication_enforce_for_root";
    // Foreign state CONTAINS an active `even_deny_root` occurrence: the
    // FIC disable wraps that existing line, the release unwraps it back
    // byte-exact (§104 flag scenario).
    const std::string flagForeign =
        "# admin comment\ndeny = 3\neven_deny_root\n";
    const fic::rollback::MutationId id =
        prepareFlagRecord(harness, flagPolicy, "even_deny_root",
                          /*appliedEnabled=*/false, {"s1"});
    // Physical disabled-flag state produced by the SAME apply transition
    // the daemon uses: sentinel + wrapper carrying the assigned journal
    // mutation id over the existing foreign occurrence.
    PamProviderFlagSpec spec;
    spec.provider = kProvider;
    spec.policy = flagPolicy;
    spec.managedKey = "even_deny_root";
    spec.enabled = false;
    spec.mutationId = id;
    spec.createSuppressionIds = {"s1"};
    PamProviderFlagMutationResult fixture =
        setPamProviderManagedFlagTransition(flagForeign, spec,
                                            PamProviderBlockPlacementRequest::End);
    require(fixture.ok, "flag fixture: " + fixture.error);
    require(fixture.content.find("FIC_PAM_SUPPRESS") != std::string::npos,
            "fixture wrapped the foreign occurrence");
    writeFile(harness.configPath, fixture.content);

    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "flag release: " + error);
    require(readFile(harness.configPath) == flagForeign,
            "sentinel removed, wrappers unwrapped, foreign byte-exact");
    for (const MutationRecord& record : harness.journal.records()) {
        require(!record.isActive(), "flag record resolved");
    }
}

void testFicCreatedContainerDeleted() {
    Harness harness;
    // FIC-created primary (created absent by FIC): container provenance +
    // the last managed entry; the release must conditionally delete the
    // empty file and resolve the container provenance (§120).
    writeFile(harness.configPath, "");
    MutationRecord containerRecord;
    containerRecord.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER", kProvider};
    containerRecord.resource = harness.configPath.string();
    containerRecord.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoOwnPamProviderContainer{kProvider, harness.configPath.string()}};
    containerRecord.status = MutationStatus::Prepared;
    std::string error;
    fic::rollback::MutationId containerId = 0;
    require(harness.journal.prepareMutation(containerRecord, containerId,
                                            error),
            "prepare container: " + error);
    require(harness.journal.setStatus(containerId, MutationStatus::Applied,
                                      error),
            "apply container: " + error);

    const fic::rollback::MutationId entryId =
        prepareEntryRecordId(harness, kPolicy, kProvider, "deny", "8",
                             harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                     entryId, /*foreign=*/"");

    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "container release: " + error);
    require(!std::filesystem::exists(harness.configPath),
            "FIC-created empty container deleted");
    require(report.containersDeleted.size() == 1, "one container deleted");
    bool containerRolledBack = false;
    for (const MutationRecord& record : harness.journal.records()) {
        if (record.id == containerId) {
            containerRolledBack = record.status == MutationStatus::RolledBack;
        }
        require(!record.isActive(), "all provider records resolved");
    }
    require(containerRolledBack, "container provenance RolledBack");
}

void testPreExistingPrimaryRetained() {
    Harness harness;
    // No container provenance: the pre-existing primary is NEVER unlinked
    // (§40) even when the release removes the last FIC entry.
    const fic::rollback::MutationId entryId =
        prepareEntryRecordId(harness, kPolicy, kProvider, "deny", "8",
                             harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                     entryId, kForeign);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "release: " + error);
    require(std::filesystem::exists(harness.configPath),
            "pre-existing primary never deleted");
    require(readFile(harness.configPath) == kForeign,
            "only foreign configuration remains");
}

void testMultipleProviderFiles() {
    Harness harness;
    // Records across TWO provider primaries (faillock + pwquality): the
    // platform profile is the source of truth for the scanned primaries.
    const std::filesystem::path pwqPath =
        harness.temp.directory / "pwquality.conf";
    fic::platform::PamCapabilityConfig cap;
    cap.capability = fic::platform::PamCapability::PasswordQuality;
    cap.provider = fic::platform::PamProviderKind::PamPwquality;
    cap.configurationMode =
        fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile;
    cap.configPath = pwqPath;
    fic::platform::PamProviderConfigTopology topology;
    topology.primaryPath = pwqPath;
    cap.configTopology = topology;
    harness.platform.capabilities.push_back(cap);

    const fic::rollback::MutationId faillockId = prepareEntryRecordId(
        harness, kPolicy, kProvider, "deny", "8",
        harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                     faillockId, kForeign);
    const fic::rollback::MutationId pwqId =
        prepareEntryRecordId(harness, "password_min_length", "pam_pwquality",
                             "minlen", "12", pwqPath.string());
    renderEntryState(pwqPath, "pam_pwquality", "password_min_length",
                     "minlen", "12", pwqId, kForeign);

    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "multi-file release: " + error);
    require(report.releasedRecords.size() == 2, "both records released");
    require(readFile(harness.configPath) == kForeign,
            "faillock foreign-only");
    require(readFile(pwqPath) == kForeign, "pwquality foreign-only");
}

void testUnrelatedRecordUntouchedAndJournalValid() {
    Harness harness;
    applyEntryFixture(harness, 1, "8");
    prepareEntryRecord(harness, 1, "8");
    // An unrelated non-provider record (sysctl backend) must survive the
    // provider release untouched (§71) with the journal file loadable.
    MutationRecord unrelated;
    unrelated.policy = {"SYSCTL", "KERNEL", "kernel.some_setting"};
    unrelated.resource = "/proc/sys/kernel/some_setting";
    unrelated.undo = UndoAction{
        fic::rollback::MutationBackend::Sysctl,
        fic::rollback::UndoRemoveManagedSetting{"kernel.some_setting", "42"}};
    unrelated.status = MutationStatus::Prepared;
    std::string error;
    fic::rollback::MutationId unrelatedId = 0;
    require(harness.journal.prepareMutation(unrelated, unrelatedId, error),
            "prepare unrelated: " + error);
    require(harness.journal.setStatus(unrelatedId, MutationStatus::Applied,
                                      error),
            "apply unrelated: " + error);

    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "release: " + error);
    bool unrelatedStillActive = false;
    std::size_t resolvedProvider = 0;
    for (const MutationRecord& record : harness.journal.records()) {
        if (record.id == unrelatedId) {
            unrelatedStillActive = record.isActive();
        } else if (!record.isActive()) {
            ++resolvedProvider;
        }
    }
    require(unrelatedStillActive, "unrelated record untouched");
    require(resolvedProvider == 1, "provider record resolved");
    // The journal file remains valid/loadable with the resolved history
    // (§107): resolved records are never deleted.
    MutationJournal reloaded(harness.journalPath);
    require(reloaded.initializeOrLoad(error),
            "journal still loadable: " + error);
    require(reloaded.records().size() >= 2,
            "resolved history is preserved");
}

// ---------------------------------------------------------------------------
// Step 7F follow-up regressions.
// ---------------------------------------------------------------------------

// Production-like capability: ProviderConfigFile + configPath + configTopology
// = nullopt. The primary MUST participate in the orphan scan, the orphan
// wrapper scan and the final proof (the same SSOT list the release uses).
fic::rollback::MutationId prepareReleaseContainerRecord(
    Harness& harness, MutationStatus status) {
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER", kProvider};
    record.resource = harness.configPath.string();
    record.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoOwnPamProviderContainer{kProvider, harness.configPath.string()}};
    record.status = status;
    std::string error;
    fic::rollback::MutationId id = 0;
    require(harness.journal.prepareMutation(record, id, error),
            "container prepare: " + error);
    if (status != MutationStatus::Prepared) {
        require(harness.journal.setStatus(id, status, error),
                "container status: " + error);
    }
    return id;
}

// Crash between the durable conditional delete and the journal resolution:
// an APPLIED container provenance with an absent primary is recoverable.
// Stage A must pass read-only; Stage B completes the lifecycle.
void testCrashAfterContainerDeleteRecovers() {
    Harness harness;
    const fic::rollback::MutationId containerId =
        prepareReleaseContainerRecord(harness, MutationStatus::Applied);
    // The FIC-owned container was durably deleted; the journal resolution
    // never happened (simulated crash); then the process restarted.
    require(!std::filesystem::exists(harness.configPath),
            "fixture: primary absent after the crash");

    // Stage A: strictly read-only and must recognize the recoverable state.
    PamProviderPackageRelease stageA(harness.journal, harness.platform,
                                     harness.options());
    PamProviderPackageRelease::Report stageAReport;
    std::string error;
    require(stageA.run(PamProviderPackageRelease::Mode::Preflight,
                       stageAReport, error),
            "Stage A must accept the crash-after-delete state: " + error);
    require(!std::filesystem::exists(harness.configPath),
            "Stage A stays read-only");

    // Stage B: existing runtime recovery (durable absence proof + resolve
    // the container provenance as RolledBack).
    PamProviderPackageRelease stageB(harness.journal, harness.platform,
                                     harness.options());
    PamProviderPackageRelease::Report report;
    require(stageB.run(PamProviderPackageRelease::Mode::Release, report,
                       error),
            "Stage B must complete the crash recovery: " + error);
    require(report.containersDeleted.size() == 1,
            "the container record resolved as deleted");
    bool rolledBack = false;
    for (const MutationRecord& record : harness.journal.records()) {
        if (record.id == containerId) {
            rolledBack = record.status == MutationStatus::RolledBack;
        }
    }
    require(rolledBack, "container provenance must be RolledBack");
    require(!std::filesystem::exists(harness.configPath),
            "file remains absent");

    // Retry idempotence.
    PamProviderPackageRelease retry(harness.journal, harness.platform,
                                    harness.options());
    PamProviderPackageRelease::Report retryReport;
    require(retry.run(PamProviderPackageRelease::Mode::Release, retryReport,
                      error),
            "retry is idempotent: " + error);
    require(!std::filesystem::exists(harness.configPath),
            "still absent after the retry");
}

// A PREPARED container provenance with an absent primary proves nothing
// (no creation witness): Stage A keeps strict ownership semantics.
void testPreparedContainerAbsentFailsClosed() {
    Harness harness;
    prepareReleaseContainerRecord(harness, MutationStatus::Prepared);
    require(!std::filesystem::exists(harness.configPath),
            "fixture: primary absent");
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "ambiguous Prepared absent container must fail closed: " +
                error);
    require(error.find("not Applied") != std::string::npos,
            "rejection must name the non-Applied provenance: " + error);
}

void testProductionLikeTopologyParticipatesInScans() {
    // Orphan FIC entry in the primary must fail the preflight (orphan scan
    // really reads the primary even without capability.configTopology).
    {
        Harness harness(/*capabilityTopology=*/false);
        renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                         1, kForeign); // no journal provenance
        PamProviderPackageRelease release(harness.journal, harness.platform,
                                          harness.options());
        PamProviderPackageRelease::Report report;
        std::string error;
        require(!release.run(PamProviderPackageRelease::Mode::Preflight,
                             report, error),
                "production-like topology: orphan entry must be detected "
                "by the package preflight: " + error);
        require(error.find("orphan") != std::string::npos,
                "detection must come from the orphan scan: " + error);
    }
    // Orphan suppression wrapper likewise.
    {
        Harness harness(/*capabilityTopology=*/false);
        writeFile(harness.configPath,
                  std::string(kForeign) +
                      pamProviderSuppressionWrapperLine(
                          kProvider, "failed_authentication_enforce_for_root",
                          "even_deny_root", 5, "s1", "even_deny_root") +
                      "\n");
        PamProviderPackageRelease release(harness.journal, harness.platform,
                                          harness.options());
        PamProviderPackageRelease::Report report;
        std::string error;
        require(!release.run(PamProviderPackageRelease::Mode::Preflight,
                             report, error),
                "production-like topology: orphan wrapper must be detected "
                "by the package preflight: " + error);
    }
    // A fully journaled release through the production-like profile: the
    // final proof reads the same primary (no FIC serialization may remain
    // and the release must succeed end-to-end).
    {
        Harness harness(/*capabilityTopology=*/false);
        const fic::rollback::MutationId id = prepareEntryRecordId(
            harness, kPolicy, kProvider, "deny", "8",
            harness.configPath.string());
        renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                         id, kForeign);
        PamProviderPackageRelease release(harness.journal, harness.platform,
                                          harness.options());
        PamProviderPackageRelease::Report report;
        std::string error;
        require(release.run(PamProviderPackageRelease::Mode::Release, report,
                            error),
                "production-like topology release: " + error);
        require(readFile(harness.configPath) == kForeign,
                "final proof really validated the primary: foreign-only");
    }
}

// Stage A must be a strict releasability proof: drifted states FAIL before
// any writer is stopped; no config/journal mutation happens.
void testStageARejectsAppliedDrifted() {
    Harness harness;
    applyEntryFixture(harness, 1, "8");
    prepareEntryRecord(harness, 1, "8");
    // Physical drift: the managed value was externally rewritten.
    {
        PamProviderEntrySpec spec;
        spec.provider = kProvider;
        spec.policy = kPolicy;
        spec.managedKey = "deny";
        spec.value = "99";
        spec.mutationId = 1;
        PamProviderMutationResult result = setPamProviderManagedEntry(
            readFile(harness.configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(result.ok, "drift fixture: " + result.error);
        writeFile(harness.configPath, result.content);
    }
    const std::string configBefore = readFile(harness.configPath);
    const std::string journalBefore = readFile(harness.journalPath);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "Stage A must reject AppliedDrifted: " + error);
    require(error.find("non-releasable") != std::string::npos,
            "rejection must name the binding state: " + error);
    require(readFile(harness.configPath) == configBefore,
            "config untouched by the failed Stage A");
    require(readFile(harness.journalPath) == journalBefore,
            "journal untouched by the failed Stage A");
}

void testStageARejectsPreparedConflict() {
    Harness harness;
    // Legit journal path to a Prepared UPDATE transition: fresh Applied
    // record (deny=5), then a refresh carrying that body as previous and
    // deny=8 as target. The refresh persists as Prepared.
    applyEntryFixture(harness, 1, "5");
    prepareEntryRecord(harness, 1, "5");
    {
        UndoRemovePamProviderManagedEntry undo;
        undo.policyName = kPolicy;
        undo.providerName = kProvider;
        undo.configPath = harness.configPath.string();
        undo.managedKey = "deny";
        undo.appliedBody = pamProviderEntryBody("deny", "8");
        undo.previousAppliedBody = pamProviderEntryBody("deny", "5");
        undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
        MutationRecord record;
        record.policy = {"IDENTITY_ACCESS", "PAM", kPolicy};
        record.resource = undo.configPath;
        record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
        record.status = MutationStatus::Prepared;
        std::string error;
        fic::rollback::MutationId assigned = 0;
        require(harness.journal.prepareMutation(record, assigned, error),
                "prepare update: " + error);
    }
    // Physical drift: the FIC-owned entry (same mutation id) carries a body
    // that is NEITHER the target nor the previous body -> PreparedConflict.
    std::string config = readFile(harness.configPath);
    const std::string previousBody = pamProviderEntryBody("deny", "5");
    const std::string driftedBody = pamProviderEntryBody("deny", "77");
    const std::size_t pos = config.find(previousBody);
    require(pos != std::string::npos, "previous body present in fixture");
    config.replace(pos, previousBody.size(), driftedBody);
    writeFile(harness.configPath, config);
    const std::string configBefore = readFile(harness.configPath);
    const std::string journalBefore = readFile(harness.journalPath);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "Stage A must reject PreparedConflict: " + error);
    require(error.find("non-releasable") != std::string::npos,
            "rejection must name the binding state: " + error);
    require(readFile(harness.configPath) == configBefore,
            "config untouched by the failed Stage A");
    require(readFile(harness.journalPath) == journalBefore,
            "journal untouched by the failed Stage A");
}

void testStageAPassesAppliedMissingAndPreparedFreshAbsent() {
    // Applied + physical entry externally released: releasable no-op.
    {
        Harness harness;
        prepareEntryRecord(harness, 1, "8");
        writeFile(harness.configPath, kForeign);
        PamProviderPackageRelease release(harness.journal, harness.platform,
                                          harness.options());
        PamProviderPackageRelease::Report report;
        std::string error;
        require(release.run(PamProviderPackageRelease::Mode::Preflight,
                            report, error),
                "Stage A must accept AppliedMissing: " + error);
    }
    // Prepared fresh + physical entry absent: releasable.
    {
        Harness harness;
        UndoRemovePamProviderManagedEntry undo;
        undo.policyName = kPolicy;
        undo.providerName = kProvider;
        undo.configPath = harness.configPath.string();
        undo.managedKey = "deny";
        undo.appliedBody = pamProviderEntryBody("deny", "8");
        undo.placement =
            fic::rollback::PamProviderBlockPlacementContract::End;
        MutationRecord record;
        record.policy = {"IDENTITY_ACCESS", "PAM", kPolicy};
        record.resource = undo.configPath;
        record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
        record.status = MutationStatus::Prepared;
        std::string error;
        fic::rollback::MutationId assigned = 0;
        require(harness.journal.prepareMutation(record, assigned, error),
                "prepare fresh: " + error);
        writeFile(harness.configPath, kForeign);
        PamProviderPackageRelease release(harness.journal, harness.platform,
                                          harness.options());
        PamProviderPackageRelease::Report report;
        require(release.run(PamProviderPackageRelease::Mode::Preflight,
                            report, error),
                "Stage A must accept PreparedFreshAbsent: " + error);
    }
}

// ---------------------------------------------------------------------------
// Step 7F final security follow-up: exact orphan-coverage regressions.
// ---------------------------------------------------------------------------

// A same-policy entry with a DIFFERENT managed key is an orphan: the weak
// (path, policy) coverage model is gone — coverage requires the exact
// (path, provider, policy, managedKey) journal identity.
void testWrongKeyOrphanSamePolicyRejected() {
    Harness harness;
    const fic::rollback::MutationId id = prepareEntryRecordId(
        harness, kPolicy, kProvider, "deny", "8",
        harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8", id,
                     kForeign);
    // Wrong-key FIC entry of the SAME policy with its own (fabricated)
    // mutation id: no exact journal record covers it — the weak
    // (path, policy) model would have covered it, the exact model does not.
    {
        PamProviderEntrySpec spec;
        spec.provider = kProvider;
        spec.policy = kPolicy;
        spec.managedKey = "fail_interval";
        spec.value = "999";
        spec.mutationId = id + 7;
        PamProviderMutationResult result = setPamProviderManagedEntry(
            readFile(harness.configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(result.ok, "wrong-key fixture: " + result.error);
        writeFile(harness.configPath, result.content);
    }
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "wrong-key same-policy orphan must fail the preflight closed: " +
                error);
    require(error.find("orphan") != std::string::npos,
            "rejection must come from the exact orphan scan: " + error);
}

// A wrong mutation id on the physical entry is drift: the exact journal
// record does not confirm the physical state (fail closed).
void testWrongMutationIdEntryRejected() {
    Harness harness;
    const fic::rollback::MutationId id = prepareEntryRecordId(
        harness, kPolicy, kProvider, "deny", "8",
        harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                     id + 1, kForeign);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "wrong mutation id must fail the preflight closed: " + error);
}


// A suppression wrapper whose (policy, managedKey) identity matches no flag
// record is an orphan even when another record of the same policy exists.
void testWrongKeyOrphanWrapperSamePolicyRejected() {
    Harness harness;
    const fic::rollback::MutationId id = prepareEntryRecordId(
        harness, kPolicy, kProvider, "deny", "8",
        harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8", id,
                     kForeign);
    writeFile(harness.configPath,
              readFile(harness.configPath) +
                  pamProviderSuppressionWrapperLine(
                      kProvider, kPolicy, "even_deny_root", id, "s9",
                      "even_deny_root") +
                  "\n");
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "wrong-key suppression wrapper must fail the preflight closed: " +
                error);
    require(error.find("suppression wrapper") != std::string::npos,
            "rejection must name the wrapper orphan: " + error);
}

} // namespace

// A PREPARED flag record owns BOTH durable sides: the previous-side
// suppression wrapper (previousSuppressionIds) is journal-covered through
// the single status-aware authority model.
void testPreparedPreviousWrapperAuthorityAccepted() {
    Harness harness;
    const char* flagPolicy = "failed_authentication_enforce_for_root";
    const std::string flagForeign =
        "# admin comment\ndeny = 3\neven_deny_root\n";
    // Prepared transition: previous disabled (wrapper s2) -> target enabled.
    UndoRemovePamProviderManagedFlag undo;
    undo.policyName = flagPolicy;
    undo.providerName = kProvider;
    undo.configPath = harness.configPath.string();
    undo.managedKey = "even_deny_root";
    undo.appliedEnabled = true;
    undo.previousAppliedEnabled = false;
    undo.previousSuppressionIds = {"s2"};
    undo.placement = fic::rollback::PamProviderBlockPlacementContract::End;
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", flagPolicy};
    record.resource = undo.configPath;
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, undo};
    record.status = MutationStatus::Prepared;
    std::string error;
    fic::rollback::MutationId assigned = 0;
    require(harness.journal.prepareMutation(record, assigned, error),
            "prepare prepared-flag: " + error);
    // Physical state: the previous (disabled) side with wrapper s2.
    PamProviderFlagSpec spec;
    spec.provider = kProvider;
    spec.policy = flagPolicy;
    spec.managedKey = "even_deny_root";
    spec.enabled = false;
    spec.mutationId = assigned;
    spec.createSuppressionIds = {"s2"};
    PamProviderFlagMutationResult fixture = setPamProviderManagedFlagTransition(
        flagForeign, spec, PamProviderBlockPlacementRequest::End);
    require(fixture.ok, "prepared previous fixture: " + fixture.error);
    writeFile(harness.configPath, fixture.content);

    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    require(release.run(PamProviderPackageRelease::Mode::Preflight, report,
                        error),
            "prepared previous-side wrapper must be journal-covered: " +
                error);
}

// An independent active container of another provider is still processed by
// the final sweep (the stricter re-enumeration never orphans live records).
void testIndependentActiveContainerStillProcessed() {
    Harness harness;
    const std::filesystem::path pwqPath =
        harness.temp.directory / "pwquality.conf";
    PamCapabilityConfig cap;
    cap.capability = fic::platform::PamCapability::PasswordQuality;
    cap.provider = fic::platform::PamProviderKind::PamPwquality;
    cap.configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    cap.configPath = pwqPath;
    fic::platform::PamProviderConfigTopology topology;
    topology.primaryPath = pwqPath;
    cap.configTopology = topology;
    harness.platform.capabilities.push_back(cap);

    // faillock: FIC-created container + last entry (deleted on release).
    writeFile(harness.configPath, "");
    const fic::rollback::MutationId faillockContainer =
        prepareReleaseContainerRecord(harness, MutationStatus::Applied);
    (void)faillockContainer;
    const fic::rollback::MutationId faillockEntry = prepareEntryRecordId(
        harness, kPolicy, kProvider, "deny", "8",
        harness.configPath.string());
    renderEntryState(harness.configPath, kProvider, kPolicy, "deny", "8",
                     faillockEntry, "");
    // pwquality: an independent FIC-created container + last entry.
    writeFile(pwqPath, "");
    MutationRecord pwqContainer;
    pwqContainer.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER",
                           "pam_pwquality"};
    pwqContainer.resource = pwqPath.string();
    pwqContainer.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoOwnPamProviderContainer{"pam_pwquality", pwqPath.string()}};
    pwqContainer.status = MutationStatus::Prepared;
    std::string error;
    fic::rollback::MutationId pwqContainerId = 0;
    require(harness.journal.prepareMutation(pwqContainer, pwqContainerId,
                                            error),
            "prepare pwq container: " + error);
    require(harness.journal.setStatus(pwqContainerId, MutationStatus::Applied,
                                      error),
            "apply pwq container: " + error);
    const fic::rollback::MutationId pwqEntry = prepareEntryRecordId(
        harness, "password_min_length", "pam_pwquality", "minlen", "12",
        pwqPath.string());
    renderEntryState(pwqPath, "pam_pwquality", "password_min_length", "minlen",
                     "12", pwqEntry, "");

    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "independent container release: " + error);
    require(report.containersDeleted.size() == 2,
            "both independent containers deleted");
    require(!std::filesystem::exists(harness.configPath) &&
                !std::filesystem::exists(pwqPath),
            "both FIC-created primaries deleted");
    for (const MutationRecord& record : harness.journal.records()) {
        require(!record.isActive(), "all provider records resolved");
    }
}

// Step 7F security follow-up: a canonical FIC provider block with ZERO
// entries (BEGIN/END only, no wrappers) has no possible journal provenance.
// Stage A must fail closed read-only; Stage B must refuse through its fresh
// preflight without any config/journal mutation.
void testEmptyOrphanProviderBlockRejectedAtPreflight() {
    Harness harness(/*capabilityTopology=*/false);
    std::string emptyBlock;
    emptyBlock += kPamProviderBlockBeginMarkerPrefix;
    emptyBlock += kProvider;
    emptyBlock += kPamProviderBlockLeadField;
    emptyBlock += kPamProviderBlockLeadNone;
    emptyBlock += "\n";
    emptyBlock += kPamProviderBlockEndMarker;
    emptyBlock += "\n";
    writeFile(harness.configPath, emptyBlock);
    const std::string configBefore = readFile(harness.configPath);
    const std::string journalBefore = readFile(harness.journalPath);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "orphan empty FIC provider block must fail Stage A closed: " +
                error);
    // The Step 7A strict grammar itself fails closed on an empty canonical
    // block ("пустой FIC PAM provider block"); the package preflight
    // empty-block check is defense-in-depth for that contract. Either way
    // Stage A must refuse and name the empty FIC provider block.
    require(error.find("provider block") != std::string::npos,
            "Stage A must name the empty FIC provider block: " + error);
    require(readFile(harness.configPath) == configBefore,
            "Stage A must not repair the empty provider block");
    require(readFile(harness.journalPath) == journalBefore,
            "Stage A must not touch the journal");
    require(!release.run(PamProviderPackageRelease::Mode::Release, report,
                         error),
            "Stage B re-runs the Stage A proof and must refuse: " + error);
    require(readFile(harness.configPath) == configBefore,
            "Stage B must not mutate the config");
    require(readFile(harness.journalPath) == journalBefore,
            "Stage B must not mutate the journal");
}

// ALT passwdqc primary participates in package scan: malformed reserved
// markers fail preflight without writes, while clean foreign files survive.
void testManagedAltPasswdqcPathScanned() {
    Harness harness;
    harness.platform.capabilities.clear();
    PamCapabilityConfig faillock;
    faillock.provider = fic::platform::PamProviderKind::PamFaillock;
    faillock.configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    faillock.configPath = harness.configPath;
    faillock.topology = fic::platform::PamTopologyStrategyKind::AltTcbManaged;
    harness.platform.capabilities.push_back(faillock);
    const std::filesystem::path passwdqcPath =
        harness.temp.directory / "passwdqc.conf";
    PamCapabilityConfig passwdqc;
    passwdqc.provider = fic::platform::PamProviderKind::PamPasswdqc;
    passwdqc.configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    passwdqc.configPath = passwdqcPath;
    passwdqc.topology =
        fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
    harness.platform.capabilities.push_back(passwdqc);
    writeFile(harness.configPath, kForeign);
    // Non-canonical reserved-namespace bytes: the trusted provider parser
    // fails closed if this file is EVER treated as a provider primary.
    const std::string foreignPasswdqc =
        "# admin\nqc_minlen = 8\n# FIC_PAM_SUSPICIOUS foreign comment\n";
    writeFile(passwdqcPath, foreignPasswdqc);
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Preflight, report,
                         error),
            "malformed passwdqc managed namespace must refuse package release");
    require(readFile(passwdqcPath) == foreignPasswdqc, "preflight changed passwdqc");
    writeFile(passwdqcPath, "# admin\nmatch=2\n");
    require(release.run(PamProviderPackageRelease::Mode::Release, report,
                        error),
            "clean ALT-shaped release including passwdqc: " +
                error);
    require(!report.changedSystemState, "release mutates nothing");
    require(readFile(passwdqcPath) == "# admin\nmatch=2\n",
            "clean passwdqc.conf stays byte-identical");
    require(readFile(harness.configPath) == kForeign,
            "managed faillock primary stays byte-identical");
}

int main() {
    try {
        testCleanNoop();
        testPreflightDoesNotMutate();
        testActiveAssignmentRelease();
        testOrphanBlockRejects();
        testPartialReleaseAndRetry();
        testOrphanWrapperRejects();
        testActiveFlagFalseRelease();
        testFicCreatedContainerDeleted();
        testPreExistingPrimaryRetained();
        testMultipleProviderFiles();
        testUnrelatedRecordUntouchedAndJournalValid();
        testProductionLikeTopologyParticipatesInScans();
        testStageARejectsAppliedDrifted();
        testStageARejectsPreparedConflict();
        testStageAPassesAppliedMissingAndPreparedFreshAbsent();
        testCrashAfterContainerDeleteRecovers();
        testPreparedContainerAbsentFailsClosed();
        testWrongKeyOrphanSamePolicyRejected();
        testWrongMutationIdEntryRejected();
        testWrongKeyOrphanWrapperSamePolicyRejected();
        testPreparedPreviousWrapperAuthorityAccepted();
        testIndependentActiveContainerStillProcessed();
        testEmptyOrphanProviderBlockRejectedAtPreflight();
        testManagedAltPasswdqcPathScanned();
    } catch (const std::exception& error) {
        std::cerr << "PamProviderPackageReleaseTests failed: " << error.what()
                  << '\n';
        return 1;
    }
    std::cout << "PamProviderPackageReleaseTests passed\n";
    return 0;
}
