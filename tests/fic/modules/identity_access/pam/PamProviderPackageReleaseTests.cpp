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

    Harness() {
        std::string error;
        require(journal.initializeOrLoad(error), "journal init: " + error);
        PamCapabilityConfig capability;
        capability.provider = fic::platform::PamProviderKind::PamFaillock;
        capability.configurationMode =
            PamCapabilityConfigurationMode::ProviderConfigFile;
        capability.configPath = configPath;
        fic::platform::PamProviderConfigTopology topology;
        topology.primaryPath = configPath;
        capability.configTopology = topology;
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
    PamProviderPackageRelease release(harness.journal, harness.platform,
                                      harness.options());
    PamProviderPackageRelease::Report report;
    std::string error;
    require(!release.run(PamProviderPackageRelease::Mode::Release, report,
                         error),
            "drifted second record blocks the removal");
    require(!report.releasedRecords.empty(),
            "partial release is monotonic (first record already released)");
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

} // namespace

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
    } catch (const std::exception& error) {
        std::cerr << "PamProviderPackageReleaseTests failed: " << error.what()
                  << '\n';
        return 1;
    }
    std::cout << "PamProviderPackageReleaseTests passed\n";
    return 0;
}
