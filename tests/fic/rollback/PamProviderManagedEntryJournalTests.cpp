#include "rollback/MutationJournal.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "rollback/MutationRecord.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

namespace {

using namespace fic::rollback;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempJournal {
public:
    TempJournal() {
        char pattern[] = "/tmp/fic-pam-provider-journal-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        directory = created;
        path = directory / "mutations.json";
    }

    ~TempJournal() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }

    std::filesystem::path directory;
    std::filesystem::path path;
};

UndoRemovePamProviderManagedEntry validPayload() {
    UndoRemovePamProviderManagedEntry payload;
    payload.policyName = "failed_authentication_attempts";
    payload.providerName = "pam_faillock";
    payload.configPath = "/etc/security/faillock.conf";
    payload.managedKey = "deny";
    payload.appliedBody = "deny = 5";
    payload.placement = PamProviderBlockPlacementContract::End;
    return payload;
}

MutationRecord recordWithPayload(
    const UndoRemovePamProviderManagedEntry& payload) {
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", payload.policyName};
    record.resource = payload.configPath;
    record.undo = UndoAction{MutationBackend::Pam, payload};
    return record;
}

std::string journalDocument(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void testRoundTrip() {
    TempJournal temp;
    MutationJournal writer(temp.path);
    std::string error;
    require(writer.load(error), error);
    MutationId id = 0;
    auto payload = validPayload();
    payload.placement = PamProviderBlockPlacementContract::Beginning;
    require(writer.prepareMutation(recordWithPayload(payload), id, error),
            error);
    require(id != 0, "journal must allocate a non-zero mutation id");
    require(writer.setStatus(id, MutationStatus::Applied, error), error);
    // The physical primitive writes exactly this marker with the SAME id:
    // one persistent transaction identity binds journal and physical entry.
    const std::string physicalMarker =
        pamProviderEntryBeginMarker(payload.policyName, id);
    require(!physicalMarker.empty(), "physical marker must be derivable");

    MutationJournal reader(temp.path);
    require(reader.load(error), error);
    const auto records = reader.activeRecords(
        {"IDENTITY_ACCESS", "PAM", payload.policyName});
    require(records.size() == 1, "record not round-tripped");
    require(records.front().id == id, "record id mismatch");
    require(records.front().status == MutationStatus::Applied,
            "record status mismatch");
    const auto* restored = std::get_if<UndoRemovePamProviderManagedEntry>(
        &records.front().undo.payload);
    require(restored != nullptr, "payload type not restored");
    require(restored->policyName == payload.policyName &&
                restored->providerName == payload.providerName &&
                restored->configPath == payload.configPath &&
                restored->managedKey == payload.managedKey &&
                restored->appliedBody == payload.appliedBody &&
                restored->previousAppliedBody.empty() &&
                restored->placement ==
                    PamProviderBlockPlacementContract::Beginning,
            "payload fields not restored byte-equal");
    require(undoActionTypeName(records.front().undo) ==
                "remove_pam_provider_managed_entry",
            "action type name wrong");
    require(journalDocument(temp.path).find(
                "remove_pam_provider_managed_entry") != std::string::npos,
            "self-describing action name missing from the document");
}

void testPrepareValidation() {
    TempJournal temp;
    MutationJournal journal(temp.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;

    // Identity consistency: resource must be the config path, policy name
    // must match the payload, module/submodule must be identity/PAM.
    {
        auto payload = validPayload();
        auto record = recordWithPayload(payload);
        record.policy.policyName = "another_policy";
        require(!journal.prepareMutation(record, id, error),
                "policy identity mismatch accepted");
        record = recordWithPayload(payload);
        record.resource = "/etc/security/pwquality.conf";
        require(!journal.prepareMutation(record, id, error),
                "resource mismatch accepted");
    }
    // Invalid payload fields are rejected on the write path.
    {
        auto payload = validPayload();
        payload.managedKey = "deny!";
        require(!journal.prepareMutation(recordWithPayload(payload), id,
                                         error),
                "invalid managed key accepted");
    }
    {
        auto payload = validPayload();
        payload.appliedBody = "deny=5";
        require(!journal.prepareMutation(recordWithPayload(payload), id,
                                         error),
                "non-canonical applied body accepted");
    }
    {
        auto payload = validPayload();
        payload.providerName = "Pam Faillock";
        require(!journal.prepareMutation(recordWithPayload(payload), id,
                                         error),
                "invalid provider token accepted");
    }
    {
        auto payload = validPayload();
        payload.configPath = "etc/security/faillock.conf";
        require(!journal.prepareMutation(recordWithPayload(payload), id,
                                         error),
                "relative config path accepted");
    }
    // The valid payload is accepted.
    {
        auto payload = validPayload();
        require(journal.prepareMutation(recordWithPayload(payload), id,
                                        error),
                error);
        require(id != 0, "valid payload must allocate a record id");
    }
}

void testPamCapabilityPayloadUnchanged() {
    // Regression: the existing disable_pam_capability Pam payload path
    // keeps its identity validation after the Pam-branch extension.
    TempJournal temp;
    MutationJournal journal(temp.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM",
                     "enable_authentication_lockout"};
    record.resource = "capability/enable_authentication_lockout";
    UndoDisablePamCapability payload;
    payload.capability = "enable_authentication_lockout";
    payload.topology = PamTopologyKind::PamAuthUpdate;
    payload.activationIdentifiers = {"fic-faillock-auth"};
    record.undo = UndoAction{MutationBackend::Pam, payload};
    require(journal.prepareMutation(record, id, error), error);
}

void testRefreshTransitions() {
    TempJournal temp;
    MutationJournal journal(temp.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;

    // (a) A fresh record must NOT claim a previous applied body.
    {
        auto payload = validPayload();
        payload.previousAppliedBody = "deny = 3";
        require(!journal.prepareMutation(recordWithPayload(payload), id,
                                         error),
                "fresh record claiming a previous body accepted");
    }
    // (b) Fresh create -> Applied.
    require(journal.prepareMutation(recordWithPayload(validPayload()), id,
                                    error),
            error);
    const MutationId freshId = id;
    require(journal.setStatus(freshId, MutationStatus::Applied, error),
            error);

    // (c) Applied refresh MUST carry the currently owned body as the
    // previous state and keeps the SAME record id (no new mutation id).
    {
        auto refresh = validPayload();
        refresh.appliedBody = "deny = 9";
        refresh.previousAppliedBody = "deny = 5";
        require(journal.prepareMutation(recordWithPayload(refresh), id,
                                        error),
                error);
        require(id == freshId,
                "in-place refresh must not allocate a new mutation id");
        require(journal.activeRecords(
                    {"IDENTITY_ACCESS", "PAM", refresh.policyName})
                        .front()
                        .status == MutationStatus::Prepared,
                "refresh must re-arm the record as Prepared");
    }
    // (d) An unresolved Prepared transition must not be silently replaced
    // by a different transition (provenance loss).
    {
        auto conflicting = validPayload();
        conflicting.appliedBody = "deny = 11";
        conflicting.previousAppliedBody = "deny = 7";
        require(!journal.prepareMutation(recordWithPayload(conflicting), id,
                                         error),
                "conflicting Prepared refresh accepted");
    }
    // (e) Deterministic re-refresh of the SAME unresolved transition is
    // idempotent: same payload, same id.
    {
        auto same = validPayload();
        same.appliedBody = "deny = 9";
        same.previousAppliedBody = "deny = 5";
        require(journal.prepareMutation(recordWithPayload(same), id, error),
                error);
        require(id == freshId, "idempotent re-prepare changed the record id");
    }
    // (f) Reload: the durable previous->target transition survives.
    MutationJournal reader(temp.path);
    require(reader.load(error), error);
    const auto records = reader.activeRecords(
        {"IDENTITY_ACCESS", "PAM", validPayload().policyName});
    require(records.size() == 1, "refresh produced extra records");
    const auto* restored = std::get_if<UndoRemovePamProviderManagedEntry>(
        &records.front().undo.payload);
    require(restored != nullptr && restored->appliedBody == "deny = 9" &&
                restored->previousAppliedBody == "deny = 5",
            "previous->target transition not restored byte-equal");
}

UndoOwnPamProviderContainer containerPayload() {
    UndoOwnPamProviderContainer payload;
    payload.providerName = "pam_faillock";
    payload.configPath = "/etc/security/faillock.conf";
    return payload;
}

MutationRecord containerRecord(const UndoOwnPamProviderContainer& payload) {
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM_CONTAINER",
                     payload.providerName};
    record.resource = payload.configPath;
    record.undo = UndoAction{MutationBackend::Pam, payload};
    return record;
}

void testContainerProvenance() {
    TempJournal temp;
    MutationJournal journal(temp.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;

    // (a) Invalid provenance payloads are rejected on the write path.
    {
        UndoOwnPamProviderContainer bad = containerPayload();
        bad.providerName = "Pam Faillock";
        require(!journal.prepareMutation(containerRecord(bad), id, error),
                "invalid provider token accepted for container provenance");
    }
    {
        UndoOwnPamProviderContainer bad = containerPayload();
        bad.configPath = "etc/security/faillock.conf";
        require(!journal.prepareMutation(containerRecord(bad), id, error),
                "relative config path accepted for container provenance");
    }
    // (b) Identity consistency: the dedicated PAM_CONTAINER submodule.
    {
        MutationRecord record = containerRecord(containerPayload());
        record.policy.submoduleName = "PAM";
        require(!journal.prepareMutation(record, id, error),
                "container provenance under the PAM submodule accepted");
    }
    // (c) Valid provenance round-trips with its own identity.
    require(journal.prepareMutation(containerRecord(containerPayload()), id,
                                    error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);
    // (d) Applied provenance must not be re-Prepared.
    require(!journal.prepareMutation(containerRecord(containerPayload()), id,
                                     error),
            "Applied container provenance re-Prepared");
    // (e) A second provider claiming the same physical file is refused.
    {
        UndoOwnPamProviderContainer second = containerPayload();
        second.providerName = "pam_pwquality";
        require(!journal.prepareMutation(containerRecord(second), id, error),
                "second container provenance for the same file accepted");
    }
    // (f) Container provenance is independent of the entry record
    // lifecycle: the entry record for the same config path still
    // round-trips and is a distinct identity.
    require(journal.prepareMutation(recordWithPayload(validPayload()), id,
                                    error),
            error);
    MutationJournal reader(temp.path);
    require(reader.load(error), error);
    const auto containerRecords = reader.activeRecords(
        {"IDENTITY_ACCESS", "PAM_CONTAINER",
         containerPayload().providerName});
    require(containerRecords.size() == 1 &&
                containerRecords.front().status == MutationStatus::Applied,
            "container provenance record not restored");
    const auto* restored = std::get_if<UndoOwnPamProviderContainer>(
        &containerRecords.front().undo.payload);
    require(restored != nullptr &&
                restored->providerName == containerPayload().providerName &&
                restored->configPath == containerPayload().configPath,
            "container provenance payload not restored byte-equal");
    require(undoActionTypeName(containerRecords.front().undo) ==
                "own_pam_provider_container",
            "container action type name wrong");
    require(journalDocument(temp.path).find("own_pam_provider_container") !=
                std::string::npos,
            "self-describing container action name missing");
    const auto entryRecords = reader.activeRecords(
        {"IDENTITY_ACCESS", "PAM", validPayload().policyName});
    require(entryRecords.size() == 1,
            "entry record must coexist with container provenance");
}



} // namespace

int main() {
    try {
        testRoundTrip();
        testPrepareValidation();
        testPamCapabilityPayloadUnchanged();
        testRefreshTransitions();
        testContainerProvenance();
    } catch (const std::exception& error) {
        std::cerr << "PamProviderManagedEntryJournalTests failed: "
                  << error.what() << '\n';
        return 1;
    }
    std::cout << "PamProviderManagedEntryJournalTests passed\n";
    return 0;
}
