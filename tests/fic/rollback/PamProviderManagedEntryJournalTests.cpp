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
    payload.containerCreated = false;
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
    payload.containerCreated = true;
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
                restored->containerCreated &&
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



} // namespace

int main() {
    try {
        testRoundTrip();
        testPrepareValidation();
        testPamCapabilityPayloadUnchanged();
    } catch (const std::exception& error) {
        std::cerr << "PamProviderManagedEntryJournalTests failed: "
                  << error.what() << '\n';
        return 1;
    }
    std::cout << "PamProviderManagedEntryJournalTests passed\n";
    return 0;
}
