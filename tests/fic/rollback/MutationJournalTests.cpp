#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace fic::rollback;

class TempFile {
public:
    TempFile() {
        std::string pattern = "/tmp/fic-mutation-journal-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        directory = created;
        path = directory / "mutations.json";
    }

    ~TempFile() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }

    std::string read() const {
        std::ifstream stream(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(stream),
                           std::istreambuf_iterator<char>());
    }

    void write(const std::string& content) const {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        if (!stream.is_open()) {
            throw std::runtime_error("could not write " + path.string());
        }
        stream << content;
        if (!stream.good()) {
            throw std::runtime_error("failed to write " + path.string());
        }
    }

    std::filesystem::path directory;
    std::filesystem::path path;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

PolicyRef sysctlPolicy() {
    return PolicyRef{"SYSCTL", "Global", "kernel_test_policy"};
}

UndoAction sysctlUndo(const std::string& value = "10") {
    return UndoAction{MutationBackend::Sysctl,
                      UndoRemoveManagedSetting{"vm.swappiness", value}};
}

MutationRecord preparedRecord(const PolicyRef& policy) {
    MutationRecord record;
    record.policy = policy;
    record.resource = "vm.swappiness";
    record.undo = sysctlUndo();
    return record;
}

// Structural comparison of in-memory records (MutationRecord has no
// operator==): enough to prove that a failed reload did not replace the
// previous in-memory state.
bool sameRecords(const std::vector<MutationRecord>& a,
                 const std::vector<MutationRecord>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t index = 0; index < a.size(); ++index) {
        if (a[index].id != b[index].id ||
            a[index].resource != b[index].resource ||
            a[index].status != b[index].status ||
            a[index].error != b[index].error ||
            a[index].createdAtEpoch != b[index].createdAtEpoch ||
            a[index].updatedAtEpoch != b[index].updatedAtEpoch) {
            return false;
        }
    }
    return true;
}

void testMissingFileIsEmptyJournal() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(), "missing journal must be empty");
    require(journal.loaded(), "bootstrap missing journal must be loaded");
    require(journal.health() == JournalHealth::Healthy,
            "bootstrap missing journal must be healthy");
    require(journal.usable(),
            "bootstrap missing journal must be operationally usable");
}

void testPrepareCommitAndReloadPersistence() {
    TempFile file;
    MutationId id = 0;
    {
        MutationJournal journal(file.path);
        std::string error;
        require(journal.load(error), error);
        require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
                error);
        require(journal.setStatus(id, MutationStatus::Applied, error), error);
    }
    MutationJournal reloaded(file.path);
    std::string error;
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1, "record must survive reload");
    const MutationRecord& record = reloaded.records().front();
    require(record.id == id, "record id must be preserved");
    require(record.status == MutationStatus::Applied,
            "committed status must survive reload");
    require(record.policy == sysctlPolicy(), "policy must survive reload");
    require(record.isActive(), "applied record must be active");
}

void testPrepareIsIdempotentForSameTriple() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);

    MutationId firstId = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), firstId, error),
            error);
    MutationRecord repeated = preparedRecord(sysctlPolicy());
    repeated.undo = sysctlUndo("42");
    MutationId secondId = 0;
    require(journal.prepareMutation(std::move(repeated), secondId, error), error);
    require(firstId == secondId,
            "repeated prepare for the same (policy, backend, resource) triple "
            "must refresh the existing record instead of duplicating it");
    require(journal.records().size() == 1,
            "idempotent prepare must not duplicate records");
    const MutationRecord& record = journal.records().front();
    require(record.status == MutationStatus::Prepared,
            "refreshed record must be back in Prepared state");
    const auto* payload =
        std::get_if<UndoRemoveManagedSetting>(&record.undo.payload);
    require(payload != nullptr && payload->appliedValue == "42",
            "refreshed record must carry the new undo payload");
}

void testDiscardRemovesRecord() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.discard(id, error), error);
    require(journal.records().empty(), "discarded record must be removed");

    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().empty(),
            "discard must be persisted to disk");
}

// Makes every later persist() fail while keeping the previous journal file
// intact: the parent directory becomes read-only, so the atomic writer
// cannot create its temp file next to the target.
void breakPersist(const TempFile& file) {
    std::error_code ec;
    std::filesystem::permissions(
        file.directory,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec,
        ec);
    require(!ec, "breakPersist: could not restrict the journal directory");
}

void restorePersist(const TempFile& file) {
    std::error_code ec;
    std::filesystem::permissions(file.directory,
                                 std::filesystem::perms::owner_all, ec);
    require(!ec, "restorePersist: could not restore the journal directory");
}

void testSetStatusPersistFailureRestoresRecord() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);

    breakPersist(file);
    require(!journal.setStatus(id, MutationStatus::RolledBack, error),
            "persist failure must be reported to the caller");
    require(!error.empty(), "persist failure must produce an error message");

    // Strong in-memory consistency: the record is still logically Applied,
    // so a repeated operation still sees the original active mutation.
    require(journal.records().size() == 1,
            "failed persist must not add or remove records");
    require(journal.records().front().status == MutationStatus::Applied,
            "failed persist must not change the in-memory status");
    require(journal.activeRecords(sysctlPolicy()).size() == 1,
            "repeated operation after failed persist must still see the "
            "original active mutation");

    restorePersist(file);
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Applied,
            "disk state must stay unchanged after failed persist");
}

void testPrepareExistingPersistFailureRestoresRecord() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);

    breakPersist(file);
    MutationRecord updated = preparedRecord(sysctlPolicy());
    updated.undo = sysctlUndo("77");
    MutationId refreshedId = 0;
    require(!journal.prepareMutation(std::move(updated), refreshedId, error),
            "refreshing an existing record must fail when persist fails");
    require(refreshedId == id, "refresh must report the existing record id");

    require(journal.records().size() == 1,
            "failed refresh must not add or remove records");
    const MutationRecord& record = journal.records().front();
    require(record.status == MutationStatus::Applied,
            "failed refresh must restore the previous status");
    const auto* payload =
        std::get_if<UndoRemoveManagedSetting>(&record.undo.payload);
    require(payload != nullptr && payload->appliedValue == "10",
            "failed refresh must restore the previous undo payload");
    require(journal.activeRecords(sysctlPolicy()).size() == 1,
            "repeated operation after failed refresh must still see the "
            "original active mutation");

    restorePersist(file);
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Applied,
            "disk state must stay unchanged after failed refresh");
}
void testActiveRecordsFiltering() {

    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);

    const PolicyRef other{"FIREWALL", "HostFiltering", "block_rdp"};
    MutationId sysctlId = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), sysctlId, error),
            error);
    MutationRecord firewallRecord;
    firewallRecord.policy = other;
    firewallRecord.resource = "block_rdp";
    firewallRecord.undo = UndoAction{MutationBackend::Firewall,
                                     UndoRemoveFirewallPolicy{"fic_block_rdp"}};
    MutationId firewallId = 0;
    require(journal.prepareMutation(std::move(firewallRecord), firewallId, error),
            error);
    require(journal.setStatus(sysctlId, MutationStatus::RolledBack, error), error);

    const std::vector<MutationRecord> active = journal.activeRecords(sysctlPolicy());
    require(active.empty(),
            "rolled back records must not be returned as active");
    const std::vector<MutationRecord> firewallActive = journal.activeRecords(other);
    require(firewallActive.size() == 1 && firewallActive.front().id == firewallId,
            "active records of other policies must be returned");
}

void testDiscardPersistFailureRestoresStateAndOrder() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId firstId = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), firstId, error),
            error);
    MutationRecord second = preparedRecord(sysctlPolicy());
    second.policy = PolicyRef{"SYSCTL", "Global", "other_policy"};
    second.resource = "kernel.kptr_restrict";
    second.undo = UndoAction{MutationBackend::Sysctl,
                             UndoRemoveManagedSetting{"kernel.kptr_restrict", "2"}};
    MutationId secondId = 0;
    require(journal.prepareMutation(std::move(second), secondId, error), error);

    breakPersist(file);
    require(!journal.discard(firstId, error),
            "discard must fail when persist fails");

    // Exact logical restoration including the original record ordering.
    require(journal.records().size() == 2,
            "failed discard must keep both records");
    require(journal.records()[0].id == firstId &&
                journal.records()[1].id == secondId,
            "failed discard must restore the record at its original position");
    require(journal.activeRecords(sysctlPolicy()).size() == 1,
            "repeated operation after failed discard must still see the "
            "original active mutation");

    restorePersist(file);
    MutationId thirdId = 0;
    MutationRecord third = preparedRecord(sysctlPolicy());
    third.policy = PolicyRef{"SYSCTL", "Global", "third_policy"};
    third.resource = "kernel.randomize_va_space";
    third.undo = UndoAction{MutationBackend::Sysctl,
                            UndoRemoveManagedSetting{"kernel.randomize_va_space", "2"}};
    require(journal.prepareMutation(std::move(third), thirdId, error), error);
    require(thirdId == secondId + 1,
            "failed operations must not consume mutation ids");

    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 3 &&
                reloaded.records()[0].id == firstId &&
                reloaded.records()[1].id == secondId &&
                reloaded.records()[2].id == thirdId,
            "restored state must persist identically");
}

void testPreparedRecordRemainsActiveAfterFailedCommit() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);

    // Backend invariant: the system mutation succeeded, but the
    // Prepared -> Applied commit failed. The Prepared provenance must stay
    // active so a later disable can still resolve the state safely.
    breakPersist(file);
    require(!journal.setStatus(id, MutationStatus::Applied, error),
            "commit failure must be reported");
    require(journal.activeRecords(sysctlPolicy()).size() == 1 &&
                journal.records().front().status == MutationStatus::Prepared,
            "failed commit must leave the Prepared provenance active");
}

void testUnreadableJournalFailsClosed() {
    TempFile file;
    // An existing path that cannot be read as a journal (here: a directory
    // occupying the journal path) must fail closed, not be silently treated
    // as an absent journal.
    std::error_code ec;
    std::filesystem::create_directory(file.path, ec);
    require(!ec, "could not occupy the journal path with a directory");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error), "unreadable existing journal must fail closed");
    require(!error.empty(), "unreadable journal must produce an error message");
}

void testZeroByteJournalFailsClosed() {
    TempFile file;
    file.write("");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error), "existing zero-byte journal must fail closed");
    require(!error.empty(), "zero-byte journal must produce an error message");
}

void testMalformedFileFailsClosed() {
    TempFile file;
    file.write("this is not json at all");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error), "malformed journal must fail closed");
    require(!error.empty(), "malformed journal must produce an error message");
    // Fresh-object failure contract: loaded stays false, but the journal is
    // poisoned (Indeterminate) so that a later disappearance of the broken
    // file cannot silently bootstrap an empty Healthy journal.
    require(!journal.loaded(), "a failed fresh load must stay unloaded");
    require(journal.health() == JournalHealth::Indeterminate,
            "a failed fresh load must poison the journal");
    require(!journal.usable(), "a failed fresh load must not be usable");
}

void testUnknownSchemaVersionFailsClosed() {
    TempFile file;
    file.write(R"({"schema_version": 999, "next_id": 1, "records": []})");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error),
            "unknown schema_version must be rejected (fail closed)");
}

void testBrokenDocumentStructureFailsClosed() {
    TempFile file;
    file.write(R"({"schema_version": 1, "records": []})");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error),
            "journal without next_id must be rejected (fail closed)");
}

void testUnknownEnumValueFailsClosed() {
    TempFile file;
    file.write(
        R"({"schema_version": 1, "next_id": 2, "records": [{"id": 1, )"
        R"("policy": {"module": "SYSCTL", "submodule": "Global", )"
        R"("policy": "p"}, "resource": "vm.swappiness", )"
        R"("undo": {"action": "remove_managed_setting", "backend": "sysctl", )"
        R"("key": "vm.swappiness", "applied_value": "10"}, )"
        R"("status": "bogus_status", "created_at_epoch": 1, )"
        R"("updated_at_epoch": 1, "error": ""}]})");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error),
            "unknown status enum must be rejected (fail closed)");
}

void testDuplicateIdFailsClosed() {
    TempFile file;
    const std::string recordJson =
        R"({"id": 1, "policy": {"module": "SYSCTL", "submodule": "Global", )"
        R"("policy": "p"}, "resource": "vm.swappiness", )"
        R"("undo": {"action": "remove_managed_setting", "backend": "sysctl", )"
        R"("key": "vm.swappiness", "applied_value": "10"}, "status": "applied", )"
        R"("created_at_epoch": 1, "updated_at_epoch": 1, "error": ""})";
    file.write(R"({"schema_version": 1, "next_id": 2, "records": [)" +
               recordJson + "," + recordJson + R"(]})");
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error), "duplicate ids must be rejected (fail closed)");
}

void testStatusAndBackendStringRoundTrip() {
    for (const MutationStatus status : {MutationStatus::Prepared,
                                        MutationStatus::Applied,
                                        MutationStatus::RolledBack,
                                        MutationStatus::RollbackFailed,
                                        MutationStatus::Detached}) {
        MutationStatus parsed = MutationStatus::Detached;
        require(mutationStatusFromString(mutationStatusToString(status), parsed),
                "status must round trip");
        require(parsed == status, "status round trip must preserve value");
    }
    for (const MutationBackend backend : {MutationBackend::Sysctl,
                                          MutationBackend::Sudo,
                                          MutationBackend::Firewall,
                                          MutationBackend::DeviceControl}) {
        MutationBackend parsed = MutationBackend::Sysctl;
        require(mutationBackendFromString(mutationBackendToString(backend), parsed),
                "backend must round trip");
        require(parsed == backend, "backend round trip must preserve value");
    }
}

void testDaemonJournalOverrideAndHelpers() {
    TempFile file;
    DaemonMutationJournal::instance().setOverridePath(file.path);

    const PolicyRef policy = sysctlPolicy();
    MutationId id = 0;
    std::string error;
    require(recordPreparedMutation(policy, "vm.swappiness", sysctlUndo(), id, error),
            error);

    // Idempotency through the helper layer as well.
    MutationId repeatedId = 0;
    require(recordPreparedMutation(policy, "vm.swappiness", sysctlUndo(),
                                   repeatedId, error),
            error);
    require(id == repeatedId, "helper prepare must be idempotent per triple");

    require(commitMutation(id, error), error);

    // Reopen the override: the applied record must be refreshed, not duplicated.
    DaemonMutationJournal::instance().resetOverride();
    DaemonMutationJournal::instance().setOverridePath(file.path);
    MutationId probe = 0;
    require(recordPreparedMutation(policy, "vm.swappiness", sysctlUndo("77"),
                                   probe, error),
            error);
    require(probe == id,
            "applied record for the same triple must be refreshed, not duplicated");

    std::string discardError;
    require(discardMutation(probe, discardError), discardError);

    DaemonMutationJournal::instance().resetOverride();
}

void testDaemonJournalFailsClosedOnBrokenFile() {
    TempFile file;
    file.write("{ broken json");
    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string error;
    MutationId id = 0;
    require(!recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                    sysctlUndo(), id, error),
            "recording against a broken journal must fail closed");
    require(!error.empty(), "broken journal must produce an error message");
    DaemonMutationJournal::instance().resetOverride();
}

// ------------------------------------------------------------------ ssh -----

UndoAction sshUndo() {
    UndoRestoreSshDirective undo;
    undo.parameter = "Port";
    undo.appliedValue = "2222";
    SshDirectiveOccurrenceMutation replacement;
    replacement.beforeLine = "Port 22";
    replacement.afterLine = "Port 2222";
    undo.occurrences = {replacement};
    return UndoAction{MutationBackend::Ssh, std::move(undo)};
}

MutationRecord preparedSshRecord() {
    MutationRecord record;
    record.policy = PolicyRef{"NET", "SshEdit", "ssh_port"};
    record.resource = "ssh:/etc/ssh/sshd_config:Port";
    record.undo = sshUndo();
    return record;
}

void testSshUndoPayloadRoundTrip() {
    TempFile file;
    MutationId id = 0;
    {
        MutationJournal journal(file.path);
        std::string error;
        require(journal.load(error), error);
        require(journal.prepareMutation(preparedSshRecord(), id, error), error);
        require(journal.setStatus(id, MutationStatus::Applied, error), error);
    }
    MutationJournal reloaded(file.path);
    std::string error;
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1,
            "ssh record must survive reload");
    const MutationRecord& record = reloaded.records().front();
    require(record.undo.backend == MutationBackend::Ssh,
            "ssh backend must survive reload");
    const auto* undo = std::get_if<UndoRestoreSshDirective>(&record.undo.payload);
    require(undo != nullptr, "ssh undo payload must survive reload");
    require(undo->parameter == "Port" && undo->appliedValue == "2222",
            "ssh parameter and applied value must survive reload");
    require(undo->occurrences.size() == 1,
            "the ssh occurrence mutation must survive reload");
    require(undo->occurrences[0].beforeLine.has_value() &&
                *undo->occurrences[0].beforeLine == "Port 22" &&
                undo->occurrences[0].afterLine == "Port 2222",
            "the replacement occurrence must survive reload");
}

void requireBrokenSshJournalFailsClosed(const std::string& content,
                                        const std::string& description) {
    TempFile file;
    file.write(content);
    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error),
            "malformed ssh journal must fail closed: " + description);
    require(!error.empty(), "ssh journal failure must report an error");
}

std::string sshJournalHead() {
    return "{\"schema_version\":1,\"next_id\":2,\"records\":[{\"id\":1,"
           "\"policy\":{\"module\":\"NET\",\"submodule\":\"SshEdit\","
           "\"policy\":\"ssh_port\"},\"resource\":\"ssh:/etc/ssh/sshd_config:Port\","
           "\"backend\":\"ssh\",\"status\":\"applied\",\"created_at_epoch\":1,"
           "\"updated_at_epoch\":1,\"error\":\"\",\"undo\":{";
}

void testSshUndoMalformedPayloadsFailClosed() {
    const std::string head = sshJournalHead();
    const std::string tail = "}}]}";

    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\"}" + tail,
        "missing payload fields");
    // The abandoned intermediate format (fingerprint + absolute line
    // indices) must be rejected explicitly, never silently converted.
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"fingerprint\":\"0123456789abcdef\",\"reverse_edits\":"
               "[{\"line\":3,\"before\":\"Port 22\",\"after\":\"Port 2222\"}]}" +
            tail,
        "legacy payload format");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[]}" + tail,
        "empty occurrences");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":1,"
               "\"before\":\"Port 22\",\"after\":\"Port 2222\"}]}" + tail,
        "occurrence index must start at 0");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":0,"
               "\"before\":\"Port 22\",\"after\":\"Port 2222\"},"
               "{\"occurrence\":0,\"before\":\"Port 2022\","
               "\"after\":\"#Port 2022\"}]}" + tail,
        "non-increasing occurrence indices");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":0,"
               "\"before\":\"Port 22\",\"after\":\"\"}]}" + tail,
        "empty after line");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":0,"
               "\"before\":\"Port 22\",\"after\":\"Port 22\"}]}" + tail,
        "before and after lines must differ");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":0,\"before\":null,"
               "\"after\":\"Port 2222\"},{\"occurrence\":1,"
               "\"before\":\"Port 2022\",\"after\":\"#Port 2022\"}]}" + tail,
        "inserted occurrence must be the only one");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"ssh\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":0,"
               "\"before\":\"Port 22\",\"after\":\"Port 2222\"},"
               "{\"occurrence\":1,\"before\":\"Port 2022\","
               "\"after\":\"Port 2222\"}]}" + tail,
        "duplicate after lines");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"remove_managed_setting\",\"backend\":\"ssh\","
               "\"key\":\"Port\",\"applied_value\":\"2222\"}" + tail,
        "inconsistent action and backend");
    requireBrokenSshJournalFailsClosed(
        head + "\"action\":\"restore_ssh_directive\",\"backend\":\"sudo\","
               "\"parameter\":\"Port\",\"applied_value\":\"2222\","
               "\"occurrences\":[{\"occurrence\":0,"
               "\"before\":\"Port 22\",\"after\":\"Port 2222\"}]}" + tail,
        "inconsistent backend");
}

} // namespace

// Arms a deterministic directory fsync hook for the journal path: the first
// `failures` fsync attempts of the journal file fail, later ones succeed.
class JournalFsyncFailure {
public:
    JournalFsyncFailure(const TempFile& file, int failures) {
        const std::string journalPath = file.path.string();
        auto remaining = std::make_shared<int>(failures);
        AtomicFileWriter::setDirectoryFsyncHookForTests(
            [journalPath, remaining](const std::string& targetPath) {
                if (targetPath != journalPath) {
                    return true;
                }
                if (*remaining > 0) {
                    --*remaining;
                    return false;
                }
                return true;
            });
    }

    ~JournalFsyncFailure() {
        AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    }
};

void testSetStatusPostRenameDurabilityFailureCompletesDurability() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);

    // The journal rename succeeds and only the first post-rename directory
    // fsync fails; persist() must transparently finish the durability
    // instead of reporting memory=old / disk=new ambiguity.
    JournalFsyncFailure failure(file, 1);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);
    require(journal.health() == JournalHealth::Healthy,
            "a completed durability barrier must keep the journal healthy");

    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Applied,
            "the disk journal must carry the committed status");
}

void testSetStatusDurabilityRetryFailurePoisonsJournal() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);

    {
        JournalFsyncFailure failure(file, 1000);
    require(!journal.setStatus(id, MutationStatus::Applied, error),
            "an unconfirmable journal durability must fail the operation");
    require(journal.health() == JournalHealth::Indeterminate,
            "the journal must become indeterminate after an unconfirmable "
            "post-rename durability failure");

    // The in-memory state stays identical to the installed document (never
    // rolled back to the previous state): the rename already published the
    // new Applied status on disk.
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "the in-memory record must match the installed document");
    // Every mutating operation refuses until an explicit reload.
    require(!journal.setStatus(id, MutationStatus::RolledBack, error),
            "a poisoned journal must refuse mutations");
    require(!journal.discard(id, error), "a poisoned journal must refuse discard");
    require(!journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            "a poisoned journal must refuse new mutations");
    require(!journal.usable(),
            "a poisoned journal must not be usable for operational decisions");
    }
    // The disk document carries the installed new content (rename happened).
    // The load must prove durability of the exact parsed snapshot before it
    // may publish anything.
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.health() == JournalHealth::Healthy,
            "a durability-proven load must restore a healthy journal");
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Applied,
            "the installed document must survive on disk");
}

void testReloadRestoresHealthyJournalAfterIndeterminate() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);

    {
        JournalFsyncFailure failure(file, 1000);
        require(!journal.setStatus(id, MutationStatus::Applied, error), error);
        require(journal.health() == JournalHealth::Indeterminate, error);

        // Healthy is a durability property, not a readability property: the
        // disk document is readable and parses, but while the directory fsync
        // barrier is impossible the load must fail closed and the journal
        // must stay Indeterminate (visible != proven durable).
        require(!journal.load(error),
                "a load without the durability barrier must not succeed");
        require(journal.health() == JournalHealth::Indeterminate,
                "a failed load barrier must keep the journal indeterminate");
        require(!journal.usable(),
                "an indeterminate journal must not be usable for operational "
                "decisions");
    }
    // A load() that CAN complete the durability barrier re-parses the
    // current disk document and resets the indeterminate state to Healthy.
    require(journal.load(error), error);
    require(journal.health() == JournalHealth::Healthy,
            "a durability-proven reload must restore the healthy journal");
    require(journal.records().front().status == MutationStatus::Applied,
            "the reloaded journal must reflect the installed document");
    // Outside the failure scope the journal is fully usable again.
    require(journal.setStatus(id, MutationStatus::RolledBack, error), error);
    require(journal.records().front().status == MutationStatus::RolledBack,
            error);
}

void testPreparePostRenameDurabilityFailurePoisonsJournal() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);

    MutationId id = 0;
    {
        JournalFsyncFailure failure(file, 1000);
        require(!journal.prepareMutation(preparedRecord(sysctlPolicy()), id,
                                         error),
                "an unconfirmable prepare must fail");
        require(journal.health() == JournalHealth::Indeterminate, error);
        // The Prepared record stays in memory: it matches the installed
        // document, so restoring "no record" would contradict the disk.
        require(journal.records().size() == 1 &&
                    journal.records().front().status ==
                        MutationStatus::Prepared,
                "the prepared record must stay consistent with the installed "
                "document");
    }
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Prepared,
            "the installed Prepared record must survive on disk");
}

void testDiscardPostRenameDurabilityFailurePoisonsJournal() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);

    {
        JournalFsyncFailure failure(file, 1000);
        require(!journal.discard(id, error),
                "an unconfirmable discard must fail");
        require(journal.health() == JournalHealth::Indeterminate, error);
        // The removal stays in memory: it matches the installed document.
        require(journal.records().empty(),
                "the removal must stay consistent with the installed document");
    }
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.records().empty(),
            "the installed document without the record must survive on disk");
}

void testLoadDurabilityBarrierFailureAndRetry() {
    TempFile file;
    {
        MutationJournal journal(file.path);
        std::string error;
        require(journal.load(error), error);
        MutationId id = 0;
        require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
                error);
        require(journal.setStatus(id, MutationStatus::Applied, error), error);
    }
    {
        // The journal document on disk is readable and parses correctly, but
        // its directory entry durability cannot be confirmed (the visible
        // file may be the result of a rename whose parent fsync failed): a
        // successful read must never imply durability.
        JournalFsyncFailure failure(file, 1000);
        MutationJournal reloaded(file.path);
        std::string error;
        require(!reloaded.load(error),
                "a readable journal must not become healthy without the "
                "durability barrier");
        require(reloaded.health() == JournalHealth::Indeterminate, error);
        require(!reloaded.usable(),
                "an unproven journal must not drive operational decisions");
        require(reloaded.records().empty(),
                "a failed load must not replace the in-memory state");
    }
    // Retry after the durability becomes confirmable.
    MutationJournal reloaded(file.path);
    std::string error;
    require(reloaded.load(error), error);
    require(reloaded.health() == JournalHealth::Healthy, error);
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Applied,
            "the reloaded records must match the disk document");
}

void testLoadRaceBetweenCaptureAndBarrier() {
    TempFile file;
    {
        MutationJournal journal(file.path);
        std::string error;
        require(journal.load(error), error);
        MutationId id = 0;
        require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
                error);
        require(journal.setStatus(id, MutationStatus::Applied, error), error);
    }
    // Deterministic race: an external actor replaces the journal exactly
    // between the load capture and the re-proof/durability barrier. The load
    // must never parse one document and durability-confirm another.
    const std::string replacement =
        "{\"schema_version\":1,\"next_id\":2,\"records\":[]}";
    MutationJournal::setLoadAfterCaptureHookForTests(
        [&file, &replacement]() { file.write(replacement); });
    struct HookReset {
        ~HookReset() {
            MutationJournal::setLoadAfterCaptureHookForTests(nullptr);
        }
    } hookReset;

    MutationJournal journal(file.path);
    std::string error;
    require(!journal.load(error),
            "a journal replaced between capture and barrier must fail closed");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);

    // After the external writer is gone, the load publishes exactly the
    // document that occupies the path.
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
    require(reloaded.health() == JournalHealth::Healthy, error);
    require(reloaded.records().empty(),
            "the replacement document must be what load publishes");
}

void testDaemonJournalTryGetBlocksIndeterminateAndRecovers() {
    TempFile file;
    DaemonMutationJournal::instance().setOverridePath(file.path);
    struct OverrideReset {
        ~OverrideReset() { DaemonMutationJournal::instance().resetOverride(); }
    } overrideReset;

    std::string error;
    MutationId id = 0;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->health() == JournalHealth::Healthy,
            "a fresh daemon journal must be healthy");
    require(recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                   sysctlUndo(), id, error),
            error);

    {
        // A post-rename durability failure poisons the open singleton journal.
        JournalFsyncFailure failure(file, 1000);
        require(!journal->setStatus(id, MutationStatus::Applied, error), error);
        require(journal->health() == JournalHealth::Indeterminate, error);

        // Operational access is blocked: tryGet() must not hand out an
        // indeterminate journal for ANY decision (apply, rollback, disable
        // ownership resolution), and the lazy recovery load() cannot succeed
        // while the directory fsync is impossible.
        std::string gateError;
        require(DaemonMutationJournal::instance().tryGet(gateError) == nullptr,
                "an indeterminate journal must fail operational access closed");
        require(gateError.find("Indeterminate") != std::string::npos,
                "the gate must explain that a reload or restart is required: " +
                    gateError);
    }

    // Retry once the durability barrier becomes confirmable: the lazy
    // recovery load() succeeds and the journal is handed out again.
    MutationJournal* recovered = DaemonMutationJournal::instance().tryGet(error);
    require(recovered != nullptr, error);
    require(recovered->health() == JournalHealth::Healthy, error);
    require(recovered->records().size() == 1 &&
                recovered->records().front().status == MutationStatus::Applied,
            "the recovered journal must match the disk document");
}

void testHealthyReloadMissingJournalFailsClosed() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);
    const std::vector<MutationRecord> before = journal.records();

    // The journal was loaded and Healthy, but the file disappeared before
    // the reload: the disappearance of previously known provenance is not
    // equivalent to an empty journal (fail closed).
    std::error_code ec;
    require(std::filesystem::remove(file.path, ec), ec.message());
    require(!journal.load(error),
            "a previously loaded journal must not heal into an empty "
            "journal after its file disappeared");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);
    require(journal.loaded(),
            "a failed reload must keep the loaded_ flag for diagnostics");
    require(sameRecords(journal.records(), before),
            "a failed reload must not touch the in-memory records");
    require(error.find("disappeared") != std::string::npos,
            "the error must explain the disappearance semantics: " + error);
}

void testIndeterminateReloadMissingJournalFailsClosed() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);

    {
        // Applied -> RolledBack: rename succeeds, durability cannot be
        // confirmed, the journal becomes Indeterminate with the in-memory
        // state identical to the installed (RolledBack) document.
        JournalFsyncFailure failure(file, 1000);
        require(!journal.setStatus(id, MutationStatus::RolledBack, error),
                error);
        require(journal.health() == JournalHealth::Indeterminate, error);
        require(journal.records().size() == 1 &&
                    journal.records().front().status ==
                        MutationStatus::RolledBack,
                "the in-memory record must match the installed document");
    }

    // The journal file disappears externally. A reload must NOT turn the
    // ambiguous provenance into an empty Healthy journal (otherwise the
    // inactive in-memory record would be lost and disable/ownership logic
    // could wrongly answer NothingToDo).
    std::error_code ec;
    require(std::filesystem::remove(file.path, ec), ec.message());
    require(!journal.load(error),
            "an Indeterminate journal must fail closed when its file "
            "disappears during reload");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::RolledBack,
            "the old in-memory records must be preserved for diagnostics");
    // Mutating operations stay refused.
    require(!journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            "a poisoned journal must refuse new mutations");
    require(!journal.setStatus(id, MutationStatus::Applied, error),
            "a poisoned journal must refuse status updates");
    require(!journal.discard(id, error),
            "a poisoned journal must refuse discard");
}

void testHealthyMalformedReloadPoisonsJournal() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);
    const std::vector<MutationRecord> before = journal.records();
    require(journal.usable(), error);
    const std::string validDocument = file.read();

    // An external actor corrupts the persistent journal after it was loaded.
    file.write("{ broken json");
    require(!journal.load(error), "a malformed reload must fail closed");
    require(journal.health() == JournalHealth::Indeterminate,
            "a failed reload of a previously Healthy journal must poison it");
    require(!journal.usable(),
            "a poisoned journal must not be operationally usable");
    require(sameRecords(journal.records(), before),
            "a failed reload must not replace the old in-memory records");

    // All mutating operations must refuse after the failed reload.
    require(!journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            "a poisoned journal must refuse new mutations");
    require(!journal.setStatus(id, MutationStatus::RolledBack, error),
            "a poisoned journal must refuse status updates");
    require(!journal.discard(id, error),
            "a poisoned journal must refuse discard");

    // Recovery: after the persistent journal is fixed, a successful
    // durability-proven load restores Healthy.
    file.write(validDocument);
    require(journal.load(error), error);
    require(journal.health() == JournalHealth::Healthy, error);
    require(journal.usable(), error);
    require(sameRecords(journal.records(), before),
            "the recovered journal must match the restored document");
}

void testDaemonJournalTryGetMissingAfterIndeterminate() {
    TempFile file;
    DaemonMutationJournal::instance().setOverridePath(file.path);
    struct OverrideReset {
        ~OverrideReset() { DaemonMutationJournal::instance().resetOverride(); }
    } overrideReset;

    std::string error;
    MutationId id = 0;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                   sysctlUndo(), id, error),
            error);

    {
        // Poison the open singleton: post-rename durability unconfirmable.
        JournalFsyncFailure failure(file, 1000);
        require(!journal->setStatus(id, MutationStatus::RolledBack, error),
                error);
        require(journal->health() == JournalHealth::Indeterminate, error);
    }

    // The journal file disappears externally: the lazy recovery must not
    // heal the Indeterminate singleton into an empty Healthy journal.
    std::error_code ec;
    require(std::filesystem::remove(file.path, ec), ec.message());
    std::string gateError;
    require(DaemonMutationJournal::instance().tryGet(gateError) == nullptr,
            "a missing journal during Indeterminate recovery must fail "
            "operational access closed");
    require(gateError.find("Indeterminate") != std::string::npos,
            "the gate must explain that a reload or restart is required: " +
                gateError);
    require(gateError.find("missing") != std::string::npos ||
                gateError.find("disappeared") != std::string::npos,
            "the gate must surface the disappearance error: " + gateError);
    require(journal->health() == JournalHealth::Indeterminate, gateError);
    require(!journal->usable(), gateError);
    require(journal->records().size() == 1,
            "the in-memory provenance must be preserved for diagnostics");
}

void testFreshBootstrapCreatesJournalAndWitness() {
    TempFile file;
    DaemonMutationJournal::instance().setOverridePath(file.path);
    struct OverrideReset {
        ~OverrideReset() { DaemonMutationJournal::instance().resetOverride(); }
    } overrideReset;

    std::string error;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->health() == JournalHealth::Healthy, error);
    require(journal->usable(), error);
    require(journal->records().empty(), "a fresh bootstrap must be empty");
    // Both persistent objects must exist after the bootstrap.
    require(std::filesystem::exists(file.path),
            "the bootstrap must create the journal file");
    const std::filesystem::path witnessPath = file.path.string() + ".initialized";
    require(std::filesystem::exists(witnessPath),
            "the bootstrap must create the initialization witness");
    // The witness must be a real versioned document.
    std::ifstream witnessStream(witnessPath, std::ios::binary);
    const std::string witnessContent(
        (std::istreambuf_iterator<char>(witnessStream)),
        std::istreambuf_iterator<char>());
    require(witnessContent.find("schema_version") != std::string::npos &&
                witnessContent.find("initialized") != std::string::npos,
            "the witness must carry the versioned document: " + witnessContent);
}

void testRestartAfterBootstrapKeepsProvenance() {
    TempFile file;
    std::string error;
    {
        DaemonMutationJournal::instance().setOverridePath(file.path);
        MutationId id = 0;
        require(recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                       sysctlUndo(), id, error),
                error);
        require(commitMutation(id, error), error);
    }
    // Simulate a daemon restart: destroy the singleton state and reopen.
    DaemonMutationJournal::instance().setOverridePath(file.path);
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    require(journal->records().size() == 1 &&
                journal->records().front().status == MutationStatus::Applied,
            "the restarted daemon must reload the provenance");
    DaemonMutationJournal::instance().resetOverride();
}

void testJournalDeletionSurvivesRestart() {
    TempFile file;
    std::string error;
    {
        DaemonMutationJournal::instance().setOverridePath(file.path);
        MutationId id = 0;
        require(recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                       sysctlUndo(), id, error),
                error);
        require(commitMutation(id, error), error);
    }
    // Delete ONLY the journal; the witness remains.
    std::error_code ec;
    require(std::filesystem::remove(file.path, ec), ec.message());
    // Simulate a daemon restart: the old journal object is destroyed.
    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string gateError;
    require(DaemonMutationJournal::instance().tryGet(gateError) == nullptr,
            "a missing journal with a valid witness must fail closed after "
            "a restart");
    require(gateError.find("provenance may have been lost") !=
                std::string::npos,
            "the error must explain the provenance loss: " + gateError);
    require(gateError.find("manual provenance recovery is required") !=
                std::string::npos,
            "a restart is not a recovery mechanism: " + gateError);
    // The witness must not be deleted or recreated.
    require(std::filesystem::exists(file.path.string() + ".initialized"),
            "the witness must survive");
    DaemonMutationJournal::instance().resetOverride();
}

void testApplyRefusedAfterProvenanceLossRestart() {
    TempFile file;
    std::string error;
    {
        DaemonMutationJournal::instance().setOverridePath(file.path);
        MutationId id = 0;
        require(recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                       sysctlUndo(), id, error),
                error);
        require(commitMutation(id, error), error);
    }
    std::error_code ec;
    require(std::filesystem::remove(file.path, ec), ec.message());
    DaemonMutationJournal::instance().setOverridePath(file.path);
    MutationId newId = 0;
    require(!recordPreparedMutation(sysctlPolicy(), "vm.other", sysctlUndo(),
                                    newId, error),
            "a new baseline must not be recorded when the journal is "
            "missing but the witness exists");
    require(error.find("provenance may have been lost") != std::string::npos,
            error);
    DaemonMutationJournal::instance().resetOverride();
}

// Prepares a pre-witness journal on disk (raw load + mutations) WITHOUT a
// witness: models an old FIC installation or a crash between the journal
// creation and the witness creation.
void preparePreWitnessJournal(const std::filesystem::path& path) {
    MutationJournal journal(path);
    std::string error;
    require(journal.load(error), error);
    MutationId id = 0;
    require(journal.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(journal.setStatus(id, MutationStatus::Applied, error), error);
    require(std::filesystem::exists(path), "journal must exist on disk");
    require(!std::filesystem::exists(path.string() + ".initialized"),
            "witness must not exist yet");
}

void testInterruptedBootstrapRecovers() {
    TempFile file;
    // J exists as a valid empty journal, W missing: crash between the two
    // bootstrap phases.
    file.write(R"({"schema_version": 1, "next_id": 1, "records": []})");
    DaemonMutationJournal::instance().setOverridePath(file.path);
    struct OverrideReset {
        ~OverrideReset() { DaemonMutationJournal::instance().resetOverride(); }
    } overrideReset;

    std::string error;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    require(journal->records().empty(), error);
    require(std::filesystem::exists(file.path.string() + ".initialized"),
            "the interrupted bootstrap must create the witness");
}

void testMigrationFromPreWitnessJournal() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    DaemonMutationJournal::instance().setOverridePath(file.path);
    struct OverrideReset {
        ~OverrideReset() { DaemonMutationJournal::instance().resetOverride(); }
    } overrideReset;

    std::string error;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    require(journal->records().size() == 1 &&
                journal->records().front().status == MutationStatus::Applied,
            "migration must preserve the records exactly");
    require(std::filesystem::exists(file.path.string() + ".initialized"),
            "migration must create the witness");
}

void testWitnessCreationFailureFailsClosed() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    const std::string witnessPath = file.path.string() + ".initialized";
    // Force the directory fsync of the witness creation to fail permanently.
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&witnessPath](const std::string& targetPath) {
            return targetPath != witnessPath;
        });
    struct HookReset {
        ~HookReset() { AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr); }
    } hookReset;

    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string error;
    require(DaemonMutationJournal::instance().tryGet(error) == nullptr,
            "a journal without a provable witness must not become operational");
    require(std::filesystem::exists(file.path),
            "the journal must stay unchanged");
    // Retry after the filesystem recovers: migration completes.
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    require(journal->records().size() == 1, error);
    DaemonMutationJournal::instance().resetOverride();
}

void testWitnessRenameDurabilityFinish() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    const std::string witnessPath = file.path.string() + ".initialized";
    // The witness rename succeeds and exactly the first directory fsync
    // fails: the transparent durability finish must complete the migration.
    auto remaining = std::make_shared<int>(1);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&witnessPath, remaining](const std::string& targetPath) {
            if (targetPath != witnessPath) {
                return true;
            }
            if (*remaining > 0) {
                --*remaining;
                return false;
            }
            return true;
        });
    struct HookReset {
        ~HookReset() { AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr); }
    } hookReset;

    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string error;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    require(journal->records().size() == 1, error);
    DaemonMutationJournal::instance().resetOverride();
}

void testWitnessRenameDurabilityFailureFailsClosed() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    const std::string witnessPath = file.path.string() + ".initialized";
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&witnessPath](const std::string& targetPath) {
            return targetPath != witnessPath;
        });
    struct HookReset {
        ~HookReset() { AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr); }
    } hookReset;

    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string error;
    require(DaemonMutationJournal::instance().tryGet(error) == nullptr,
            "an unconfirmable witness durability must deny operational access");
    require(std::filesystem::exists(witnessPath),
            "the installed witness may remain on disk (installed != durable)");
    // The next startup takes the migration path again.
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    DaemonMutationJournal::instance().resetOverride();
}

void testMalformedWitnessFailsClosed() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    // Malformed witness: a persistent-state anomaly, never auto-repaired.
    // (TempFile::write targets the journal path, so the witness is written
    // through its own stream.)
    const std::filesystem::path witnessPath =
        file.path.string() + ".initialized";
    {
        std::ofstream witnessStream(witnessPath, std::ios::binary | std::ios::trunc);
        require(witnessStream.is_open(), "could not write the witness");
        witnessStream << "garbage witness";
    }
    const std::string witnessDocument = [&witnessPath] {
        std::ifstream stream(witnessPath, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(stream),
                           std::istreambuf_iterator<char>());
    }();

    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string error;
    require(DaemonMutationJournal::instance().tryGet(error) == nullptr,
            "a malformed witness must fail closed");
    require(error.find("anomaly") != std::string::npos ||
                error.find("некорректен") != std::string::npos,
            error);
    std::ifstream witnessStream(witnessPath, std::ios::binary);
    const std::string witnessAfter(
        (std::istreambuf_iterator<char>(witnessStream)),
        std::istreambuf_iterator<char>());
    require(witnessAfter == witnessDocument,
            "the witness must stay unchanged (no auto-repair)");
    // Zero-byte witness is the same anomaly.
    std::error_code ec;
    require(std::filesystem::remove(witnessPath, ec), ec.message());
    {
        std::ofstream zeroStream(witnessPath, std::ios::binary | std::ios::trunc);
        require(zeroStream.is_open(), "could not write the zero-byte witness");
    }
    require(DaemonMutationJournal::instance().tryGet(error) == nullptr,
            "a zero-byte witness must fail closed");
    require(std::filesystem::file_size(witnessPath, ec) == 0 && !ec,
            "the zero-byte witness must stay unchanged");
    DaemonMutationJournal::instance().resetOverride();
}

void testSymlinkWitnessFailsClosed() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    const std::string targetPath = file.path.string() + ".witness-target";
    std::error_code ec;
    std::filesystem::create_symlink(file.path, targetPath, ec);
    require(!ec, ec.message());
    std::filesystem::create_symlink(targetPath,
                                    file.path.string() + ".initialized", ec);
    require(!ec, ec.message());

    DaemonMutationJournal::instance().setOverridePath(file.path);
    std::string error;
    require(DaemonMutationJournal::instance().tryGet(error) == nullptr,
            "a symlink witness must fail closed without following it");
    DaemonMutationJournal::instance().resetOverride();
}

void testEmptyRecordsKeepWitness() {
    TempFile file;
    std::string error;
    {
        DaemonMutationJournal::instance().setOverridePath(file.path);
        MutationId id = 0;
        require(recordPreparedMutation(sysctlPolicy(), "vm.swappiness",
                                       sysctlUndo(), id, error),
                error);
        require(discardMutation(id, error), error);
    }
    // The witness means "journal lifecycle initialized", not "records exist".
    require(std::filesystem::exists(file.path.string() + ".initialized"),
            "the witness must survive emptying the journal");
    // After a restart the journal stays a normal initialized lifecycle state.
    DaemonMutationJournal::instance().setOverridePath(file.path);
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(journal->usable(), error);
    require(journal->records().empty(), error);
    DaemonMutationJournal::instance().resetOverride();
}

// Models a concurrent FIC instance performing a full legitimate
// witness-aware bootstrap with one Applied record.
void concurrentFullBootstrapWithRecord(const std::filesystem::path& path) {
    MutationJournal other(path);
    std::string error;
    require(other.initializeOrLoad(error), error);
    MutationId id = 0;
    require(other.prepareMutation(preparedRecord(sysctlPolicy()), id, error),
            error);
    require(other.setStatus(id, MutationStatus::Applied, error), error);
    require(other.lifecycleInitialized(),
            "the concurrent instance must complete its lifecycle");
    require(other.records().size() == 1, error);
}

// Mandatory test A/B: instance A probed J missing / W missing, then a second
// instance performed a FULL bootstrap (journal with an Applied record + a
// valid witness). A's exclusive install must conflict, the state table must
// be re-evaluated, and A must join the created lifecycle WITHOUT replacing
// the journal.
void testVirginBootstrapDoesNotOverwriteConcurrentFullBootstrap() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    MutationJournal::setBeforeVirginJournalInstallHookForTests([&file]() {
        // Clear the hook first: the concurrent instance performs its own
        // full bootstrap and must not recurse into this seam.
        MutationJournal::setBeforeVirginJournalInstallHookForTests(nullptr);
        concurrentFullBootstrapWithRecord(file.path);
    });
    struct HookReset {
        ~HookReset() {
            MutationJournal::setBeforeVirginJournalInstallHookForTests(
                nullptr);
        }
    } hookReset;

    require(journal.initializeOrLoad(error), error);
    require(journal.lifecycleInitialized(), error);
    require(journal.usable(), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "instance A must load the concurrent instance's record, never "
            "replace it with the empty bootstrap document");
    // The on-disk journal must be the concurrent instance's document.
    MutationJournal verify(file.path);
    require(verify.initializeOrLoad(error), error);
    require(verify.records().size() == 1 &&
                verify.records().front().status == MutationStatus::Applied,
            "the persisted journal must still carry the concurrent record");
}

// Mandatory test A/C: a concurrent instance created a durable journal (with
// an Applied record) but the witness is still missing (interrupted
// bootstrap). A must NOT replace the journal and must take the migration
// flow, preserving the records.
void testVirginBootstrapDoesNotOverwriteConcurrentJournalOnly() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    std::string journalContentBefore;
    MutationJournal::setBeforeVirginJournalInstallHookForTests(
        [&file, &error, &journalContentBefore]() {
            // Clear the hook first: the concurrent instance performs its own
            // full bootstrap and must not recurse into this seam.
            MutationJournal::setBeforeVirginJournalInstallHookForTests(
                nullptr);
            {
                MutationJournal other(file.path);
                require(other.initializeOrLoad(error), error);
                MutationId id = 0;
                require(other.prepareMutation(preparedRecord(sysctlPolicy()),
                                              id, error),
                        error);
                require(other.setStatus(id, MutationStatus::Applied, error),
                        error);
            }
            // Simulate the concurrent instance crashing before the witness.
            std::error_code ec;
            std::filesystem::remove(file.path.string() + ".initialized", ec);
            require(!ec, ec.message());
            std::ifstream stream(file.path, std::ios::binary);
            journalContentBefore.assign(
                std::istreambuf_iterator<char>(stream),
                std::istreambuf_iterator<char>());
        });
    struct HookReset {
        ~HookReset() {
            MutationJournal::setBeforeVirginJournalInstallHookForTests(
                nullptr);
        }
    } hookReset;

    require(journal.initializeOrLoad(error), error);
    require(journal.lifecycleInitialized(), error);
    require(journal.usable(), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "migration must preserve the concurrent instance's records");
    require(std::filesystem::exists(file.path.string() + ".initialized"),
            "instance A must complete the interrupted bootstrap by proving "
            "the witness");
    std::ifstream stream(file.path, std::ios::binary);
    const std::string journalContentAfter(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>());
    require(journalContentAfter == journalContentBefore,
            "the journal content must not be rewritten by the migration");
}

// Mandatory test D: the journal disappears AFTER the witness was created
// during virgin bootstrap. The final strict proof must fail closed —
// critically NOT into an empty Healthy journal.
void testVirginBootstrapJournalDisappearsAfterWitnessFailsClosed() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    MutationJournal::setBeforeFinalJournalProofHookForTests(
        [&file]() {
            std::error_code ec;
            std::filesystem::remove(file.path, ec);
            require(!ec, ec.message());
        });
    struct HookReset {
        ~HookReset() {
            MutationJournal::setBeforeFinalJournalProofHookForTests(nullptr);
        }
    } hookReset;

    require(!journal.initializeOrLoad(error),
            "a missing journal after witness creation must fail closed");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);
    require(!journal.lifecycleInitialized(), error);
    require(std::filesystem::exists(file.path.string() + ".initialized"),
            "the witness must remain on disk");
    // Next restart: J missing + W valid → provenance loss, fail closed.
    MutationJournal restarted(file.path);
    std::string restartError;
    require(!restarted.initializeOrLoad(restartError),
            "the next startup must detect the provenance loss");
    require(restartError.find("provenance") != std::string::npos,
            "the restart must report provenance loss: " + restartError);
}

// Mandatory test E: the journal disappears between the first proof and the
// final proof of the migration flow. Fail closed; the next restart sees
// J missing + W valid → provenance loss, fail closed.
void testMigrationJournalDisappearsBeforeFinalProofFailsClosed() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    MutationJournal journal(file.path);
    std::string error;
    MutationJournal::setBeforeFinalJournalProofHookForTests(
        [&file]() {
            std::error_code ec;
            std::filesystem::remove(file.path, ec);
            require(!ec, ec.message());
        });
    struct HookReset {
        ~HookReset() {
            MutationJournal::setBeforeFinalJournalProofHookForTests(nullptr);
        }
    } hookReset;

    require(!journal.initializeOrLoad(error),
            "the migration must fail closed when the journal disappears "
            "before the final proof");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);
    require(!journal.lifecycleInitialized(), error);
    // Next restart: J missing + W valid → provenance loss, fail closed.
    MutationJournal restarted(file.path);
    std::string restartError;
    require(!restarted.initializeOrLoad(restartError),
            "the next startup must detect the provenance loss");
    require(restartError.find("provenance") != std::string::npos,
            "the restart must report provenance loss: " + restartError);
}

// Mandatory test F: after a failed witness creation the SAME object must
// retry the witness-aware migration on the next initializeOrLoad() — the
// raw journal load must not bypass the witness.
void testSameObjectRetriesWitnessAwareMigrationAfterWitnessFailure() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    const std::string witnessPath = file.path.string() + ".initialized";
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&witnessPath](const std::string& targetPath) {
            return targetPath != witnessPath;
        });
    struct HookReset {
        ~HookReset() {
            AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
        }
    } hookReset;

    MutationJournal journal(file.path);
    std::string error;
    require(!journal.initializeOrLoad(error),
            "witness creation failure must fail closed");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);
    require(!journal.lifecycleInitialized(),
            "the witness-aware lifecycle must NOT be considered initialized");
    // NOTE: the witness file may already be installed on disk at this point
    // (rename-ok + fsync-fail leaves it installed but NOT proven durable);
    // the next initialization must still re-prove/accept it.

    // Filesystem recovers; retry on the SAME object.
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(journal.initializeOrLoad(error), error);
    require(journal.lifecycleInitialized(),
            "the retry must complete the witness-aware migration");
    require(journal.usable(), error);
    require(journal.health() == JournalHealth::Healthy, error);
    require(std::filesystem::exists(witnessPath), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "the retry must preserve the migrated records");
}

// Mandatory test G: a malformed witness must fail closed on EVERY
// initializeOrLoad() on the same object — a raw journal reload must never
// bypass the persistent-state anomaly.
void testSameObjectMalformedWitnessNeverBypassed() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    const std::string witnessPath = file.path.string() + ".initialized";
    {
        std::ofstream stream(witnessPath, std::ios::binary | std::ios::trunc);
        stream << "{\"schema_version\":999,\"initialized\":true}\n";
    }
    MutationJournal journal(file.path);
    std::string firstError;
    require(!journal.initializeOrLoad(firstError),
            "a malformed witness must fail closed");
    require(journal.health() == JournalHealth::Indeterminate, firstError);
    require(!journal.usable(), firstError);
    require(!journal.lifecycleInitialized(), firstError);

    std::string secondError;
    require(!journal.initializeOrLoad(secondError),
            "the same-object retry must re-run the witness-aware state "
            "table, not a raw reload");
    require(!journal.usable(), secondError);
    require(!journal.lifecycleInitialized(), secondError);
}

// Mandatory test H: after a successful lifecycle, initializeOrLoad() on the
// same object must fail closed when the journal disappears (follow-up 6/7
// semantics preserved).
void testSuccessfulLifecycleThenJournalDeletionFailsClosed() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.initializeOrLoad(error), error);
    require(journal.lifecycleInitialized(), error);
    require(journal.usable(), error);

    std::error_code ec;
    require(std::filesystem::remove(file.path, ec), ec.message());
    require(!journal.initializeOrLoad(error),
            "the disappeared journal must never become an empty Healthy "
            "journal");
    require(journal.health() == JournalHealth::Indeterminate, error);
    require(!journal.usable(), error);
}

// Mandatory test I: the migration must not rewrite the journal — the file
// identity (device/inode) and content must be preserved across witness
// creation.
void testMigrationDoesNotRewriteJournalFile() {
    TempFile file;
    preparePreWitnessJournal(file.path);
    AtomicTargetState before;
    std::string error;
    require(AtomicFileWriter::captureTargetState(file.path.string(), before,
                                                 &error),
            error);
    std::ifstream stream(file.path, std::ios::binary);
    const std::string contentBefore((std::istreambuf_iterator<char>(stream)),
                                    std::istreambuf_iterator<char>());

    MutationJournal journal(file.path);
    require(journal.initializeOrLoad(error), error);
    require(journal.lifecycleInitialized(), error);

    AtomicTargetState after;
    require(AtomicFileWriter::captureTargetState(file.path.string(), after,
                                                 &error),
            error);
    require(before.identity.device == after.identity.device &&
                before.identity.inode == after.identity.inode,
            "the migration must keep the same journal file (no rewrite)");
    std::ifstream afterStream(file.path, std::ios::binary);
    const std::string contentAfter(
        (std::istreambuf_iterator<char>(afterStream)),
        std::istreambuf_iterator<char>());
    require(contentAfter == contentBefore,
            "the migration must keep the journal content unchanged");
}
int main() {
    const struct {
        const char* name;
        void (*test)();
    } tests[] = {
        {"missing file is empty journal", testMissingFileIsEmptyJournal},
        {"prepare commit reload persistence", testPrepareCommitAndReloadPersistence},
        {"prepare idempotency", testPrepareIsIdempotentForSameTriple},
        {"discard removes record", testDiscardRemovesRecord},
        {"set status persist failure restores record",
         testSetStatusPersistFailureRestoresRecord},
        {"set status post-rename durability completes",
         testSetStatusPostRenameDurabilityFailureCompletesDurability},
        {"set status durability retry failure poisons journal",
         testSetStatusDurabilityRetryFailurePoisonsJournal},
        {"reload restores healthy journal after indeterminate",
         testReloadRestoresHealthyJournalAfterIndeterminate},
        {"prepare post-rename durability failure poisons journal",
         testPreparePostRenameDurabilityFailurePoisonsJournal},
        {"discard post-rename durability failure poisons journal",
         testDiscardPostRenameDurabilityFailurePoisonsJournal},
        {"prepare existing persist failure restores record",
         testPrepareExistingPersistFailureRestoresRecord},
        {"discard persist failure restores state and order",
         testDiscardPersistFailureRestoresStateAndOrder},
        {"prepared record remains active after failed commit",
         testPreparedRecordRemainsActiveAfterFailedCommit},
        {"unreadable existing journal fails closed",
         testUnreadableJournalFailsClosed},
        {"zero byte journal fails closed", testZeroByteJournalFailsClosed},
        {"active records filtering", testActiveRecordsFiltering},
        {"malformed file fails closed", testMalformedFileFailsClosed},
        {"unknown schema version fails closed", testUnknownSchemaVersionFailsClosed},
        {"broken document structure fails closed", testBrokenDocumentStructureFailsClosed},
        {"unknown enum value fails closed", testUnknownEnumValueFailsClosed},
        {"duplicate id fails closed", testDuplicateIdFailsClosed},
        {"status and backend string round trip", testStatusAndBackendStringRoundTrip},
        {"ssh undo payload round trip", testSshUndoPayloadRoundTrip},
        {"ssh undo malformed payloads fail closed", testSshUndoMalformedPayloadsFailClosed},
        {"daemon journal override and helpers", testDaemonJournalOverrideAndHelpers},
        {"daemon journal fails closed on broken file", testDaemonJournalFailsClosedOnBrokenFile},
        {"load durability barrier failure and retry", testLoadDurabilityBarrierFailureAndRetry},
        {"load race between capture and barrier", testLoadRaceBetweenCaptureAndBarrier},
        {"daemon journal tryGet blocks indeterminate and recovers",
         testDaemonJournalTryGetBlocksIndeterminateAndRecovers},
        {"healthy reload missing journal fails closed",
         testHealthyReloadMissingJournalFailsClosed},
        {"indeterminate reload missing journal fails closed",
         testIndeterminateReloadMissingJournalFailsClosed},
        {"healthy malformed reload poisons journal",
         testHealthyMalformedReloadPoisonsJournal},
        {"daemon journal tryGet missing after indeterminate",
         testDaemonJournalTryGetMissingAfterIndeterminate},
        {"fresh bootstrap creates journal and witness",
         testFreshBootstrapCreatesJournalAndWitness},
        {"restart after bootstrap keeps provenance",
         testRestartAfterBootstrapKeepsProvenance},
        {"journal deletion survives restart",
         testJournalDeletionSurvivesRestart},
        {"apply refused after provenance loss restart",
         testApplyRefusedAfterProvenanceLossRestart},
        {"interrupted bootstrap recovers", testInterruptedBootstrapRecovers},
        {"migration from pre-witness journal",
         testMigrationFromPreWitnessJournal},
        {"witness creation failure fails closed",
         testWitnessCreationFailureFailsClosed},
        {"witness rename durability finish", testWitnessRenameDurabilityFinish},
        {"witness rename durability failure fails closed",
         testWitnessRenameDurabilityFailureFailsClosed},
        {"malformed witness fails closed", testMalformedWitnessFailsClosed},
        {"symlink witness fails closed", testSymlinkWitnessFailsClosed},
        {"concurrent full bootstrap journal preserved",
         testVirginBootstrapDoesNotOverwriteConcurrentFullBootstrap},
        {"concurrent journal-only bootstrap migrates",
         testVirginBootstrapDoesNotOverwriteConcurrentJournalOnly},
        {"virgin bootstrap journal disappears after witness fails closed",
         testVirginBootstrapJournalDisappearsAfterWitnessFailsClosed},
        {"migration journal disappears before final proof fails closed",
         testMigrationJournalDisappearsBeforeFinalProofFailsClosed},
        {"same-object retry after witness creation failure",
         testSameObjectRetriesWitnessAwareMigrationAfterWitnessFailure},
        {"same-object malformed witness never bypassed",
         testSameObjectMalformedWitnessNeverBypassed},
        {"successful lifecycle then journal deletion fails closed",
         testSuccessfulLifecycleThenJournalDeletionFailsClosed},
        {"migration does not rewrite journal file",
         testMigrationDoesNotRewriteJournalFile},
        {"empty records keep witness", testEmptyRecordsKeepWitness}
    };

    std::size_t failures = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "FAIL: " << name << ": " << exception.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
