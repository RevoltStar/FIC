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

void testMissingFileIsEmptyJournal() {
    TempFile file;
    MutationJournal journal(file.path);
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(), "missing journal must be empty");
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

    // The disk document carries the installed new content (rename happened).
    MutationJournal reloaded(file.path);
    require(reloaded.load(error), error);
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

        // An explicit load() re-parses the current disk document and resets
        // the indeterminate state back to Healthy.
        require(journal.load(error), error);
        require(journal.health() == JournalHealth::Healthy,
                "a successful reload must restore the healthy journal");
        require(journal.records().front().status == MutationStatus::Applied,
                "the reloaded journal must reflect the installed document");
    }
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
        {"daemon journal fails closed on broken file", testDaemonJournalFailsClosedOnBrokenFile}
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
