#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
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

} // namespace

int main() {
    const struct {
        const char* name;
        void (*test)();
    } tests[] = {
        {"missing file is empty journal", testMissingFileIsEmptyJournal},
        {"prepare commit reload persistence", testPrepareCommitAndReloadPersistence},
        {"prepare idempotency", testPrepareIsIdempotentForSameTriple},
        {"discard removes record", testDiscardRemovesRecord},
        {"active records filtering", testActiveRecordsFiltering},
        {"malformed file fails closed", testMalformedFileFailsClosed},
        {"unknown schema version fails closed", testUnknownSchemaVersionFailsClosed},
        {"broken document structure fails closed", testBrokenDocumentStructureFailsClosed},
        {"unknown enum value fails closed", testUnknownEnumValueFailsClosed},
        {"duplicate id fails closed", testDuplicateIdFailsClosed},
        {"status and backend string round trip", testStatusAndBackendStringRoundTrip},
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
