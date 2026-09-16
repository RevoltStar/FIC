#include "rollback/MutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <nlohmann/json.hpp>

#include <ctime>
#include <functional>
#include <system_error>
#include <utility>

namespace fic::rollback {
namespace {

using nlohmann::json;

std::int64_t currentEpochSeconds() {
    return static_cast<std::int64_t>(::time(nullptr));
}

// Test-only seam storage (see setLoadAfterCaptureHookForTests()).
std::function<void()>& loadAfterCaptureHook() {
    static std::function<void()> hook;
    return hook;
}

json serializeUndoAction(const UndoAction& action) {
    json value;
    value["action"] = undoActionTypeName(action);
    // The undo payload must be self-describing: deserializeUndoAction requires
    // the backend inside the undo object to validate payload/backend
    // consistency on load (fail closed).
    value["backend"] = mutationBackendToString(action.backend);
    if (const auto* setting =
            std::get_if<UndoRemoveManagedSetting>(&action.payload)) {
        value["key"] = setting->key;
        value["applied_value"] = setting->appliedValue;
    } else if (const auto* sshDirective =
                   std::get_if<UndoRestoreSshDirective>(&action.payload)) {
        value["parameter"] = sshDirective->parameter;
        value["applied_value"] = sshDirective->appliedValue;
        json occurrences = json::array();
        for (const SshDirectiveOccurrenceMutation& occurrence :
             sshDirective->occurrences) {
            json item;
            // The vector order is the mutation identity; no positional index
            // is serialized.
            if (occurrence.beforeLine.has_value()) {
                item["before"] = *occurrence.beforeLine;
            } else {
                item["before"] = nullptr; // FIC inserted the line
            }
            item["after"] = occurrence.afterLine;
            occurrences.push_back(std::move(item));
        }
        value["occurrences"] = std::move(occurrences);
    } else if (const auto* firewallPolicy =
                   std::get_if<UndoRemoveFirewallPolicy>(&action.payload)) {
        value["policy"] = firewallPolicy->policyName;
    } else if (const auto* feature =
                   std::get_if<UndoDisableDeviceFeature>(&action.payload)) {
        value["feature"] = feature->feature;
    }
    return value;
}

bool deserializeUndoAction(const json& value, UndoAction& action, std::string& error) {
    const std::string actionName = value.value("action", "");
    const std::string backendName = value.value("backend", "");
    MutationBackend backend;
    if (!mutationBackendFromString(backendName, backend)) {
        error = "unknown mutation undo backend: " + backendName;
        return false;
    }
    action.backend = backend;
    if (actionName == "remove_managed_setting" &&
        (backend == MutationBackend::Sysctl || backend == MutationBackend::Sudo)) {
        UndoRemoveManagedSetting payload;
        payload.key = value.value("key", "");
        payload.appliedValue = value.value("applied_value", "");
        if (payload.key.empty() ||
            (backend == MutationBackend::Sudo && payload.appliedValue.empty())) {
            error = "remove_managed_setting undo requires a key";
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "restore_ssh_directive" &&
        backend == MutationBackend::Ssh) {
        // Fail closed on the abandoned intermediate payload format (global
        // section fingerprint + absolute line indices): it must never be
        // silently converted to the mutation-local semantics.
        if (value.contains("fingerprint") || value.contains("reverse_edits")) {
            error = "restore_ssh_directive undo uses the unsupported legacy "
                    "payload format (fingerprint/reverse_edits); the record "
                    "must be resolved manually";
            return false;
        }
        UndoRestoreSshDirective payload;
        payload.parameter = value.value("parameter", "");
        payload.appliedValue = value.value("applied_value", "");
        const auto occurrencesIt = value.find("occurrences");
        if (payload.parameter.empty() ||
            payload.appliedValue.empty() ||
            occurrencesIt == value.end() || !occurrencesIt->is_array() ||
            occurrencesIt->empty()) {
            error = "restore_ssh_directive undo requires a parameter, an "
                    "applied value and occurrences";
            return false;
        }
        std::size_t position = 0;
        for (const json& item : *occurrencesIt) {
            if (!item.is_object()) {
                error = "ssh occurrence mutation must be an object";
                return false;
            }
            // The occurrence vector order is the mutation identity. The
            // redundant positional field of the intermediate development
            // format is tolerated only when it matches the vector position
            // exactly (same semantics); anything else is rejected fail
            // closed instead of being silently re-interpreted.
            const auto occurrenceIt = item.find("occurrence");
            if (occurrenceIt != item.end()) {
                if (!occurrenceIt->is_number_unsigned() ||
                    occurrenceIt->get<std::size_t>() != position) {
                    error = "ssh occurrence index does not match the "
                            "recorded occurrence order";
                    return false;
                }
            }
            SshDirectiveOccurrenceMutation occurrence;
            const auto beforeIt = item.find("before");
            if (beforeIt == item.end() ||
                (!beforeIt->is_string() && !beforeIt->is_null())) {
                error = "ssh occurrence mutation requires a string or null "
                        "before line";
                return false;
            }
            if (beforeIt->is_string()) {
                std::string before = beforeIt->get<std::string>();
                if (before.empty()) {
                    error = "ssh occurrence mutation before line must not be "
                            "empty";
                    return false;
                }
                occurrence.beforeLine = std::move(before);
            }
            const auto afterIt = item.find("after");
            if (afterIt == item.end() || !afterIt->is_string() ||
                afterIt->get<std::string>().empty()) {
                error = "ssh occurrence mutation requires a non-empty after line";
                return false;
            }
            occurrence.afterLine = afterIt->get<std::string>();
            if (occurrence.beforeLine.has_value() &&
                *occurrence.beforeLine == occurrence.afterLine) {
                error = "ssh occurrence mutation before and after lines must "
                        "differ";
                return false;
            }
            // An inserted line is a single-occurrence mutation: the whole
            // recorded mutation is either one replacement/comment set or one
            // insertion.
            if (!occurrence.beforeLine.has_value() &&
                occurrencesIt->size() != 1) {
                error = "an inserted ssh directive must be the only recorded "
                        "occurrence mutation";
                return false;
            }
            // Identical after lines are legal: duplicated directives produce
            // identical commented lines (e.g. two "#Port 22" duplicates), and
            // the ordered sequence comparison keeps the payload unambiguous.
            payload.occurrences.push_back(std::move(occurrence));
            ++position;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_firewall_policy" &&
        backend == MutationBackend::Firewall) {
        UndoRemoveFirewallPolicy payload;
        payload.policyName = value.value("policy", "");
        if (payload.policyName.empty()) {
            error = "remove_firewall_policy undo requires a policy";
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "disable_device_feature" &&
        backend == MutationBackend::DeviceControl) {
        UndoDisableDeviceFeature payload;
        payload.feature = value.value("feature", "");
        if (payload.feature.empty()) {
            error = "disable_device_feature undo requires a feature";
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    error = "unknown or inconsistent undo action: " + actionName +
            " for backend " + backendName;
    return false;
}

json serializeRecord(const MutationRecord& record) {
    json value;
    value["id"] = record.id;
    value["policy"] = {
        {"module", record.policy.moduleName},
        {"submodule", record.policy.submoduleName},
        {"policy", record.policy.policyName}
    };
    value["resource"] = record.resource;
    value["backend"] = mutationBackendToString(record.undo.backend);
    value["status"] = mutationStatusToString(record.status);
    value["undo"] = serializeUndoAction(record.undo);
    value["created_at_epoch"] = record.createdAtEpoch;
    value["updated_at_epoch"] = record.updatedAtEpoch;
    value["error"] = record.error;
    return value;
}

bool deserializeRecord(const json& value, MutationRecord& record, std::string& error) {
    if (!value.is_object()) {
        error = "journal record must be an object";
        return false;
    }
    const auto idIt = value.find("id");
    if (idIt == value.end() || !idIt->is_number_unsigned()) {
        error = "journal record requires an unsigned id";
        return false;
    }
    record.id = idIt->get<MutationId>();

    const auto policyIt = value.find("policy");
    if (policyIt == value.end() || !policyIt->is_object()) {
        error = "journal record requires a policy object";
        return false;
    }
    record.policy.moduleName = policyIt->value("module", "");
    record.policy.submoduleName = policyIt->value("submodule", "");
    record.policy.policyName = policyIt->value("policy", "");
    if (record.policy.moduleName.empty() || record.policy.policyName.empty()) {
        error = "journal record policy requires module and policy names";
        return false;
    }

    record.resource = value.value("resource", "");

    const auto undoIt = value.find("undo");
    if (undoIt == value.end() || !undoIt->is_object()) {
        error = "journal record requires an undo object";
        return false;
    }
    if (!deserializeUndoAction(*undoIt, record.undo, error)) {
        return false;
    }

    MutationStatus status;
    if (!mutationStatusFromString(value.value("status", ""), status)) {
        error = "unknown mutation status: " + value.value("status", std::string());
        return false;
    }
    record.status = status;

    record.createdAtEpoch = value.value("created_at_epoch", std::int64_t{0});
    record.updatedAtEpoch = value.value("updated_at_epoch", std::int64_t{0});
    record.error = value.value("error", std::string());
    return true;
}

} // namespace

std::string mutationStatusToString(MutationStatus status) {
    switch (status) {
    case MutationStatus::Prepared: return "prepared";
    case MutationStatus::Applied: return "applied";
    case MutationStatus::RolledBack: return "rolled_back";
    case MutationStatus::RollbackFailed: return "rollback_failed";
    case MutationStatus::Detached: return "detached";
    }
    return "unknown";
}

bool mutationStatusFromString(const std::string& value, MutationStatus& status) {
    if (value == "prepared") { status = MutationStatus::Prepared; return true; }
    if (value == "applied") { status = MutationStatus::Applied; return true; }
    if (value == "rolled_back") { status = MutationStatus::RolledBack; return true; }
    if (value == "rollback_failed") { status = MutationStatus::RollbackFailed; return true; }
    if (value == "detached") { status = MutationStatus::Detached; return true; }
    return false;
}

std::string mutationBackendToString(MutationBackend backend) {
    switch (backend) {
    case MutationBackend::Sysctl: return "sysctl";
    case MutationBackend::Sudo: return "sudo";
    case MutationBackend::Ssh: return "ssh";
    case MutationBackend::Firewall: return "firewall";
    case MutationBackend::DeviceControl: return "device_control";
    }
    return "unknown";
}

bool mutationBackendFromString(const std::string& value, MutationBackend& backend) {
    if (value == "sysctl") { backend = MutationBackend::Sysctl; return true; }
    if (value == "sudo") { backend = MutationBackend::Sudo; return true; }
    if (value == "ssh") { backend = MutationBackend::Ssh; return true; }
    if (value == "firewall") { backend = MutationBackend::Firewall; return true; }
    if (value == "device_control") { backend = MutationBackend::DeviceControl; return true; }
    return false;
}

std::string undoActionTypeName(const UndoAction& action) {
    if (std::holds_alternative<UndoRemoveManagedSetting>(action.payload)) {
        return "remove_managed_setting";
    }
    if (std::holds_alternative<UndoRestoreSshDirective>(action.payload)) {
        return "restore_ssh_directive";
    }
    if (std::holds_alternative<UndoRemoveFirewallPolicy>(action.payload)) {
        return "remove_firewall_policy";
    }
    if (std::holds_alternative<UndoDisableDeviceFeature>(action.payload)) {
        return "disable_device_feature";
    }
    return "unknown";
}

MutationJournal::MutationJournal(std::filesystem::path path)
    : path_(std::move(path)) {
}

bool MutationJournal::failLoad(std::string message, std::string& error) {
    // Transactional failure: never mutate records_/nextId_/loaded_ — the
    // previous in-memory state stays for diagnostics — but revoke operational
    // trust so stale provenance cannot drive any decision.
    health_ = JournalHealth::Indeterminate;
    error = std::move(message);
    return false;
}

bool MutationJournal::load(std::string& error) {
    std::error_code probeError;
    const std::filesystem::file_status status =
        std::filesystem::status(path_, probeError);
    if (probeError &&
        status.type() != std::filesystem::file_type::not_found) {
        return failLoad("Не удалось проверить наличие mutation journal " +
                            path_.string() + ": " + probeError.message(),
                        error);
    }
    if (status.type() == std::filesystem::file_type::not_found ||
        !std::filesystem::exists(status)) {
        // A missing journal is an empty journal ONLY during the initial
        // bootstrap of a never-loaded journal object. The disappearance of a
        // previously known journal (loaded, or already Indeterminate) does
        // not prove that the earlier ambiguous provenance safely vanished:
        // it must fail closed instead of healing into an empty Healthy
        // journal.
        const bool bootstrapMissing =
            !loaded_ && health_ == JournalHealth::Healthy;
        if (bootstrapMissing) {
            records_.clear();
            nextId_ = 1;
            loaded_ = true;
            error.clear();
            return true;
        }
        return failLoad("Mutation journal disappeared during reload/recovery; "
                        "provenance cannot be treated as empty: " +
                            path_.string(),
                        error);
    }

    // Snapshot-bound read: capture the exact current document (identity,
    // metadata, content) through one descriptor. Parsing happens strictly
    // against snapshot.content, so a durability confirmation later in this
    // function always refers to the same bytes that were parsed.
    AtomicTargetState snapshot;
    std::string captureError;
    if (!AtomicFileWriter::captureTargetState(path_.string(), snapshot,
                                              &captureError)) {
        // The file exists but cannot be opened/read: never treat permission,
        // symlink or I/O failures as an absent journal (fail closed).
        return failLoad("Существующий mutation journal недоступен для чтения "
                        "(fail closed): " +
                            captureError,
                        error);
    }
    if (snapshot.content.empty()) {
        // An existing zero-byte journal is corrupted persistent security
        // state: fail closed instead of silently assuming an empty journal.
        // A valid empty journal must carry the schema document.
        return failLoad("Mutation journal существует, но пуст (fail closed): " +
                            path_.string(),
                        error);
    }

    // Test-only seam: an external writer may replace the journal between the
    // capture and the re-proof below; the re-proof must detect it.
    if (loadAfterCaptureHook()) {
        loadAfterCaptureHook()();
    }

    const std::string& content = snapshot.content;

    json document;
    try {
        document = json::parse(content);
    } catch (const json::exception& exception) {
        return failLoad("Mutation journal повреждён (fail closed): " +
                            std::string(exception.what()),
                        error);
    }
    if (!document.is_object()) {
        return failLoad(
            "Mutation journal должен быть JSON-объектом (fail closed)", error);
    }
    const auto schemaIt = document.find("schema_version");
    if (schemaIt == document.end() || !schemaIt->is_number_unsigned()) {
        return failLoad(
            "Mutation journal не содержит schema_version (fail closed)",
            error);
    }
    if (schemaIt->get<std::uint32_t>() != kSchemaVersion) {
        return failLoad("Неподдерживаемая schema_version mutation journal: " +
                            schemaIt->dump(),
                        error);
    }
    const auto nextIdIt = document.find("next_id");
    if (nextIdIt == document.end() || !nextIdIt->is_number_unsigned()) {
        return failLoad(
            "Mutation journal не содержит корректный next_id (fail closed)",
            error);
    }
    const auto recordsIt = document.find("records");
    if (recordsIt == document.end() || !recordsIt->is_array()) {
        return failLoad(
            "Mutation journal не содержит массив records (fail closed)",
            error);
    }

    // Transactional parse: everything above worked on local state; the
    // in-memory journal is only replaced after the parsed snapshot was
    // re-proved and durably confirmed.
    std::vector<MutationRecord> parsed;
    parsed.reserve(recordsIt->size());
    for (const json& item : *recordsIt) {
        MutationRecord record;
        std::string recordError;
        if (!deserializeRecord(item, record, recordError)) {
            return failLoad("Mutation journal содержит некорректную запись "
                            "(fail closed): " +
                                recordError,
                            error);
        }
        parsed.push_back(std::move(record));
    }

    const MutationId parsedNextId = nextIdIt->get<MutationId>();
    for (const MutationRecord& record : parsed) {
        if (record.id >= parsedNextId) {
            return failLoad(
                "Mutation journal содержит id без next_id (fail closed)",
                error);
        }
    }
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (parsed[outer].id == parsed[inner].id) {
                return failLoad(
                    "Mutation journal содержит дубликат id (fail closed)",
                    error);
            }
        }
    }

    // The parsed document is proven, but readable != durable: the visible
    // file may still be the result of a rename whose parent directory fsync
    // never completed. Re-prove the exact captured snapshot against the
    // current path (an external writer may have replaced the journal since
    // the capture) and run the durability barrier BEFORE publishing anything.
    std::string durabilityError;
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            path_.string(), snapshot, &durabilityError)) {
        // Fail closed: without the proven durability of the exact parsed
        // snapshot the journal must not become operational. The previous
        // in-memory state is left untouched; health is poisoned so that no
        // operational decision (reads included) may use ambiguous provenance
        // until a successful load() or a daemon restart.
        return failLoad("Durability mutation journal не подтверждена для "
                        "прочитанного snapshot (fail closed): " +
                            durabilityError,
                        error);
    }

    records_ = std::move(parsed);
    nextId_ = parsedNextId;
    loaded_ = true;
    // The exact captured document was parsed, re-proved against the path and
    // durably confirmed: an ambiguous earlier persistence is now resolved
    // against actual persistent state, so the journal is usable again.
    health_ = JournalHealth::Healthy;
    error.clear();
    return true;
}

MutationRecord* MutationJournal::find(MutationId id) {
    for (MutationRecord& record : records_) {
        if (record.id == id) {
            return &record;
        }
    }
    return nullptr;
}

MutationJournal::PersistOutcome MutationJournal::persist(std::string& error) {
    json document;
    document["schema_version"] = kSchemaVersion;
    document["next_id"] = nextId_;
    json records = json::array();
    for (const MutationRecord& record : records_) {
        records.push_back(serializeRecord(record));
    }
    document["records"] = std::move(records);

    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.fileMode = 0600;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(path_.string(), document.dump(2) + "\n",
                                           options, &error, &result)) {
        if (!result.installed) {
            // The new document was never published by rename: the persistent
            // journal definitely still holds the previous content, so the
            // caller may safely restore the in-memory state.
            return PersistOutcome::NotInstalled;
        }
        // Post-rename durability failure: the journal target already carries
        // the new document, but the rename is not crash-durable yet. Finish
        // the durability transparently instead of reporting an ambiguous
        // failure (memory=old / disk=new must never continue as normal).
        std::string barrierError;
        if (result.installedTargetState.has_value() &&
            AtomicFileWriter::ensureTargetDurableIfCurrentState(
                path_.string(), *result.installedTargetState, &barrierError)) {
            return PersistOutcome::Persisted;
        }
        error = "Mutation journal записан (rename), но durability "
                "подтвердить не удалось; journal переведён в состояние "
                "Indeterminate (fail closed до успешного reload): " +
                barrierError;
        return PersistOutcome::Indeterminate;
    }
    return PersistOutcome::Persisted;
}

bool MutationJournal::prepareMutation(MutationRecord record,
                                      MutationId& id,
                                      std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: результат "
                "последней persist-операции не был надёжно завершён; "
                "требуется успешный reload journal";
        return false;
    }
    if (record.policy.moduleName.empty() || record.policy.policyName.empty()) {
        error = "Mutation record требует module и policy";
        return false;
    }
    if (record.resource.empty()) {
        error = "Mutation record требует resource";
        return false;
    }

    // Idempotency: an active record for the same (policy, backend, resource)
    // is refreshed instead of duplicated (repeated apply).
    for (MutationRecord& existing : records_) {
        if (existing.isActive() &&
            existing.policy == record.policy &&
            existing.undo.backend == record.undo.backend &&
            existing.resource == record.resource) {
            const MutationRecord previous = existing;
            existing.undo = record.undo;
            existing.status = MutationStatus::Prepared;
            existing.error.clear();
            existing.updatedAtEpoch = currentEpochSeconds();
            id = existing.id;
            const PersistOutcome outcome = persist(error);
            if (outcome == PersistOutcome::Persisted) {
                return true;
            }
            if (outcome == PersistOutcome::NotInstalled) {
                // Pre-install failure: the persistent journal definitely
                // still holds the previous document, so the in-memory state
                // is safely restored (strong in-memory consistency holds).
                existing = previous;
                return false;
            }
            // Indeterminate: the new document already occupies the journal
            // target. Restoring the previous in-memory state would contradict
            // the installed document; the new state is kept and the journal
            // becomes fail closed until a successful load().
            health_ = JournalHealth::Indeterminate;
            return false;
        }
    }

    record.id = nextId_;
    record.status = MutationStatus::Prepared;
    record.error.clear();
    const std::int64_t now = currentEpochSeconds();
    record.createdAtEpoch = now;
    record.updatedAtEpoch = now;
    id = record.id;
    nextId_ += 1;
    records_.push_back(std::move(record));
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) {
        return true;
    }
    if (outcome == PersistOutcome::NotInstalled) {
        // Do not keep an unpersisted in-memory record: the caller must see the
        // failure and refuse the system mutation (fail closed). The persistent
        // journal definitely still holds the previous document.
        records_.pop_back();
        nextId_ -= 1;
        return false;
    }
    // Indeterminate: keep the new record (it matches the installed document)
    // and poison the journal.
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::setStatus(MutationId id, MutationStatus status,
                                std::string& error) {
    return setStatusWithMessage(id, status, std::string(), error);
}

bool MutationJournal::setStatusWithMessage(MutationId id, MutationStatus status,
                                           const std::string& message,
                                           std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: результат "
                "последней persist-операции не был надёжно завершён; "
                "требуется успешный reload journal";
        return false;
    }
    MutationRecord* record = find(id);
    if (record == nullptr) {
        error = "Mutation record не найден: " + std::to_string(id);
        return false;
    }
    const MutationRecord previous = *record;
    record->status = status;
    record->error = message;
    record->updatedAtEpoch = currentEpochSeconds();
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) {
        return true;
    }
    if (outcome == PersistOutcome::NotInstalled) {
        // Pre-install persist failure: the persistent journal definitely
        // still holds the previous document, so the journal keeps its
        // pre-operation logical state and retries still see the original
        // active record (fail closed).
        *record = previous;
        return false;
    }
    // Indeterminate: the new document already occupies the journal target.
    // Keep the in-memory record identical to the installed document and fail
    // closed until a successful load() re-parses the disk.
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::discard(MutationId id, std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: результат "
                "последней persist-операции не был надёжно завершён; "
                "требуется успешный reload journal";
        return false;
    }
    for (std::size_t index = 0; index < records_.size(); ++index) {
        if (records_[index].id == id) {
            const MutationRecord removed = records_[index];
            records_.erase(records_.begin() +
                           static_cast<std::ptrdiff_t>(index));
            const PersistOutcome outcome = persist(error);
            if (outcome == PersistOutcome::Persisted) {
                return true;
            }
            if (outcome == PersistOutcome::NotInstalled) {
                // Restore the record at its original position: the journal
                // must stay logically identical (including record ordering)
                // to the state before the failed operation; the persistent
                // journal definitely still holds the previous document.
                records_.insert(records_.begin() +
                                    static_cast<std::ptrdiff_t>(index),
                                removed);
                return false;
            }
            // Indeterminate: keep the removal (it matches the installed
            // document) and fail closed until a successful load().
            health_ = JournalHealth::Indeterminate;
            return false;
        }
    }
    error = "Mutation record не найден: " + std::to_string(id);
    return false;
}

std::vector<MutationRecord> MutationJournal::activeRecords(
    const PolicyRef& policy) const {
    std::vector<MutationRecord> result;
    for (const MutationRecord& record : records_) {
        if (record.isActive() && record.policy == policy) {
            result.push_back(record);
        }
    }
    return result;
}

void MutationJournal::setLoadAfterCaptureHookForTests(
    std::function<void()> hook) {
    loadAfterCaptureHook() = std::move(hook);
}

} // namespace fic::rollback
