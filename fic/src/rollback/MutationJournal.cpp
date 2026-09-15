#include "rollback/MutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <nlohmann/json.hpp>

#include <ctime>
#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace fic::rollback {
namespace {

using nlohmann::json;

std::int64_t currentEpochSeconds() {
    return static_cast<std::int64_t>(::time(nullptr));
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
    case MutationBackend::Firewall: return "firewall";
    case MutationBackend::DeviceControl: return "device_control";
    }
    return "unknown";
}

bool mutationBackendFromString(const std::string& value, MutationBackend& backend) {
    if (value == "sysctl") { backend = MutationBackend::Sysctl; return true; }
    if (value == "sudo") { backend = MutationBackend::Sudo; return true; }
    if (value == "firewall") { backend = MutationBackend::Firewall; return true; }
    if (value == "device_control") { backend = MutationBackend::DeviceControl; return true; }
    return false;
}

std::string undoActionTypeName(const UndoAction& action) {
    if (std::holds_alternative<UndoRemoveManagedSetting>(action.payload)) {
        return "remove_managed_setting";
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

bool MutationJournal::load(std::string& error) {
    std::error_code probeError;
    const std::filesystem::file_status status =
        std::filesystem::status(path_, probeError);
    if (probeError &&
        status.type() != std::filesystem::file_type::not_found) {
        error = "Не удалось проверить наличие mutation journal " +
                path_.string() + ": " + probeError.message();
        return false;
    }
    if (status.type() == std::filesystem::file_type::not_found ||
        !std::filesystem::exists(status)) {
        // A missing journal is an empty journal: no provenance exists yet.
        records_.clear();
        nextId_ = 1;
        loaded_ = true;
        error.clear();
        return true;
    }

    std::ifstream stream(path_, std::ios::binary);
    if (!stream.is_open()) {
        // The file exists but cannot be opened: never treat permission or
        // I/O failures as an absent journal (fail closed).
        error = "Существующий mutation journal недоступен для чтения "
                "(fail closed): " + path_.string();
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        error = "Не удалось прочитать mutation journal: " + path_.string();
        return false;
    }
    const std::string content = buffer.str();
    if (content.empty()) {
        // An existing zero-byte journal is corrupted persistent security
        // state: fail closed instead of silently assuming an empty journal.
        // A valid empty journal must carry the schema document.
        error = "Mutation journal существует, но пуст (fail closed): " +
                path_.string();
        return false;
    }

    json document;
    try {
        document = json::parse(content);
    } catch (const json::exception& exception) {
        error = "Mutation journal повреждён (fail closed): " +
                std::string(exception.what());
        return false;
    }
    if (!document.is_object()) {
        error = "Mutation journal должен быть JSON-объектом (fail closed)";
        return false;
    }
    const auto schemaIt = document.find("schema_version");
    if (schemaIt == document.end() || !schemaIt->is_number_unsigned()) {
        error = "Mutation journal не содержит schema_version (fail closed)";
        return false;
    }
    if (schemaIt->get<std::uint32_t>() != kSchemaVersion) {
        error = "Неподдерживаемая schema_version mutation journal: " +
                schemaIt->dump();
        return false;
    }
    const auto nextIdIt = document.find("next_id");
    if (nextIdIt == document.end() || !nextIdIt->is_number_unsigned()) {
        error = "Mutation journal не содержит корректный next_id (fail closed)";
        return false;
    }
    const auto recordsIt = document.find("records");
    if (recordsIt == document.end() || !recordsIt->is_array()) {
        error = "Mutation journal не содержит массив records (fail closed)";
        return false;
    }

    std::vector<MutationRecord> parsed;
    parsed.reserve(recordsIt->size());
    for (const json& item : *recordsIt) {
        MutationRecord record;
        std::string recordError;
        if (!deserializeRecord(item, record, recordError)) {
            error = "Mutation journal содержит некорректную запись (fail closed): " +
                    recordError;
            return false;
        }
        parsed.push_back(std::move(record));
    }

    const MutationId parsedNextId = nextIdIt->get<MutationId>();
    for (const MutationRecord& record : parsed) {
        if (record.id >= parsedNextId) {
            error = "Mutation journal содержит id без next_id (fail closed)";
            return false;
        }
    }
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (parsed[outer].id == parsed[inner].id) {
                error = "Mutation journal содержит дубликат id (fail closed)";
                return false;
            }
        }
    }

    records_ = std::move(parsed);
    nextId_ = parsedNextId;
    loaded_ = true;
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

bool MutationJournal::persist(std::string& error) {
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
    return AtomicFileWriter::write(path_.string(), document.dump(2) + "\n",
                                   options, &error);
}

bool MutationJournal::prepareMutation(MutationRecord record,
                                      MutationId& id,
                                      std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
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
            if (!persist(error)) {
                // Strong in-memory consistency: the observable journal state
                // must stay logically identical to the pre-operation state.
                existing = previous;
                return false;
            }
            return true;
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
    if (!persist(error)) {
        // Do not keep an unpersisted in-memory record: the caller must see the
        // failure and refuse the system mutation (fail closed).
        records_.pop_back();
        nextId_ -= 1;
        return false;
    }
    return true;
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
    MutationRecord* record = find(id);
    if (record == nullptr) {
        error = "Mutation record не найден: " + std::to_string(id);
        return false;
    }
    const MutationRecord previous = *record;
    record->status = status;
    record->error = message;
    record->updatedAtEpoch = currentEpochSeconds();
    if (!persist(error)) {
        // Strong in-memory consistency: on persist failure the journal keeps
        // its pre-operation logical state, so retries still see the original
        // active record (fail closed).
        *record = previous;
        return false;
    }
    return true;
}

bool MutationJournal::discard(MutationId id, std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    for (std::size_t index = 0; index < records_.size(); ++index) {
        if (records_[index].id == id) {
            const MutationRecord removed = records_[index];
            records_.erase(records_.begin() +
                           static_cast<std::ptrdiff_t>(index));
            if (!persist(error)) {
                // Restore the record at its original position: the journal
                // must stay logically identical (including record ordering)
                // to the state before the failed operation.
                records_.insert(records_.begin() +
                                    static_cast<std::ptrdiff_t>(index),
                                removed);
                return false;
            }
            return true;
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

} // namespace fic::rollback
