#include "rollback/MutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <modules/oss/grub/GrubManagedBlock.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
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

// Test-only seam storage (see setLoadAfterCaptureHookForTests(),
// setBeforeVirginJournalInstallHookForTests() and
// setBeforeFinalJournalProofHookForTests()).
std::function<void()>& loadAfterCaptureHook() {
    static std::function<void()> hook;
    return hook;
}

std::function<void()>& beforeVirginJournalInstallHook() {
    static std::function<void()> hook;
    return hook;
}

std::function<void()>& beforeFinalJournalProofHook() {
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
    } else if (const auto* sshPolicy =
                   std::get_if<UndoRemoveSshManagedPolicy>(&action.payload)) {
        value["policy"] = sshPolicy->policyName;
        value["directive"] = sshPolicy->directive;
        value["applied_value"] = sshPolicy->appliedValue;
        json disabledIds = json::array();
        for (const std::string& id : sshPolicy->disabledMutationIds) {
            disabledIds.push_back(id);
        }
        value["disabled_mutation_ids"] = std::move(disabledIds);
    } else if (const auto* firewallPolicy =
                   std::get_if<UndoRemoveFirewallPolicy>(&action.payload)) {
        value["policy"] = firewallPolicy->policyName;
    } else if (const auto* feature =
                   std::get_if<UndoDisableDeviceFeature>(&action.payload)) {
        value["feature"] = feature->feature;
    } else if (const auto* dacBaseline =
                   std::get_if<UndoApplyDacPlatformBaseline>(&action.payload)) {
        value["policy"] = dacBaseline->policyName;
    } else if (const auto* grubSetting =
                   std::get_if<UndoRemoveGrubManagedSetting>(&action.payload)) {
        value["key"] = grubSetting->key;
        value["applied_value"] = grubSetting->appliedValue;
    } else if (const auto* sssdSetting = std::get_if<
                   UndoRemoveSssdManagedSetting>(&action.payload)) {
        value["section"] = sssdSetting->section;
        value["option"] = sssdSetting->option;
        value["applied_value"] = sssdSetting->appliedValue;
    } else if (const auto* kerberosScalar = std::get_if<
                   UndoRestoreKerberosScalar>(&action.payload)) {
        value["section"] = kerberosScalar->section;
        value["relation"] = kerberosScalar->relation;
        value["applied_value"] = kerberosScalar->appliedValue;
        value["before_kind"] = kerberosScalar->beforeKind ==
                KerberosBeforeKind::Present
            ? "present"
            : "missing";
        value["before_raw_line"] = kerberosScalar->beforeRawLine;
        value["section_existed_before"] = kerberosScalar->sectionExistedBefore;
    }
    return value;
}

// Shared GRUB undo-payload validation. Used by BOTH the write path
// (MutationJournal::prepareMutation) and the read path
// (deserializeUndoAction) so that the writer can never persist a record
// the loader would reject. An empty appliedValue is VALID: an applied
// policy value of "" (e.g. grub_cmdline_linux="") is a legitimate
// durable state. Only the managed-key identity and the absence of
// CR, LF and NUL in the applied value are enforced.
bool validateGrubUndoPayload(const UndoRemoveGrubManagedSetting& payload,
                             std::string& error) {
    if (payload.key.empty()) {
        error = "remove_grub_managed_setting undo requires a managed key";
        return false;
    }
    if (!isGrubManagedKey(payload.key)) {
        error = "remove_grub_managed_setting undo requires a FIC "
                "supported GRUB key, got: " +
            payload.key;
        return false;
    }
    if (payload.appliedValue.find_first_of("\r\n") != std::string::npos ||
        payload.appliedValue.find('\0') != std::string::npos) {
        error = "remove_grub_managed_setting undo applied value must not "
                "contain CR, LF or NUL";
        return false;
    }
    return true;
}

// Shared SSSD undo-payload validation. Used by BOTH the write path
// (MutationJournal::prepareMutation) and the read path
// (deserializeUndoAction) so that the writer can never persist a record
// the loader would reject. Section/option follow the SSSD configuration
// syntax rules; the applied value must be free of CR, LF and NUL.
bool validateSssdUndoPayload(const UndoRemoveSssdManagedSetting& payload,
                             std::string& error) {
    if (payload.section.empty() ||
        payload.section.find_first_of("[]\r\n") != std::string::npos) {
        error = "remove_sssd_managed_setting undo requires a valid SSSD "
                "section";
        return false;
    }
    const auto validOptionCharacter = [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '_' ||
            character == '-';
    };
    if (payload.option.empty() ||
        !std::all_of(payload.option.begin(), payload.option.end(),
                     validOptionCharacter)) {
        error = "remove_sssd_managed_setting undo requires a valid SSSD "
                "option name";
        return false;
    }
    if (payload.appliedValue.find_first_of("\r\n") != std::string::npos ||
        payload.appliedValue.find('\0') != std::string::npos) {
        error = "remove_sssd_managed_setting undo applied value must not "
                "contain CR, LF or NUL";
        return false;
    }
    return true;
}

bool validKerberosSectionName(const std::string& section) {
    return !section.empty() &&
        section.find_first_of("[]*#;\r\n") == std::string::npos;
}

bool validKerberosRelationName(const std::string& relation) {
    return !relation.empty() &&
        relation.find_first_of("=*#;[]\r\n{} \t") == std::string::npos;
}

bool lineFreeOfControlCharacters(const std::string& line) {
    return line.find_first_of("\r\n") == std::string::npos &&
        line.find('\0') == std::string::npos;
}

// Shared Kerberos undo-payload validation (write + read parity). The exact
// raw before line is required for Present and forbidden for Missing; the
// sectionExistedBefore flag must agree with the before kind.
bool validateKerberosUndoPayload(const UndoRestoreKerberosScalar& payload,
                                 std::string& error) {
    if (!validKerberosSectionName(payload.section)) {
        error = "restore_kerberos_scalar undo requires a valid Kerberos "
                "section";
        return false;
    }
    if (!validKerberosRelationName(payload.relation)) {
        error = "restore_kerberos_scalar undo requires a valid Kerberos "
                "relation name";
        return false;
    }
    if (payload.appliedValue.empty() ||
        !lineFreeOfControlCharacters(payload.appliedValue)) {
        error = "restore_kerberos_scalar undo requires a non-empty applied "
                "value without CR, LF or NUL";
        return false;
    }
    if (payload.beforeKind == KerberosBeforeKind::Present) {
        if (payload.beforeRawLine.empty() ||
            !lineFreeOfControlCharacters(payload.beforeRawLine)) {
            error = "restore_kerberos_scalar undo requires a non-empty raw "
                    "before line without CR, LF or NUL";
            return false;
        }
        if (!payload.sectionExistedBefore) {
            error = "restore_kerberos_scalar undo with a present relation "
                    "requires sectionExistedBefore";
            return false;
        }
    } else if (!payload.beforeRawLine.empty()) {
        error = "restore_kerberos_scalar undo with a missing relation must "
                "not carry a raw before line";
        return false;
    }
    return true;
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
    if (actionName == "remove_ssh_managed_policy" &&
        backend == MutationBackend::Ssh) {
        // The legacy reverse-mutation SSH payload (restore_ssh_directive) is
        // intentionally not migrated: such records fail closed as unknown
        // actions and must be resolved manually.
        UndoRemoveSshManagedPolicy payload;
        payload.policyName = value.value("policy", "");
        payload.directive = value.value("directive", "");
        payload.appliedValue = value.value("applied_value", "");
        if (payload.policyName.empty() || payload.directive.empty() ||
            payload.appliedValue.empty()) {
            error = "remove_ssh_managed_policy undo requires a policy, a "
                    "directive and an applied value";
            return false;
        }
        const auto disabledIt = value.find("disabled_mutation_ids");
        if (disabledIt != value.end()) {
            if (!disabledIt->is_array()) {
                error = "disabled_mutation_ids must be an array";
                return false;
            }
            for (const json& item : *disabledIt) {
                if (!item.is_string() || item.get<std::string>().empty()) {
                    error = "disabled mutation ids must be non-empty strings";
                    return false;
                }
                payload.disabledMutationIds.push_back(item.get<std::string>());
            }
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
    if (actionName == "apply_dac_platform_baseline" &&
        backend == MutationBackend::Dac) {
        // The payload carries policy identity only: baseline metadata is
        // read from the platform profile at rollback time, never from the
        // journal.
        UndoApplyDacPlatformBaseline payload;
        payload.policyName = value.value("policy", "");
        if (payload.policyName.empty()) {
            error = "apply_dac_platform_baseline undo requires a policy";
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_grub_managed_setting" &&
        backend == MutationBackend::Grub) {
        UndoRemoveGrubManagedSetting payload;
        payload.key = value.value("key", "");
        // Fail-closed STRUCTURAL parsing of applied_value: the field MUST
        // be present and MUST be a JSON string. An empty string is a VALID
        // value (e.g. grub_cmdline_linux=""), but a MISSING or non-string
        // applied_value is malformed provenance: it must never silently
        // deserialize as "" and must never escape as an uncaught JSON type
        // error. Semantic constraints (managed-key whitelist, CR/LF/NUL)
        // stay in validateGrubUndoPayload below.
        const auto appliedIt = value.find("applied_value");
        if (appliedIt == value.end() || !appliedIt->is_string()) {
            error = "remove_grub_managed_setting undo requires a string "
                    "applied_value (an empty string is valid)";
            return false;
        }
        payload.appliedValue = appliedIt->get<std::string>();
        if (!validateGrubUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_sssd_managed_setting" &&
        backend == MutationBackend::Sssd) {
        UndoRemoveSssdManagedSetting payload;
        payload.section = value.value("section", "");
        payload.option = value.value("option", "");
        // Structural parsing: applied_value MUST be present and a JSON
        // string (missing/non-string/null is malformed provenance).
        const auto appliedIt = value.find("applied_value");
        if (appliedIt == value.end() || !appliedIt->is_string()) {
            error = "remove_sssd_managed_setting undo requires a string "
                    "applied_value";
            return false;
        }
        payload.appliedValue = appliedIt->get<std::string>();
        if (!validateSssdUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "restore_kerberos_scalar" &&
        backend == MutationBackend::Kerberos) {
        UndoRestoreKerberosScalar payload;
        payload.section = value.value("section", "");
        payload.relation = value.value("relation", "");
        const auto appliedIt = value.find("applied_value");
        if (appliedIt == value.end() || !appliedIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string "
                    "applied_value";
            return false;
        }
        payload.appliedValue = appliedIt->get<std::string>();
        const auto beforeKindIt = value.find("before_kind");
        if (beforeKindIt == value.end() || !beforeKindIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string "
                    "before_kind";
            return false;
        }
        if (*beforeKindIt == "present") {
            payload.beforeKind = KerberosBeforeKind::Present;
        } else if (*beforeKindIt == "missing") {
            payload.beforeKind = KerberosBeforeKind::Missing;
        } else {
            error = "restore_kerberos_scalar undo has unknown before_kind: " +
                beforeKindIt->get<std::string>();
            return false;
        }
        const auto rawLineIt = value.find("before_raw_line");
        if (rawLineIt == value.end() || !rawLineIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string "
                    "before_raw_line";
            return false;
        }
        payload.beforeRawLine = rawLineIt->get<std::string>();
        const auto sectionExistedIt = value.find("section_existed_before");
        if (sectionExistedIt == value.end() ||
            !sectionExistedIt->is_boolean()) {
            error = "restore_kerberos_scalar undo requires a boolean "
                    "section_existed_before";
            return false;
        }
        payload.sectionExistedBefore = sectionExistedIt->get<bool>();
        if (!validateKerberosUndoPayload(payload, error)) {
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
    // Cross-field consistency: for GRUB the record identity carries the
    // managed key. record.resource MUST equal UndoRemoveGrubManagedSetting
    // .key — a disagreement means malformed provenance, which must never
    // reach apply-time repair reuse (fail closed at load, not at apply).
    if (record.undo.backend == MutationBackend::Grub) {
        const auto* grub =
            std::get_if<UndoRemoveGrubManagedSetting>(&record.undo.payload);
        if (grub == nullptr || grub->key != record.resource) {
            error = "GRUB journal resource does not match undo key: "
                    "resource '" +
                record.resource + "'";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Sssd) {
        const auto* sssd =
            std::get_if<UndoRemoveSssdManagedSetting>(&record.undo.payload);
        if (sssd == nullptr ||
            sssd->section + "/" + sssd->option != record.resource) {
            error = "SSSD journal resource does not match undo "
                    "section/option: resource '" +
                record.resource + "'";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Kerberos) {
        const auto* kerberos =
            std::get_if<UndoRestoreKerberosScalar>(&record.undo.payload);
        if (kerberos == nullptr ||
            kerberos->section + "/" + kerberos->relation != record.resource) {
            error = "Kerberos journal resource does not match undo "
                    "section/relation: resource '" +
                record.resource + "'";
            return false;
        }
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
    case MutationBackend::Dac: return "dac";
    case MutationBackend::Grub: return "grub";
    case MutationBackend::Sssd: return "sssd";
    case MutationBackend::Kerberos: return "kerberos";
    }
    return "unknown";
}

bool mutationBackendFromString(const std::string& value, MutationBackend& backend) {
    if (value == "sysctl") { backend = MutationBackend::Sysctl; return true; }
    if (value == "sudo") { backend = MutationBackend::Sudo; return true; }
    if (value == "ssh") { backend = MutationBackend::Ssh; return true; }
    if (value == "firewall") { backend = MutationBackend::Firewall; return true; }
    if (value == "device_control") { backend = MutationBackend::DeviceControl; return true; }
    if (value == "dac") { backend = MutationBackend::Dac; return true; }
    if (value == "grub") { backend = MutationBackend::Grub; return true; }
    if (value == "sssd") { backend = MutationBackend::Sssd; return true; }
    if (value == "kerberos") { backend = MutationBackend::Kerberos; return true; }
    return false;
}

std::string undoActionTypeName(const UndoAction& action) {
    if (std::holds_alternative<UndoRemoveManagedSetting>(action.payload)) {
        return "remove_managed_setting";
    }
    if (std::holds_alternative<UndoRemoveSshManagedPolicy>(action.payload)) {
        return "remove_ssh_managed_policy";
    }
    if (std::holds_alternative<UndoRemoveFirewallPolicy>(action.payload)) {
        return "remove_firewall_policy";
    }
    if (std::holds_alternative<UndoDisableDeviceFeature>(action.payload)) {
        return "disable_device_feature";
    }
    if (std::holds_alternative<UndoApplyDacPlatformBaseline>(action.payload)) {
        return "apply_dac_platform_baseline";
    }
    if (std::holds_alternative<UndoRemoveGrubManagedSetting>(action.payload)) {
        return "remove_grub_managed_setting";
    }
    if (std::holds_alternative<UndoRemoveSssdManagedSetting>(action.payload)) {
        return "remove_sssd_managed_setting";
    }
    if (std::holds_alternative<UndoRestoreKerberosScalar>(action.payload)) {
        return "restore_kerberos_scalar";
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

std::filesystem::path MutationJournal::witnessPath() const {
    return path_.string() + ".initialized";
}

bool MutationJournal::witnessIsValid(std::string& error) {
    // A valid witness requires an exact versioned document captured through
    // a regular-file descriptor (symlinks and other non-regular objects are
    // refused) AND a state-bound durability barrier: visible != durable.
    AtomicTargetState snapshot;
    std::string captureError;
    if (!AtomicFileWriter::captureTargetState(witnessPath().string(),
                                              snapshot, &captureError)) {
        error = "Initialization witness недоступен/некорректен (fail closed): " +
                captureError;
        return false;
    }
    json document;
    try {
        document = json::parse(snapshot.content);
    } catch (const json::exception& exception) {
        error = "Initialization witness повреждён (fail closed): " +
                std::string(exception.what());
        return false;
    }
    if (!document.is_object() || document.size() != 2 ||
        document.find("schema_version") == document.end() ||
        document.find("initialized") == document.end() ||
        !document["schema_version"].is_number_unsigned() ||
        document["schema_version"].get<std::uint32_t>() !=
            kWitnessSchemaVersion ||
        document["initialized"] != true) {
        error = "Initialization witness имеет неожиданное содержимое "
                "(fail closed): " +
                witnessPath().string();
        return false;
    }
    std::string durabilityError;
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            witnessPath().string(), snapshot, &durabilityError)) {
        error = "Durability initialization witness не подтверждена "
                "(fail closed): " +
                durabilityError;
        return false;
    }
    return true;
}

bool MutationJournal::createWitness(std::string& error) {
    json document;
    document["schema_version"] = kWitnessSchemaVersion;
    document["initialized"] = true;
    AtomicWriteOptions options;
    // Exclusive create: never silently replace a foreign object occupying
    // the witness path (a directory, a symlink, a malformed file, or a
    // concurrently created witness).
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.exclusiveCreate = true;
    options.fileMode = 0600;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(witnessPath().string(),
                                           document.dump(2) + "\n", options,
                                           &error, &result)) {
        if (!result.installed) {
            // Not installed: either a race (another process created the
            // witness between the existence check and the commit) or a real
            // creation failure. Accept only a valid durable witness.
            std::string witnessError;
            if (witnessIsValid(witnessError)) {
                error.clear();
                return true;
            }
            error = "Не удалось создать initialization witness (fail closed): " +
                    error + "; " + witnessError;
            return false;
        }
        // installed != durable: the rename published the witness but the
        // parent directory fsync failed. Finish the durability transparently
        // against the exact installed state; otherwise fail closed — the
        // next startup will take the migration path (J exists + W missing).
        std::string barrierError;
        if (result.installedTargetState.has_value() &&
            AtomicFileWriter::ensureTargetDurableIfCurrentState(
                witnessPath().string(), *result.installedTargetState,
                &barrierError)) {
            error.clear();
            return true;
        }
        error = "Initialization witness записан (rename), но durability "
                "подтвердить не удалось (fail closed): " +
                barrierError;
        return false;
    }
    return true;
}

bool MutationJournal::initializeOrLoad(std::string& error) {
    if (lifecycleInitialized_) {
        // Completed witness-aware lifecycle: strict live reload. After the
        // persistent initialization the disappearance of the journal is
        // NEVER a valid empty bootstrap (follow-up 6/7 semantics) — a raw
        // reload must not bypass the persistent witness state.
        return loadExisting(error);
    }
    return initializeFresh(error);
}

bool MutationJournal::initializeFresh(std::string& error) {
    // Bounded witness-aware state table. An exclusive-create conflict means
    // another FIC instance created the journal concurrently: the state table
    // is re-classified (the file is NEVER replaced). A hostile writer racing
    // forever cannot be served forever either — after the bounded number of
    // passes the initialization fails closed with explicit diagnostics.
    constexpr int kMaxStateTablePasses = 3;
    for (int pass = 0; pass < kMaxStateTablePasses; ++pass) {
        // Persistent (journal, witness) presence probe.
        std::error_code journalProbeError;
        const std::filesystem::file_status journalStatus =
            std::filesystem::status(path_, journalProbeError);
        if (journalProbeError &&
            journalStatus.type() != std::filesystem::file_type::not_found) {
            return failLoad("Не удалось проверить наличие mutation journal " +
                                path_.string() + ": " +
                                journalProbeError.message(),
                            error);
        }
        const bool journalMissing =
            journalStatus.type() == std::filesystem::file_type::not_found ||
            !std::filesystem::exists(journalStatus);

        std::error_code witnessProbeError;
        const std::filesystem::file_status witnessStatus =
            std::filesystem::status(witnessPath(), witnessProbeError);
        if (witnessProbeError &&
            witnessStatus.type() != std::filesystem::file_type::not_found) {
            return failLoad("Не удалось проверить наличие initialization "
                            "witness " +
                                witnessPath().string() + ": " +
                                witnessProbeError.message(),
                            error);
        }
        const bool witnessMissing =
            witnessStatus.type() == std::filesystem::file_type::not_found ||
            !std::filesystem::exists(witnessStatus);

        if (journalMissing) {
            if (witnessMissing) {
                switch (bootstrapVirgin(error)) {
                    case BootstrapOutcome::Installed:
                        return true;
                    case BootstrapOutcome::ConflictJournalExists:
                        // Another instance created the journal between the
                        // probe and the exclusive install. Never assume it
                        // is our empty journal: re-evaluate the persistent
                        // state table (bounded); the journal will be loaded
                        // and validated through the normal strict rules.
                        continue;
                    case BootstrapOutcome::Failed:
                        return false;
                }
            }
            // Witness present (valid or not) while the journal is missing. A
            // valid witness means the journal lifecycle was initialized
            // before: its disappearance is provenance loss, never a virgin
            // bootstrap. An invalid witness is a persistent-state anomaly.
            // Neither may be healed automatically.
            std::string witnessError;
            if (witnessIsValid(witnessError)) {
                return failLoad(
                    "Mutation journal is missing although its persistent "
                    "initialization witness exists; rollback provenance may "
                    "have been lost; manual provenance recovery is required: " +
                        path_.string(),
                    error);
            }
            return failLoad("Persistent-state anomaly: mutation journal "
                            "отсутствует, initialization witness некорректен "
                            "(fail closed): " +
                                witnessError,
                            error);
        }
        return initializeExistingJournal(witnessMissing, error);
    }
    return failLoad("Witness-aware initialization не завершилась после "
                    "ограниченного числа попыток разрешения concurrent "
                    "bootstrap race (fail closed): " +
                        path_.string(),
                    error);
}

bool MutationJournal::initializeExistingJournal(bool witnessMissing,
                                                std::string& error) {
    // Journal exists: strict load only — a vanished journal inside this
    // transaction must never heal into an empty journal.
    if (witnessMissing) {
        // Migration / interrupted bootstrap:
        //   loadExisting J → create/prove W → FINAL loadExisting proof J
        // The lifecycle becomes initialized only after BOTH persistent
        // objects were proven within the same transaction.
        if (!loadExisting(error)) {
            return false;
        }
        if (!createWitness(error)) {
            // lifecycleInitialized_ stays false: the witness-aware
            // initialization did NOT complete. A retry on this object
            // re-runs the witness-aware state table (never a raw reload
            // that would bypass the witness).
            return failLoad("Не удалось создать initialization witness "
                            "после успешной proof journal (fail closed): " +
                                error,
                            error);
        }
        if (beforeFinalJournalProofHook()) {
            beforeFinalJournalProofHook()();
        }
        // Final re-proof: between the first proof and the witness creation
        // the journal may have disappeared or been replaced. This is not a
        // filesystem transaction — the known residual re-proof→fsync TOCTOU
        // after this point remains.
        if (!loadExisting(error)) {
            return false;
        }
        lifecycleInitialized_ = true;
        error.clear();
        return true;
    }
    std::string witnessError;
    if (!witnessIsValid(witnessError)) {
        return failLoad("Persistent-state anomaly: mutation journal "
                        "корректен, но initialization witness некорректен "
                        "(fail closed): " +
                            witnessError,
                        error);
    }
    // Normal startup: prove both persistent objects, then publish the
    // operational lifecycle state.
    if (!loadExisting(error)) {
        return false;
    }
    lifecycleInitialized_ = true;
    error.clear();
    return true;
}

MutationJournal::BootstrapOutcome MutationJournal::bootstrapVirgin(
    std::string& error) {
    // Virgin bootstrap: create a real schema-valid empty journal FIRST with
    // NO-REPLACE semantics (journal-before-witness ordering keeps a crash
    // between the two phases recoverable through the migration path).
    // Invariant: bootstrap code NEVER replaces an existing journal — a
    // concurrent instance's journal (already carrying provenance records)
    // must not be destroyable by our empty temp document.
    json document;
    document["schema_version"] = kSchemaVersion;
    document["next_id"] = 1;
    document["records"] = json::array();
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    // Exclusive install: no-replace semantics — the commit fails if any
    // object occupies the target at commit time.
    options.exclusiveCreate = true;
    options.fileMode = 0600;
    // Copy before invoking: the hook may reassign/clear the slot while it
    // runs; destroying the executing std::function would be UB.
    if (auto hook = beforeVirginJournalInstallHook()) {
        hook();
    }
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(path_.string(),
                                           document.dump(2) + "\n", options,
                                           &error, &result)) {
        if (!result.installed) {
            // Distinguish "target appeared due to the bootstrap race" from a
            // real filesystem failure by re-probing the path (never by errno
            // text).
            std::error_code probeError;
            const std::filesystem::file_status status =
                std::filesystem::status(path_, probeError);
            if (!probeError && std::filesystem::exists(status)) {
                // Another instance won the bootstrap race for the journal.
                // NEVER assume it is our empty journal: re-classify through
                // the state table (the journal will be loaded and validated
                // through the normal strict regular-file rules; a symlink or
                // another non-regular object fails closed there).
                return BootstrapOutcome::ConflictJournalExists;
            }
            // Not installed, target absent: nothing was published and the
            // witness was not created; the next startup retries the
            // bootstrap.
            failLoad("Не удалось создать пустой mutation journal "
                     "(fail closed): " +
                         error,
                     error);
            return BootstrapOutcome::Failed;
        }
        // installed != durable: the rename published the empty journal but
        // the parent directory fsync failed. Finish the durability
        // transparently against the exact installed state; otherwise fail
        // closed — the next startup sees J exists + W missing and takes the
        // migration path.
        std::string barrierError;
        if (!(result.installedTargetState.has_value() &&
              AtomicFileWriter::ensureTargetDurableIfCurrentState(
                  path_.string(), *result.installedTargetState,
                  &barrierError))) {
            failLoad("Пустой mutation journal записан (rename), но durability "
                     "подтвердить не удалось (fail closed): " +
                         barrierError,
                     error);
            return BootstrapOutcome::Failed;
        }
        error.clear();
    }
    if (!createWitness(error)) {
        failLoad("Не удалось создать initialization witness "
                 "(fail closed): " +
                     error,
                 error);
        return BootstrapOutcome::Failed;
    }
    // Copy before invoking: the hook may reassign/clear the slot while it
    // runs; destroying the executing std::function would be UB.
    if (auto hook = beforeFinalJournalProofHook()) {
        hook();
    }
    // Final strict proof of the freshly created pair: if the journal
    // disappeared after the witness was created, this fails closed —
    // critically NOT into an empty Healthy journal.
    if (!loadExisting(error)) {
        return BootstrapOutcome::Failed;
    }
    lifecycleInitialized_ = true;
    return BootstrapOutcome::Installed;
}

bool MutationJournal::load(std::string& error) {
    // Raw primitive: legacy bootstrap semantics (see the header comment).
    return loadImpl(MissingJournalPolicy::AllowFreshEmpty, error);
}

bool MutationJournal::loadExisting(std::string& error) {
    // Strict primitive: the journal is required to exist — a missing file is
    // ALWAYS an error here, never an empty bootstrap.
    return loadImpl(MissingJournalPolicy::RequireExisting, error);
}

bool MutationJournal::loadImpl(MissingJournalPolicy policy,
                               std::string& error) {
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
        // A missing journal is an empty journal ONLY for the raw legacy
        // primitive (AllowFreshEmpty) during the initial bootstrap of a
        // never-loaded journal object. The disappearance of a previously
        // known journal (loaded, or already Indeterminate) — and ANY missing
        // journal under the strict witness-aware policy — does not prove
        // that the earlier ambiguous provenance safely vanished: it must
        // fail closed instead of healing into an empty Healthy journal.
        const bool bootstrapMissing =
            policy == MissingJournalPolicy::AllowFreshEmpty &&
            !loaded_ && health_ == JournalHealth::Healthy;
        if (bootstrapMissing) {
            records_.clear();
            nextId_ = 1;
            loaded_ = true;
            error.clear();
            return true;
        }
        if (policy == MissingJournalPolicy::RequireExisting) {
            return failLoad("Mutation journal is missing (strict "
                            "existing-journal load); provenance cannot be "
                            "treated as empty: " +
                                path_.string(),
                            error);
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
    // At most one ACTIVE record may exist for one logical mutation identity
    // (policy, backend, resource): prepareMutation() idempotent refresh and
    // all repair reuse paths rely on this invariant for unambiguous
    // provenance. Two simultaneously active records for one identity mean
    // ambiguous provenance — fail closed at load. Historical resolved
    // records (RolledBack / Detached) NEVER conflict with an active record:
    // mutation history must be preserved.
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        if (!parsed[outer].isActive()) {
            continue;
        }
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (!parsed[inner].isActive()) {
                continue;
            }
            if (parsed[outer].policy == parsed[inner].policy &&
                parsed[outer].undo.backend == parsed[inner].undo.backend &&
                parsed[outer].resource == parsed[inner].resource) {
                return failLoad(
                    "Mutation journal содержит несколько активных записей "
                    "одного logical mutation identity (policy, backend, "
                    "resource): '" +
                        parsed[outer].resource + "' (fail closed)",
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
    // Record consistency before ANY refresh/insert: for GRUB the logical
    // identity carries the managed key, so the payload MUST agree with it
    // (record.resource == undo.key). The payload itself must satisfy the
    // SAME rules the loader enforces (see validateGrubUndoPayload): the
    // writer must never persist a record the loader would reject. An
    // empty appliedValue is valid (applied policy value "" is legitimate).
    // A malformed record is never silently refreshed or persisted — fail
    // closed. Other backends keep their existing semantics unchanged.
    if (record.undo.backend == MutationBackend::Grub) {
        const auto* grub =
            std::get_if<UndoRemoveGrubManagedSetting>(&record.undo.payload);
        if (grub == nullptr || grub->key != record.resource) {
            error = "GRUB mutation record требует undo key == resource ('" +
                record.resource + "'): "
                "payload не согласован с identity (fail closed)";
            return false;
        }
        if (!validateGrubUndoPayload(*grub, error)) {
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Sssd) {
        const auto* sssd =
            std::get_if<UndoRemoveSssdManagedSetting>(&record.undo.payload);
        const std::string expectedResource =
            sssd == nullptr ? std::string() : sssd->section + "/" + sssd->option;
        if (sssd == nullptr || expectedResource != record.resource) {
            error = "SSSD mutation record требует resource "
                    "'<section>/<option>', согласованный с undo payload ('" +
                record.resource + "'): payload не согласован с identity "
                "(fail closed)";
            return false;
        }
        if (!validateSssdUndoPayload(*sssd, error)) {
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Kerberos) {
        const auto* kerberos =
            std::get_if<UndoRestoreKerberosScalar>(&record.undo.payload);
        const std::string expectedResource =
            kerberos == nullptr
                ? std::string()
                : kerberos->section + "/" + kerberos->relation;
        if (kerberos == nullptr || expectedResource != record.resource) {
            error = "Kerberos mutation record требует resource "
                    "'<section>/<relation>', согласованный с undo payload ('" +
                record.resource + "'): payload не согласован с identity "
                "(fail closed)";
            return false;
        }
        if (!validateKerberosUndoPayload(*kerberos, error)) {
            return false;
        }
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

void MutationJournal::setBeforeVirginJournalInstallHookForTests(
    std::function<void()> hook) {
    beforeVirginJournalInstallHook() = std::move(hook);
}

void MutationJournal::setBeforeFinalJournalProofHookForTests(
    std::function<void()> hook) {
    beforeFinalJournalProofHook() = std::move(hook);
}

} // namespace fic::rollback
