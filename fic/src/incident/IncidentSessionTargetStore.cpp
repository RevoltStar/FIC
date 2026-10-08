#include "incident/IncidentSessionTargetStore.h"

#include "incident/IncidentStateStore.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/FileStats.h>
#include <fic/core/fs/SecureStateFile.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>
#include <optional>

namespace fic::incident {
namespace {

using ::AtomicWriteOptions;
using ::AtomicWriteResult;
using ::FileMetadataPolicy;
using ::fic::core::SecureStateReadResult;
using ::fic::core::SecureStateReadStatus;
using json = nlohmann::json;

// Bound both serialized writes and secure reads; long escaped strings can
// exceed a simple target-count estimate.
constexpr std::uintmax_t kStoreMaxBytes = 64 * 1024;
constexpr std::size_t kMaxTargets = 256;
constexpr std::uint64_t kStoreSchemaVersion = 2;

bool validBootId(const std::string& value) {
    if (value.size() != 36) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f') ||
                     (value[i] >= 'A' && value[i] <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool selectableClass(const std::string& value) {
    return value == "user" || value == "user-early" ||
           value == "user-light" || value == "user-early-light";
}

bool validTarget(const IncidentSessionTarget& target) {
    return target.uid != 0 && !target.canonicalName.empty() &&
           target.canonicalName.size() <= 256 && !target.sessionId.empty() &&
           target.sessionId.size() <= 256 && target.sessionStartTimestamp != 0 &&
           selectableClass(target.sessionClass) &&
           (target.runtimeObligation ==
                IncidentSessionTarget::RuntimeObligation::Pending ||
            target.runtimeObligation ==
                IncidentSessionTarget::RuntimeObligation::Discharged);
}

std::optional<uid_t>& expectedStoreOwner() {
    static std::optional<uid_t> owner = 0;
    return owner;
}
std::optional<uid_t>& expectedStoreParentOwner() {
    static std::optional<uid_t> owner = 0;
    return owner;
}
bool& storeIdentityOverride() {
    static bool override_ = false;
    return override_;
}

std::string serialize(const std::string& bootId,
                      std::uint64_t generation,
                      const std::vector<IncidentSessionTarget>& targets) {
    json targetsJson = json::array();
    for (const IncidentSessionTarget& target : targets) {
        targetsJson.push_back({
            {"uid", target.uid},
            {"name", target.canonicalName},
            {"session_id", target.sessionId},
            {"session_start", target.sessionStartTimestamp},
            {"session_class", target.sessionClass},
            {"runtime_obligation",
             target.runtimeObligation ==
                     IncidentSessionTarget::RuntimeObligation::Discharged
                 ? "discharged"
                 : "pending"},
        });
    }
    const json document = {
        {"schema_version", kStoreSchemaVersion},
        {"lifecycle_marker", "fenced_before_severity"},
        {"boot_id", bootId},
        {"incident_generation", generation},
        {"targets", targetsJson},
    };
    return document.dump();
}

struct ParsedTargets {
    bool ok = false;
    std::string bootId;
    std::uint64_t generation = 0;
    std::vector<IncidentSessionTarget> targets;
};

ParsedTargets parse(const std::string& content) {
    ParsedTargets parsed;
    if (content.size() > kStoreMaxBytes) return parsed;
    try {
        json document = json::parse(content, nullptr, false);
        if (document.is_discarded() || !document.is_object() ||
            document.size() != 5) return parsed;
        const auto schema = document.find("schema_version");
        const auto marker = document.find("lifecycle_marker");
        const auto boot = document.find("boot_id");
        const auto generation = document.find("incident_generation");
        const auto targets = document.find("targets");
        if (schema == document.end() || !schema->is_number_unsigned() ||
            schema->get<std::uint64_t>() != kStoreSchemaVersion ||
            marker == document.end() || !marker->is_string() ||
            marker->get<std::string>() != "fenced_before_severity" ||
            boot == document.end() || !boot->is_string() ||
            generation == document.end() || !generation->is_number_unsigned() ||
            generation->get<std::uint64_t>() == 0 ||
            targets == document.end() || !targets->is_array() ||
            targets->size() > kMaxTargets) {
            return parsed;
        }
        parsed.bootId = boot->get<std::string>();
        parsed.generation = generation->get<std::uint64_t>();
        if (!validBootId(parsed.bootId)) return parsed;
        for (const json& item : *targets) {
            if (!item.is_object() || item.size() != 6) return parsed;
            const auto uid = item.find("uid");
            const auto name = item.find("name");
            const auto sessionId = item.find("session_id");
            const auto sessionStart = item.find("session_start");
            const auto sessionClass = item.find("session_class");
            const auto obligation = item.find("runtime_obligation");
            if (uid == item.end() || !uid->is_number_unsigned() ||
                uid->get<std::uint64_t>() == 0 ||
                uid->get<std::uint64_t>() > std::numeric_limits<uid_t>::max() ||
                name == item.end() || !name->is_string() ||
                name->get<std::string>().empty() ||
                name->get<std::string>().size() > 256 ||
                sessionId == item.end() || !sessionId->is_string() ||
                sessionId->get<std::string>().empty() ||
                sessionId->get<std::string>().size() > 256 ||
                sessionStart == item.end() || !sessionStart->is_number_unsigned() ||
                sessionStart->get<std::uint64_t>() == 0 ||
                sessionClass == item.end() || !sessionClass->is_string() ||
                !selectableClass(sessionClass->get<std::string>()) ||
                obligation == item.end() || !obligation->is_string() ||
                (obligation->get<std::string>() != "pending" &&
                 obligation->get<std::string>() != "discharged")) {
                return parsed;
            }
            IncidentSessionTarget target;
            target.uid = static_cast<uid_t>(uid->get<std::uint64_t>());
            target.canonicalName = name->get<std::string>();
            target.sessionId = sessionId->get<std::string>();
            target.sessionStartTimestamp = sessionStart->get<std::uint64_t>();
            target.sessionClass = sessionClass->get<std::string>();
            target.runtimeObligation =
                obligation->get<std::string>() == "discharged"
                    ? IncidentSessionTarget::RuntimeObligation::Discharged
                    : IncidentSessionTarget::RuntimeObligation::Pending;
            parsed.targets.push_back(std::move(target));
        }
        // Duplicates would make "one obligation per user" ambiguous.
        std::vector<uid_t> seen;
        for (const IncidentSessionTarget& target : parsed.targets) {
            if (std::find(seen.begin(), seen.end(), target.uid) != seen.end())
                return parsed;
            seen.push_back(target.uid);
        }
        parsed.ok = true;
    } catch (const json::exception&) {
        return ParsedTargets{};
    }
    return parsed;
}

bool validWrite(const std::string& bootId, std::uint64_t generation,
                const std::vector<IncidentSessionTarget>& targets) {
    if (!validBootId(bootId) || generation == 0 ||
        targets.size() > kMaxTargets) return false;
    std::vector<uid_t> seen;
    for (const auto& target : targets) {
        if (!validTarget(target) ||
            std::find(seen.begin(), seen.end(), target.uid) != seen.end())
            return false;
        seen.push_back(target.uid);
    }
    return true;
}

} // namespace

IncidentSessionTargetStore::IncidentSessionTargetStore(
    std::filesystem::path lockStatusPath)
    : path_(lockStatusPath.parent_path() / "incident_session_targets") {}

IncidentSessionTargetStore IncidentSessionTargetStore::forTesting(
    std::filesystem::path path) {
    return IncidentSessionTargetStore(std::move(path), true);
}

::fic::core::SecureStateFileExpectation
IncidentSessionTargetStore::expectation() {
    ::fic::core::SecureStateFileExpectation expectation;
    expectation.owner = expectedStoreOwner();
    gid_t group = ::getegid();
    if (!storeIdentityOverride()) {
        uid_t owner = 0;
        group = static_cast<gid_t>(-1);
        ::FileStats::resolve_owner_group("root", "fic", owner, group);
    }
    expectation.group = group;
    expectation.exactMode = 0640;
    expectation.maxSize = kStoreMaxBytes;
    expectation.requireSingleLink = true;
    expectation.parentOwner = expectedStoreParentOwner();
    expectation.parentGroup = group;
    // The store lives in the same directory as lockstatus, which carries
    // 02750 in production (setgid "fic" group). Tests own their temp dir.
    expectation.exactParentMode = storeIdentityOverride() ? 0700 : 02750;
    return expectation;
}

void IncidentSessionTargetStore::setOwnershipExpectationForTests(
    std::optional<uid_t> owner, std::optional<uid_t> parentOwner) {
    expectedStoreOwner() = owner;
    expectedStoreParentOwner() = parentOwner;
    storeIdentityOverride() = owner.has_value();
}

IncidentSessionTargetStore::ReadResult IncidentSessionTargetStore::read() const {
    ReadResult result;
    const SecureStateReadResult read = ::fic::core::readSecureFileBounded(
        path_, expectation(), kStoreMaxBytes);
    if (read.status == SecureStateReadStatus::Missing) {
        // Positively proven absence. Whether absence may be trusted as
        // "no targets" is a caller decision that needs the incident state:
        // an active incident with a missing store is NOT a proven empty set.
        result.provenance = ReadProvenance::Absent;
        return result;
    }
    if (read.status != SecureStateReadStatus::Proven) {
        result.detail = read.detail.empty()
            ? "incident session target store is unprovable"
            : read.detail;
        return result;
    }
    const ParsedTargets parsed = parse(read.content);
    if (!parsed.ok) {
        result.detail = "incident session target store content is invalid";
        return result;
    }
    result.provenance = ReadProvenance::Proven;
    result.bootId = parsed.bootId;
    result.incidentGeneration = parsed.generation;
    result.targets = parsed.targets;
    result.provenState = read.targetState;
    return result;
}

IncidentSessionTargetStore::WriteResult IncidentSessionTargetStore::write(
    const std::string& bootId, std::uint64_t incidentGeneration,
    const std::vector<IncidentSessionTarget>& targets) const {
    WriteResult result;
    if (!validWrite(bootId, incidentGeneration, targets)) {
        result.detail = "incident session target store write refused";
        return result;
    }
    const std::string content = serialize(bootId, incidentGeneration, targets);
    if (content.size() > kStoreMaxBytes) {
        result.detail = "incident session target store exceeds size bound";
        return result;
    }
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0640;
    options.fileOwner = expectedStoreOwner();
    options.fileGroup = expectation().group;
    AtomicWriteResult writeResult;
    std::string error;
    const bool written = ::AtomicFileWriter::writeWithResult(
        path_.string(), content,
        options, &error, &writeResult);
    if (!writeResult.installed) {
        result.detail = error.empty()
            ? "incident session target store write failed before replacement"
            : error;
        return result;
    }
    if (written && writeResult.durabilityConfirmed) {
        result.durable = true;
        return result;
    }
    // rename(2) published the new content, but the durability barrier (parent
    // directory fsync) is not proven. Re-prove through the state-bound helper
    // so an externally replaced target can never be confirmed.
    std::string durabilityError;
    const bool durable =
        writeResult.installedTargetState.has_value() &&
        ::AtomicFileWriter::ensureTargetDurableIfCurrentState(
            path_.string(), *writeResult.installedTargetState,
            &durabilityError);
    if (!durable) {
        result.detail = durabilityError.empty()
            ? "incident session target store durability is unproven"
            : durabilityError;
        return result;
    }
    result.durable = true;
    return result;
}

IncidentSessionTargetStore::WriteResult
IncidentSessionTargetStore::writeIfCurrent(
    const ReadResult& expected, const std::string& bootId,
    std::uint64_t generation,
    const std::vector<IncidentSessionTarget>& targets) const {
    if (expected.provenance == ReadProvenance::Unprovable ||
        (expected.provenance == ReadProvenance::Proven &&
         !expected.provenState.has_value()))
        return {false, "target store predecessor is unproven"};
    if (!validWrite(bootId, generation, targets))
        return {false, "incident session target store write refused"};
    const std::string content = serialize(bootId, generation, targets);
    if (content.size() > kStoreMaxBytes)
        return {false, "incident session target store exceeds size bound"};
    AtomicWriteOptions options;
    options.createIfMissing = expected.provenance == ReadProvenance::Absent;
    options.exclusiveCreate = options.createIfMissing;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0640;
    options.fileOwner = expectedStoreOwner();
    options.fileGroup = expectation().group;
    if (expected.provenState) options.expectedTargetState = expected.provenState;
    AtomicWriteResult writeResult;
    std::string error;
    const bool written = ::AtomicFileWriter::writeWithResult(
        path_.string(), content,
        options, &error, &writeResult);
    if (!writeResult.installed)
        return {false, error.empty() ? "conditional target write failed" : error};
    if (written && writeResult.durabilityConfirmed) return {true, ""};
    std::string durabilityError;
    const bool durable = writeResult.installedTargetState.has_value() &&
        ::AtomicFileWriter::ensureTargetDurableIfCurrentState(
            path_.string(), *writeResult.installedTargetState, &durabilityError);
    return {durable, durable ? "" :
        (durabilityError.empty() ? "target durability is unproven" : durabilityError)};
}

} // namespace fic::incident
