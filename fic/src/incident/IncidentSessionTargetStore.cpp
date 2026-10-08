#include "incident/IncidentSessionTargetStore.h"

#include "incident/IncidentStateStore.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/FileStats.h>
#include <fic/core/fs/SecureStateFile.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>

namespace fic::incident {
namespace {

using ::AtomicWriteOptions;
using ::AtomicWriteResult;
using ::FileMetadataPolicy;
using ::fic::core::SecureStateReadResult;
using ::fic::core::SecureStateReadStatus;
using json = nlohmann::json;

// Bounded content: at most 256 targets x ~200 bytes of JSON. The hard read
// bound is well above that, and both bounds together make a hostile or
// corrupt file impossible to mistake for a large target set.
constexpr std::uintmax_t kStoreMaxBytes = 64 * 1024;
constexpr std::size_t kMaxTargets = 256;
constexpr std::uint64_t kStoreSchemaVersion = 1;

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
    json document = json::parse(content, nullptr, false);
    if (document.is_discarded() || !document.is_object()) return parsed;
    const auto schema = document.find("schema_version");
    const auto boot = document.find("boot_id");
    const auto generation = document.find("incident_generation");
    const auto targets = document.find("targets");
    if (schema == document.end() || !schema->is_number_integer() ||
        schema->get<std::uint64_t>() != kStoreSchemaVersion ||
        boot == document.end() || !boot->is_string() ||
        generation == document.end() || !generation->is_number_unsigned() ||
        targets == document.end() || !targets->is_array() ||
        targets->size() > kMaxTargets) {
        return parsed;
    }
    parsed.bootId = boot->get<std::string>();
    parsed.generation = generation->get<std::uint64_t>();
    if (parsed.bootId.empty()) return parsed;
    for (const json& item : *targets) {
        if (!item.is_object()) return parsed;
        const auto uid = item.find("uid");
        const auto name = item.find("name");
        const auto sessionId = item.find("session_id");
        const auto sessionStart = item.find("session_start");
        const auto sessionClass = item.find("session_class");
        const auto obligation = item.find("runtime_obligation");
        if (uid == item.end() || !uid->is_number_unsigned() ||
            uid->get<std::uint64_t>() == 0 ||
            name == item.end() || !name->is_string() ||
            name->get<std::string>().empty() ||
            sessionId == item.end() || !sessionId->is_string() ||
            sessionId->get<std::string>().empty() ||
            sessionStart == item.end() || !sessionStart->is_number_unsigned() ||
            sessionClass == item.end() || !sessionClass->is_string() ||
            sessionClass->get<std::string>().empty() ||
            obligation == item.end() || !obligation->is_string()) {
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
    return parsed;
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
    return result;
}

IncidentSessionTargetStore::WriteResult IncidentSessionTargetStore::write(
    const std::string& bootId, std::uint64_t incidentGeneration,
    const std::vector<IncidentSessionTarget>& targets) const {
    WriteResult result;
    if (bootId.empty() || targets.size() > kMaxTargets) {
        result.detail = "incident session target store write refused";
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
        path_.string(), serialize(bootId, incidentGeneration, targets),
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

} // namespace fic::incident