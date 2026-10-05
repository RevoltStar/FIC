#include "incident/IncidentStateStore.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/FileStats.h>

#include <cstdint>
#include <unistd.h>

namespace fic::incident {
namespace {

using Provenance = IncidentStateStore::Provenance;
using PersistenceResult = IncidentStateStore::PersistenceResult;
using ReadResult = IncidentStateStore::ReadResult;

// A monotonic raise retries a bounded number of times: each iteration either
// proves the target is already persisted, installs it, or loses the optimistic
// race and recomputes against the winner's state.
constexpr int MAX_RAISE_ATTEMPTS = 8;

// Exact on-disk serialization. The trailing newline is REQUIRED by the
// strict parser; writing it here keeps writer and parser symmetric.
std::string serialize(::fic::core::IncidentSeverity severity) {
    return ::fic::core::incidentSeverityToken(severity) + "\n";
}
// The strict content parser.
//
// Everything the old permissive SingleLineFileHandler tolerated is refused
// here on purpose:
//   * no trimming and no surrounding whitespace,
//   * no comments,
//   * exactly one line (a second '\n' is rejected),
//   * no empty prefix/suffix,
//   * no unknown or mixed-case tokens,
//   * no trailing bytes after the final newline,
//   * the final newline itself is mandatory.
bool parseStrictSeverity(const std::string& content,
                         ::fic::core::IncidentSeverity& severity,
                         std::string& reason) {
    if (content.empty()) {
        reason = "empty content";
        return false;
    }
    if (content.back() != '\n') {
        reason = "missing final newline";
        return false;
    }
    const std::string body = content.substr(0, content.size() - 1);
    if (body.empty()) {
        reason = "empty token";
        return false;
    }
    if (body.find('\n') != std::string::npos) {
        reason = "multiple lines";
        return false;
    }
    if (body.find('#') != std::string::npos) {
        reason = "comments are not accepted";
        return false;
    }
    const std::optional<::fic::core::IncidentSeverity> parsed =
        ::fic::core::parseIncidentSeverityToken(body);
    if (!parsed.has_value()) {
        reason = "unknown severity token";
        return false;
    }
    severity = *parsed;
    reason.clear();
    return true;
}

} // namespace
std::string incidentProvenanceReason(Provenance provenance) {
    switch (provenance) {
        case Provenance::Proven:
            return "proven";
        case Provenance::Absent:
            return "absent";
        case Provenance::Broken:
            break;
    }
    return "broken";
}

IncidentStateStore::IncidentStateStore()
    : path_(fic::core::FicRuntimePaths::get().lockStatusFile) {
}

IncidentStateStore::IncidentStateStore(std::filesystem::path path)
    : path_(std::move(path)) {
}

namespace {

// Production ownership requirement: only root may authorise incident state,
// and the containing directory must be root owned as well. Tests replace
// these with the identity they actually own (see
// setOwnershipExpectationForTests); nothing in the daemon changes them.
std::optional<uid_t>& expectedStateOwner() {
    static std::optional<uid_t> owner = 0;
    return owner;
}

std::optional<uid_t>& expectedStateParentOwner() {
    static std::optional<uid_t> owner = 0;
    return owner;
}

bool& testIdentityOverride() {
    static bool enabled = false;
    return enabled;
}

} // namespace

void IncidentStateStore::setOwnershipExpectationForTests(
    std::optional<uid_t> owner, std::optional<uid_t> parentOwner) {
    expectedStateOwner() = owner;
    expectedStateParentOwner() = parentOwner;
    testIdentityOverride() = true;
}

::fic::core::SecureStateFileExpectation IncidentStateStore::lockedStateExpectation() {
    ::fic::core::SecureStateFileExpectation expectation;
    // The state file is authoritative security state: root owned, never
    // group/other writable, at most one link, and small enough that the hard
    // read bound is the only size that can ever apply.
    expectation.owner = expectedStateOwner();
    gid_t group = ::getegid();
    if (!testIdentityOverride()) {
        uid_t rootId = 0;
        group = static_cast<gid_t>(-1);
        FileStats::resolve_owner_group("root", "fic", rootId, group);
    }
    expectation.group = group;
    expectation.exactMode = 0640;
    expectation.maxSize = 64;
    expectation.requireSingleLink = true;
    expectation.parentOwner = expectedStateParentOwner();
    expectation.parentGroup = group;
    expectation.exactParentMode = testIdentityOverride() ? 0700 : 02750;
    return expectation;
}

IncidentStateStore::ReadResult IncidentStateStore::read() const {
    using ::fic::core::SecureStateReadResult;
    using ::fic::core::SecureStateReadStatus;

    const SecureStateReadResult secure =
        ::fic::core::readSecureStateFile(path_, lockedStateExpectation());
    switch (secure.status) {
        case SecureStateReadStatus::Missing:
            // Absence is proven honestly through the same secure open. It is
            // NOT "proven unlocked": every consumer must treat it as ISOLATE.
            return ReadResult{Provenance::Absent, ::fic::core::IncidentSeverity::Unlocked,
                              "", std::nullopt};
        case SecureStateReadStatus::Proven:
            break;
        case SecureStateReadStatus::Unprovable:
            return ReadResult{Provenance::Broken, ::fic::core::IncidentSeverity::Unlocked,
                              secure.detail, std::nullopt};
    }

    ::fic::core::IncidentSeverity severity = ::fic::core::IncidentSeverity::Unlocked;
    std::string reason;
    if (!parseStrictSeverity(secure.content, severity, reason)) {
        return ReadResult{Provenance::Broken, ::fic::core::IncidentSeverity::Unlocked,
                          "malformed incident state: " + reason,
                          std::nullopt};
    }
    return ReadResult{Provenance::Proven, severity, "", secure.targetState};
}
// Performs ONE conditional atomic write of `target` guarded by the proven
// precondition. The write is metadata-enforcing so a hostile replacement
// cannot leave the new state file with permissive modes.
IncidentStateStore::RaiseResult IncidentStateStore::writeLocked(
    const AtomicTargetState& precondition,
    ::fic::core::IncidentSeverity target,
    bool allowCreate) const {
    RaiseResult result;
    AtomicWriteOptions options;
    options.createIfMissing = allowCreate;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = precondition.mode == 0 ? 0640 : precondition.mode;
    options.fileOwner = precondition.owner;
    options.fileGroup = allowCreate
        ? lockedStateExpectation().group
        : std::optional<gid_t>(precondition.group);
    // The optimistic precondition is what makes this a compare-and-swap
    // against a cooperating writer instead of a blind overwrite. It only
    // applies when a real predecessor was proven: for a create-from-absence
    // there is no predecessor, and passing an empty expected state would make
    // the precondition fail by construction.
    if (!allowCreate) {
        options.expectedTargetState = precondition;
    }

    AtomicWriteResult writeResult;
    std::string error;
    const bool writeSucceeded = AtomicFileWriter::writeWithResult(
        path_.string(), serialize(target), options, &error, &writeResult);

    // writeWithResult() returns false for BOTH a pre-install failure and a
    // post-rename durability failure. Those are different worlds and must not
    // be conflated: `installed` is the authoritative discriminator.
    //   installed == false -> nothing was replaced; the caller must reread.
    //   installed == true  -> rename(2) already published the new severity,
    //                         the system already carries it, and only the
    //                         durability barrier is missing.
    if (!writeResult.installed) {
        result.durable = false;
        result.persistence = writeResult.preconditionFailed
            ? PersistenceResult::NotInstalled
            : PersistenceResult::Failed;
        result.detail = writeResult.preconditionFailed
            ? "incident state changed before the conditional write"
            : (error.empty()
                   ? "incident state write failed before replacement"
                   : "incident state write failed: " + error);
        return result;
    }

    result.effectiveSeverity = target;
    result.escalated = true;
    result.installedState = writeResult.installedTargetState;
    if (writeSucceeded && writeResult.durabilityConfirmed) {
        result.durable = true;
        result.persistence = PersistenceResult::DurableConfirmed;
        result.detail.clear();
        return result;
    }
    // rename(2) already published the new severity. Durability is NOT proven
    // yet, but the system DOES carry the new state: installed != durable.
    result.durable = false;
    result.persistence = PersistenceResult::InstalledNotDurable;
    result.detail = "incident state installed but parent fsync failed";
    return result;
}
// The durability retry barrier for an installed-but-unconfirmed write.
//
// Pre-rename failure vs post-rename failure are different worlds, so the two
// are separated explicitly:
//   * InstalledNotDurable: the target already carries the new severity. FIC
//     re-proves the EXACT installed state and retries only the directory
//     barrier. If that succeeds the escalation IS durable.
//   * NotInstalled/Failed: nothing was replaced, nothing is durable, and the
//     caller must fall back to the BROKEN_STATE encoding.
IncidentStateStore::RaiseResult IncidentStateStore::confirmInstalledDurability(
    RaiseResult result) const {
    if (!result.installedState.has_value()) {
        return result;
    }
    std::string error;
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            path_.string(), *result.installedState, &error)) {
        result.durable = false;
        // A rename that cannot be fsynced is NOT a security state: after a
        // crash or power loss the file could still revert to the previous,
        // possibly UNLOCKED, content. The caller must not treat the published
        // severity as effective, so the effective severity is forced to
        // ISOLATE here and the caller escalates its runtime to containment.
        result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
        result.brokenStatePersisted = false;
        result.detail = "incident state durability could not be confirmed: " +
            error;
        return result;
    }
    result.durable = true;
    result.persistence = PersistenceResult::DurableConfirmed;
    result.detail.clear();
    return result;
}

IncidentStateStore::RaiseResult IncidentStateStore::raiseToAtLeast(
    ::fic::core::IncidentSeverity requested) const {
    RaiseResult failure;
    failure.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
    failure.persistence = PersistenceResult::Failed;
    failure.detail = "incident state is not proven";

    for (int attempt = 0; attempt < MAX_RAISE_ATTEMPTS; ++attempt) {
        const ReadResult current = read();
        if (current.provenance == Provenance::Broken) {
            // FIC cannot prove the object it would have to replace, so it must
            // never overwrite it: an unproven object could be a symlink, a
            // hostile replacement, or a foreign file. BROKEN_STATE is itself
            // the ISOLATE encoding, but only once the absence is durable, which
            // encodeDurableBrokenStateLocked() proves (or refuses).
            failure.detail = current.detail;
            return encodeDurableBrokenStateLocked();
        }
        if (current.provenance == Provenance::Absent) {
            // Absence is already effective ISOLATE. Only bootstrap or an
            // explicit administrative clear may create a weaker state.
            return encodeDurableBrokenStateLocked();
        }

        // Proven state. target = max(current, requested): never lower.
        const ::fic::core::IncidentSeverity target =
            ::fic::core::maxIncidentSeverity(current.severity, requested);
        if (target == current.severity) {
            // Idempotent: the persisted severity is already at least as high
            // as requested. No write, no escalation, no notification spam.
            RaiseResult idempotent;
            idempotent.durable = true;
            idempotent.persistence = PersistenceResult::DurableConfirmed;
            idempotent.effectiveSeverity = current.severity;
            idempotent.escalated = false;
            idempotent.detail.clear();
            return idempotent;
        }

        RaiseResult written = writeLocked(*current.provenState, target, false);
        if (written.persistence == PersistenceResult::DurableConfirmed) {
            return written;
        }
        if (written.persistence == PersistenceResult::InstalledNotDurable) {
            RaiseResult confirmed = confirmInstalledDurability(written);
            return confirmed.durable ? confirmed
                : encodeDurableBrokenStateLocked(written.installedState);
        }
        if (written.persistence == PersistenceResult::NotInstalled) {
            // Lost the optimistic race: reread, recompute max(), retry. This is
            // what prevents the "A writes HARD / B writes SOFT" lost update.
            continue;
        }
        return encodeDurableBrokenStateLocked();
    }

    failure.detail = "incident state raise did not converge";
    return failure;
}

// Durable BROKEN_STATE fallback.
//
// The invariant this protects: after a reboot the ONLY persistent witness of
// the incident must not still say UNLOCKED. If the requested severity cannot
// be made durable, FIC encodes the incident as a DURABLY ABSENT state file,
// which is exactly the BROKEN_STATE -> ISOLATE condition the reader already
// treats fail-closed.
//
// This is emphatically NOT an unconditional unlink():
//   1. the exact current object is proven (identity + metadata + content),
//   2. removeIfCurrentState() re-proves that exact state descriptor-relative
//      and only then unlinks - a replacement between proof and unlink is
//      detected and NOT deleted,
//   3. the parent directory is fsynced and the absence re-proven.
IncidentStateStore::RaiseResult
IncidentStateStore::encodeDurableBrokenStateLocked(
    const std::optional<AtomicTargetState>& expected) const {
    RaiseResult result;
    result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
    result.persistence = PersistenceResult::Failed;

    const ReadResult current = read();
    if (current.provenance == Provenance::Absent) {
        std::string error;
        result.durable = AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
            path_.string(), &error);
        if (!result.durable) {
            result.detail = "incident state absence is not durable: " + error;
            return result;
        }
        result.brokenStatePersisted = true;
        result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
        result.persistence = PersistenceResult::DurableConfirmed;
        result.detail = "incident state is already durably absent";
        return result;
    }
    if (current.provenance == Provenance::Broken ||
        !current.provenState.has_value()) {
        // The object at the path is not provable, so FIC must not delete it.
        // Leaving it alone keeps it the (fail-closed) BROKEN_STATE witness.
        result.durable = false;
        result.brokenStatePersisted = false;
        result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
        result.detail = "incident state object is not provable and was not "
            "removed: " + current.detail;
        return result;
    }

    if (expected.has_value()) {
        const AtomicTargetState& actual = *current.provenState;
        if (actual.identity.device != expected->identity.device ||
            actual.identity.inode != expected->identity.inode ||
            actual.mode != expected->mode || actual.owner != expected->owner ||
            actual.group != expected->group || actual.content != expected->content) {
            result.detail = "installed incident state was replaced before BROKEN fallback";
            return result;
        }
    }

    std::string error;
    AtomicRemoveResult removed;
    if (!AtomicFileWriter::removeIfCurrentState(
            path_.string(), *current.provenState, &error, &removed)) {
        result.durable = false;
        result.detail = "could not remove the proven incident state object: " +
            error;
        return result;
    }
    if (removed.preconditionFailed || !removed.removed) {
        // Either the object changed under us (replacement -> never delete) or
        // the unlink itself was refused. Either way FIC does not own the
        // current object and must not claim a durable absence.
        result.durable = false;
        result.detail = removed.preconditionFailed
            ? "incident state object changed before removal; nothing deleted"
            : "incident state object was not removed";
        return result;
    }
    if (!removed.durabilityConfirmed) {
        // The directory entry is gone in the running system but the removal is
        // not crash-durable, so the on-disk UNLOCKED could still return.
        result.durable = false;
        result.detail = "incident state removal is not durable";
        return result;
    }

    std::string barrierError;
    if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
            path_.string(), &barrierError)) {
        result.durable = false;
        result.detail = "incident state absence could not be proven durable: " +
            barrierError;
        return result;
    }

    result.durable = true;
    result.brokenStatePersisted = true;
    result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
    result.persistence = PersistenceResult::DurableConfirmed;
    result.detail = "incident encoded as durably absent BROKEN_STATE";
    return result;
}

IncidentStateStore::RaiseResult IncidentStateStore::encodeDurableBrokenState()
    const {
    return encodeDurableBrokenStateLocked();
}

// Administrative clear.
//
// There is NO unlink fallback here. The only accepted outcome is a durably
// proven UNLOCKED; if the write or its durability cannot be proven, clear
// FAILS and the previous incident stays active. Deleting the file instead
// would leave BROKEN_STATE, which is ISOLATE - the opposite of what the
// administrator asked for.
IncidentStateStore::ClearResult IncidentStateStore::clear() const {
    ClearResult result;
    const ReadResult current = read();
    if (current.provenance == Provenance::Broken) {
        result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
        result.persistence = PersistenceResult::NotInstalled;
        result.detail = "incident state is not provable: " + current.detail;
        return result;
    }

    AtomicTargetState precondition;
    if (current.provenance == Provenance::Proven) {
        precondition = *current.provenState;
    } else {
        precondition.mode = 0640;
        precondition.owner = expectedStateOwner().value_or(0);
    }

    RaiseResult written = writeLocked(
        precondition, ::fic::core::IncidentSeverity::Unlocked,
        current.provenance == Provenance::Absent);
    if (written.persistence == PersistenceResult::InstalledNotDurable) {
        written = confirmInstalledDurability(written);
    }
    if (!written.durable && written.installedState.has_value()) {
        // A failed downgrade may already have published UNLOCKED. Restore the
        // exact prior severity conditionally, or remove the installed object
        // as a BROKEN/ISOLATE witness. Never report the prior severity while
        // a usable UNLOCKED pathname remains.
        if (current.provenance == Provenance::Proven) {
            RaiseResult restored = writeLocked(
                *written.installedState, current.severity, false);
            if (restored.persistence == PersistenceResult::InstalledNotDurable) {
                restored = confirmInstalledDurability(restored);
            }
            if (restored.durable) {
                result.effectiveSeverity = current.severity;
                result.persistence = restored.persistence;
                result.detail = "clear failed; previous incident restored durably";
                return result;
            }
            if (restored.installedState.has_value()) {
                written.installedState = restored.installedState;
            }
        }
        const RaiseResult broken = encodeDurableBrokenStateLocked(written.installedState);
        result.effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
        result.persistence = broken.persistence;
        result.detail = "clear failed; " + broken.detail;
        return result;
    }
    result.persistence = written.persistence;
    result.effectiveSeverity = written.durable
        ? ::fic::core::IncidentSeverity::Unlocked
        : (current.provenance == Provenance::Proven
               ? current.severity
               : ::fic::core::IncidentSeverity::Isolate);
    result.detail = written.detail;
    result.ok = written.durable;
    return result;
}
} // namespace fic::incident
