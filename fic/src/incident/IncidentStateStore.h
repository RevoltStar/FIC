#ifndef FIC_INCIDENT_STATE_STORE_H
#define FIC_INCIDENT_STATE_STORE_H

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/SecureStateFile.h>
#include <fic/core/incident/IncidentSeverity.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace fic::incident {

// The authoritative persistent incident state file.
//
// Content contract (EXACTLY this, nothing else):
//   "UNLOCKED\n" | "SOFT\n" | "STANDARD\n" | "HARD\n" | "ISOLATE\n"
//
// No JSON, no reasons, no timestamps, no detector names, no history. History
// lives in the security audit trail; this file is a single security decision.
class IncidentStateStore {
public:
    // Provenance of a read. Only Proven carries a usable severity;
    // Absent, InvalidContent and Broken are effective ISOLATE.
    enum class Provenance {
        // Content positively proven to be exactly one valid severity token.
        Proven,
        // Object positively proven absent (ENOENT through a secure open).
        Absent,
        // Object identity/metadata/content are proven, but its token is not a
        // valid severity. Only an exact administrative clear may replace it.
        InvalidContent,
        // Unreadable, symlink, non-regular, wrong metadata, unsafe parent,
        // oversize, or a concurrent change detected during the proof.
        Broken
    };

    struct ReadResult {
        Provenance provenance = Provenance::Broken;
        // Meaningful only when provenance == Proven.
        ::fic::core::IncidentSeverity severity = ::fic::core::IncidentSeverity::Unlocked;
        // Why the read is not Proven. Empty when Proven or Absent.
        std::string detail;
        // The proven identity/metadata/content snapshot, present for Proven
        // and InvalidContent. Used as the exact write precondition.
        std::optional<AtomicTargetState> provenState;
    };

    // How a write attempt was resolved, in terms the caller must honour.
    enum class PersistenceResult {
        // New severity is installed AND confirmed durable.
        DurableConfirmed,
        // New severity is installed but the parent directory fsync failed;
        // the caller must run the durability retry before believing it.
        InstalledNotDurable,
        // Nothing was replaced (the precondition failed or the write was
        // refused before the rename).
        NotInstalled,
        // Could not durably record the requested severity. The caller must
        // fall back to a durable BROKEN_STATE encoding.
        Failed
    };

    struct RaiseResult {
        // False when the requested severity could NOT be made durably
        // persistent in any form (see Failed) - the caller must fall back to
        // ISOLATE with a DEGRADED runtime state.
        bool durable = false;
        PersistenceResult persistence = PersistenceResult::Failed;
        // Severity that is now durably persisted.
        ::fic::core::IncidentSeverity effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
        // True when this call actually raised the persistent severity. A
        // repeat of the same or a lower level is a no-op (idempotent) and
        // leaves this false.
        bool escalated = false;
        // True when the persistent object is durably absent, i.e. the
        // BROKEN_STATE fallback encoding is in effect and ISOLATE applies.
        bool brokenStatePersisted = false;
        std::string detail;
        // Populated for InstalledNotDurable: the exact state published by
        // rename, so the caller can re-prove it before a durability retry.
        std::optional<AtomicTargetState> installedState;
    };

    struct ClearResult {
        bool ok = false;
        bool brokenState = false;
        ::fic::core::IncidentSeverity effectiveSeverity = ::fic::core::IncidentSeverity::Standard;
        PersistenceResult persistence = PersistenceResult::Failed;
        std::string detail;
    };

    IncidentStateStore();

    // Tests and the packaging lifecycle install an alternate runtime path.
    explicit IncidentStateStore(std::filesystem::path path);

    const std::filesystem::path& path() const { return path_; }

    // Fail-closed read. Only Proven gives a usable severity.
    ReadResult read() const;

    // Monotonic raise: target = max(current, requested). Never lowers.
    // Performs the read -> compute -> conditional atomic write -> retry loop
    // internally, so a concurrent writer cannot cause a lost update.
    RaiseResult raiseToAtLeast(::fic::core::IncidentSeverity requested) const;

    // Administrative clear. A successful clear is only durable UNLOCKED.
    // Failed compensation may encode durable absence as BROKEN/ISOLATE;
    // absence is never a successful unlock.
    ClearResult clear() const;

    // Durable BROKEN_STATE fallback used when a requested severity cannot be
    // made durable: conditionally removes EXACTLY the proven object, fsyncs
    // the parent and proves the absence is durable. Durable absence means
    // BROKEN_STATE -> ISOLATE. Refuses to touch any object whose identity,
    // metadata or content FIC cannot prove.
    RaiseResult encodeDurableBrokenState() const;

    // Metadata contract FIC requires of its own state file. Exposed so the
    // packaging lifecycle can create the initial file with exactly these
    // properties and so tests can build a hostile filesystem.
    static ::fic::core::SecureStateFileExpectation lockedStateExpectation();

    // Test-only seam. Production always requires root ownership of the state
    // file and of its parent, because only root may authorise incident state.
    // An unprivileged test process cannot own those objects, so the suite
    // installs the identity it actually owns instead of weakening the
    // production default. Nothing in the daemon ever calls this.
    static void setOwnershipExpectationForTests(
        std::optional<uid_t> owner, std::optional<uid_t> parentOwner);

private:
    // Retry barrier for a rename that published the new severity before its
    // parent directory fsync succeeded.
    RaiseResult confirmInstalledDurability(RaiseResult result) const;
    RaiseResult encodeDurableBrokenStateLocked(
        const std::optional<AtomicTargetState>& expected = std::nullopt) const;
    RaiseResult writeLocked(const AtomicTargetState& precondition,
                            ::fic::core::IncidentSeverity target,
                            bool allowCreate) const;

    std::filesystem::path path_;
};

// Human-readable reason a read failed. Shared with audit records.
std::string incidentProvenanceReason(IncidentStateStore::Provenance provenance);
const char* incidentProvenanceToken(IncidentStateStore::Provenance provenance);

} // namespace fic::incident

#endif // FIC_INCIDENT_STATE_STORE_H
