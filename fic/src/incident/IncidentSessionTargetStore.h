#ifndef FIC_INCIDENT_INCIDENT_SESSION_TARGET_STORE_H
#define FIC_INCIDENT_INCIDENT_SESSION_TARGET_STORE_H

#include <fic/core/fs/SecureStateFile.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fic::incident {

// Durable provenance of ONE session-derived containment target (Model A).
//
// The record is written BEFORE any containment action that could destroy the
// proving login session, so the obligation survives TerminateSession, partial
// failures, FIC restarts and severity escalation.
struct IncidentSessionTarget {
    uid_t uid = 0;
    // Canonical NSS name proven at selection time. UID-reuse protection
    // re-proves this name before any later user-runtime action.
    std::string canonicalName;
    // Selection evidence from the proving logind session.
    std::string sessionId;
    std::uint64_t sessionStartTimestamp = 0;
    std::string sessionClass;
    // Runtime obligation (only ISOLATE creates one).
    //   pending    — user-runtime containment is still owed;
    //   discharged — proven gone (or resolved safely, e.g. kernel reboot).
    enum class RuntimeObligation { Pending, Discharged };
    RuntimeObligation runtimeObligation = RuntimeObligation::Pending;
};

// Fail-closed persistent store of the session-derived targets of the CURRENT
// incident, separate from the incident state file (whose format is exactly one
// severity token and must never grow fields).
//
// Read contract (never an implicit "empty"):
//   Proven        — content validated against the schema and the expectation;
//                   targets() is authoritative for this store version.
//   Absent        — the file is positively absent AND no incident obligation
//                   is known: a fresh-install baseline. Callers decide with
//                   the incident state whether absence may be trusted.
//   Unprovable    — anything else (missing expectation match, corrupt
//                   content, unsafe metadata, oversize, I/O failure). The
//                   caller must DEGRADE, never act on a guessed target set.
class IncidentSessionTargetStore {
public:
    enum class ReadProvenance { Proven, Absent, Unprovable };

    struct ReadResult {
        ReadProvenance provenance = ReadProvenance::Unprovable;
        // Meaningful only for Proven.
        std::string bootId;
        // Monotonic incident-generation counter: every successful
        // administrative clear increments it, so targets of a PREVIOUS
        // incident can never authorize actions in a new one.
        std::uint64_t incidentGeneration = 0;
        std::vector<IncidentSessionTarget> targets;
        std::string detail;
    };

    struct WriteResult {
        bool durable = false;
        std::string detail;
    };

    // Production store below the FIC runtime state directory. The exact path
    // is <state parent dir>/incident_session_targets; the constructor derives
    // it from the same root-owned directory that holds the lockstatus file so
    // both objects share one security boundary.
    explicit IncidentSessionTargetStore(std::filesystem::path lockStatusPath);

    // Tests install an explicit path (any directory they own).
    static IncidentSessionTargetStore forTesting(std::filesystem::path path);

    const std::filesystem::path& path() const { return path_; }

    // Fail-closed read. See ReadResult.
    ReadResult read() const;

    // Durable replace of the whole target set for one incident generation.
    // Atomic rename + fsync of the file and the parent directory; the write
    // is only reported durable after the directory fsync is proven.
    WriteResult write(const std::string& bootId,
                      std::uint64_t incidentGeneration,
                      const std::vector<IncidentSessionTarget>& targets) const;

    // Expectation used for both read and write; mirrors the lockstatus
    // contract (root owner, 0640, single link, safe parent, small).
    static ::fic::core::SecureStateFileExpectation expectation();

    // Test-only identity override, mirroring IncidentStateStore. Nothing in
    // the daemon ever calls this.
    static void setOwnershipExpectationForTests(
        std::optional<uid_t> owner, std::optional<uid_t> parentOwner);

private:
    explicit IncidentSessionTargetStore(
        std::filesystem::path path, bool) : path_(std::move(path)) {}
    std::filesystem::path path_;
};

} // namespace fic::incident

#endif // FIC_INCIDENT_INCIDENT_SESSION_TARGET_STORE_H