#ifndef FIC_ROLLBACK_MUTATION_JOURNAL_H
#define FIC_ROLLBACK_MUTATION_JOURNAL_H

#include "rollback/MutationRecord.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace fic::rollback {

// Persistent JSON journal of executed FIC mutations.
//
// Reliability contract:
//   * every update rewrites the whole document atomically (temp file + rename
//     + parent directory fsync);
//   * the document carries a schema_version and is rejected (fail closed) on
//     unknown schema versions, unknown enum values or structurally broken
//     content;
//   * a missing file is an empty journal ONLY for a never-loaded fresh
//     object without an initialization witness (see initializeOrLoad); a
//     malformed file, a file that cannot
//     be opened/read, and an existing zero-byte file are load errors and
//     callers must refuse rollback rather than guess;
//   * pre-install persist failure (the new document was NOT published by
//     rename): the observable journal state stays logically identical to the
//     state before the operation (including record ordering) and mutating
//     operations may be retried;
//   * post-rename persist failure (rename published the new document but the
//     parent directory fsync failed): persist() first tries to finish the
//     durability transparently (re-prove the installed document, fsync the
//     directory). When that is impossible, the journal becomes
//     Indeterminate: the in-memory state stays identical to the installed
//     document (never rolled back to the previous state), every mutating
//     operation fails closed, and only a successful load() may restore the
//     Healthy state.
//   * Healthy is a DURABILITY property, not a readability property: a
//     journal document that was successfully read and parsed is still not
//     Healthy until the exact captured snapshot was re-proved to still
//     occupy the path AND the parent directory fsync succeeded (visible !=
//     proven durable). A failed load durability barrier poisons the journal
//     (Indeterminate) and it stays unusable for ALL operational decisions
//     (reads included) until a successful load() or daemon restart.
enum class JournalHealth {
    Healthy,
    Indeterminate
};

class MutationJournal {
public:
    static constexpr std::uint32_t kSchemaVersion = 1;
    // Independent version identifier of the initialization witness document;
    // the journal JSON schema itself is unchanged.
    static constexpr std::uint32_t kWitnessSchemaVersion = 1;

    explicit MutationJournal(std::filesystem::path path);

    // Companion witness path: <journal path>.initialized. Derived
    // deterministically from the journal path; no extra path plumbing.
    std::filesystem::path witnessPath() const;

    // Loads the journal from disk. Must be called before mutations. The load
    // is snapshot-bound and durability-proven: the exact current document is
    // captured, parsed, re-proved to still occupy the path, and the parent
    // directory is fsynced BEFORE any state is published; only then does the
    // journal become Healthy. A missing file is an empty journal ONLY during
    // the initial bootstrap of a never-loaded journal (loaded_ == false &&
    // Healthy): the disappearance of a previously loaded or Indeterminate
    // journal is NOT equivalent to an empty journal and fails closed. Any
    // failed load poisons the journal (health = Indeterminate, usable() ==
    // false) while records_/nextId_ stay untouched for diagnostics; a
    // successful load re-parses the current disk document and restores
    // Healthy.
    //
    // RAW PRIMITIVE (tests/diagnostics and live-object reload only): this
    // method knows nothing about the initialization witness. Operational
    // startup MUST use initializeOrLoad(); a daemon facade must never use
    // load() to bypass the witness on a fresh object.
    bool load(std::string& error);

    // Witness-aware lifecycle entrypoint — the ONLY entrypoint operational
    // facades (DaemonMutationJournal) may use for initialization. Handles the
    // persistent (journal, witness) state table:
    //   J missing + W missing → virgin bootstrap: durable empty journal,
    //                           then durable witness, then load/prove;
    //   J exists + W missing  → migration / interrupted bootstrap: prove the
    //                           journal, create a durable witness, only then
    //                           operational (journal never rewritten);
    //   J exists + W valid    → normal load (both proven before usable);
    //   J exists + W invalid  → fail closed, journal unchanged, no witness
    //                           repair (a malformed witness is a persistent
    //                           state anomaly);
    //   J missing + W valid   → provenance loss: fail closed ("manual
    //                           provenance recovery is required");
    //   J missing + W invalid → fail closed (persistent-state anomaly).
    // For a previously loaded (live) object this delegates to load(): the
    // witness question was already answered at initialization and a vanished
    // journal must never re-bootstrap (follow-up 6 semantics).
    // Any failure poisons the object (Indeterminate, usable() == false) while
    // records_/nextId_ stay untouched for diagnostics.
    bool initializeOrLoad(std::string& error);
    bool loaded() const { return loaded_; }
    const std::vector<MutationRecord>& records() const { return records_; }
    JournalHealth health() const { return health_; }

    // A journal may drive operational decisions ONLY while it is loaded and
    // Healthy. Tests and diagnostics may still use records()/health() for
    // inspection, but daemon facades must gate every journal-backed decision
    // (apply, rollback, ownership resolution, detach) on usable().
    bool usable() const { return loaded_ && health_ == JournalHealth::Healthy; }

    // Inserts a new Prepared record, or updates an existing active record for
    // the same (policy, backend, resource) triple. Returns the record id.
    bool prepareMutation(MutationRecord record, MutationId& id, std::string& error);
    bool setStatus(MutationId id, MutationStatus status, std::string& error);
    bool setStatusWithMessage(MutationId id, MutationStatus status,
                              const std::string& message, std::string& error);
    bool discard(MutationId id, std::string& error);

    std::vector<MutationRecord> activeRecords(const PolicyRef& policy) const;

    // Test-only deterministic seam between the capture of the journal
    // document and its parse/re-proof/durability confirmation inside load().
    // It lets tests inject an external journal replacement exactly in the
    // window that targetStateMatches() must detect. Production code must
    // never set this hook.
    static void setLoadAfterCaptureHookForTests(std::function<void()> hook);

private:
    // Witness-aware initialization of a fresh (never-loaded) object:
    // implements the persistent (journal, witness) state table.
    bool initializeFresh(std::string& error);
    // Virgin bootstrap: durable empty journal, then durable witness, then
    // load/prove (journal-before-witness ordering keeps a crash between the
    // two phases recoverable through the migration path).
    bool bootstrapVirgin(std::string& error);

    enum class PersistOutcome {
        // The new document was installed and its durability confirmed.
        Persisted,
        // The new document was never published by rename: the persistent
        // journal definitely still holds the previous content.
        NotInstalled,
        // The new document was published by rename but its durability could
        // not be confirmed: the journal must become Indeterminate.
        Indeterminate
    };

    PersistOutcome persist(std::string& error);
    // Centralized failed-load handling: revoke operational trust (health =
    // Indeterminate, usable() == false) WITHOUT touching records_/nextId_/
    // loaded_, so the previous in-memory state stays available for
    // diagnostics and recovery while no operational decision may use it.
    bool failLoad(std::string message, std::string& error);
    // Witness primitives. witnessIsValid(): capture exact regular-file
    // snapshot, verify the exact versioned content and run the state-bound
    // durability barrier — a mere filesystem::exists() proves nothing.
    // createWitness(): crash-safe creation (temp fsync + rename + parent
    // fsync via AtomicFileWriter), exclusive create, mode 0600, refuses to
    // replace a foreign existing object; if a concurrent writer created a
    // valid durable witness first, that counts as success. The witness is
    // "created" only after confirmed durability (installed != durable).
    bool witnessIsValid(std::string& error);
    bool createWitness(std::string& error);
    MutationRecord* find(MutationId id);

    std::filesystem::path path_;
    std::vector<MutationRecord> records_;
    MutationId nextId_ = 1;
    bool loaded_ = false;
    JournalHealth health_ = JournalHealth::Healthy;
};

} // namespace fic::rollback

#endif // FIC_ROLLBACK_MUTATION_JOURNAL_H