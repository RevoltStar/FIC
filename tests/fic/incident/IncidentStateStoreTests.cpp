#include "incident/IncidentStateStore.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/incident/IncidentSeverity.h>
#include <fic/core/fs/SecureStateFile.h>

#include <sys/stat.h>

#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using ::AtomicFileWriter;
using ::AtomicWriteOptions;
using ::AtomicWriteResult;
using ::FileMetadataPolicy;
using ::fic::incident::IncidentStateStore;
using ::fic::core::IncidentSeverity;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/fic-incident-state-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        directory = created;
    }
    ~TempDir() {
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        AtomicFileWriter::setRemovePreunlinkHookForTests({});
        fic::core::setSecureStatePostReadHookForTests({});
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
    std::filesystem::path directory;
};

std::filesystem::path statePath(const TempDir& temp) {
    return temp.directory / "lockstatus";
}

// Writes the state file the way FIC itself would, so the metadata proof in
// the reader is satisfied by the fixtures.
void writeState(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::trunc);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0640);
}

bool fsyncAlwaysFails(const std::string&) {
    return false;
}


// ---------------------------------------------------------------------------
// Invariant 1/2: ONLY a positively proven UNLOCKED token means "no incident".
// Every other unprovable state (missing, corrupt, symlink, wrong metadata,
// unsafe parent) is BROKEN_STATE, whose effective severity is ISOLATE.
// ---------------------------------------------------------------------------

void testProvenUnlockedIsTheOnlyUnlockedState(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");

    IncidentStateStore store(path);
    const auto read = store.read();
    require(read.provenance == IncidentStateStore::Provenance::Proven,
            "UNLOCKED must be positively proven");
    require(read.severity == IncidentSeverity::Unlocked,
            "proven UNLOCKED must read back as Unlocked");

    writeState(path, "HARD\n");
    const auto hardened = store.read();
    require(hardened.provenance == IncidentStateStore::Provenance::Proven &&
            hardened.severity == IncidentSeverity::Hard,
            "HARD must be positively proven");
}

void testMissingStateIsNotProvenUnlocked(const TempDir& temp) {
    IncidentStateStore store(statePath(temp));
    const auto read = store.read();
    // Absence is reported honestly as Absent and is NEVER proven UNLOCKED.
    require(read.provenance == IncidentStateStore::Provenance::Absent,
            "a missing state file must be reported as Absent");
    require(read.provenance != IncidentStateStore::Provenance::Proven,
            "a missing state file must never be reported as proven UNLOCKED");
}

void testCorruptStateIsBroken(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    IncidentStateStore store(path);

    // Everything the old permissive handler tolerated is refused here.
    const std::vector<std::string> corruptions = {
        "",                 // empty
        "UNLOCKED",         // missing final newline
        "UNLOCKED\n\n",     // extra blank line
        "UNLOCKED\nHARD\n", // two lines
        " unlocked\n",      // leading whitespace
        "UNLOCKED \n",      // trailing whitespace
        "# UNLOCKED\n",     // comment
        "0\n",              // legacy pre-schema value
        "1\n",              // legacy pre-schema value
        "unlocked\n",       // wrong case
        "BOGUS\n",          // unknown token
        "UNLOCKED\ntrailing", // bytes after the newline
    };
    for (const std::string& content : corruptions) {
        writeState(path, content);
        require(store.read().provenance == IncidentStateStore::Provenance::Broken,
                "malformed content must be Broken: [" + content + "]");
    }

    // The only accepted spellings.
    for (const std::string& content :
         {"UNLOCKED\n", "SOFT\n", "STANDARD\n", "HARD\n", "ISOLATE\n"}) {
        writeState(path, content);
        require(store.read().provenance == IncidentStateStore::Provenance::Proven,
                "exact token must be proven: [" + content + "]");
    }
}

void testSymlinkStateIsBroken(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    const std::filesystem::path target = temp.directory / "elsewhere";
    writeState(target, "UNLOCKED\n");
    ::symlink(target.c_str(), path.c_str());

    IncidentStateStore store(path);
    require(store.read().provenance == IncidentStateStore::Provenance::Broken,
            "a symlinked state file must be Broken, never followed");
}

void testWrongMetadataStateIsBroken(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);
    require(store.read().provenance == IncidentStateStore::Provenance::Proven,
            "fixture precondition");

    // World-writable state file: an unprivileged writer could rewrite it.
    ::chmod(path.c_str(), 0666);
    require(store.read().provenance == IncidentStateStore::Provenance::Broken,
            "a group/world writable state file must be Broken");

    ::chmod(path.c_str(), 0600);
    require(store.read().provenance == IncidentStateStore::Provenance::Broken,
            "a restrictive but noncanonical mode must still be Broken");

    ::chmod(path.c_str(), 0640);
    ::chmod(temp.directory.c_str(), 0750);
    require(store.read().provenance == IncidentStateStore::Provenance::Broken,
            "wrong parent mode must be Broken");
    ::chmod(temp.directory.c_str(), 0700);

    // Directory instead of a regular file.
    ::unlink(path.c_str());
    ::mkdir(path.c_str(), 0755);
    require(store.read().provenance == IncidentStateStore::Provenance::Broken,
            "a non-regular state file must be Broken");
}

// ---------------------------------------------------------------------------
// Invariant 3: automated severity never decreases; a repeated raise of the
// same or a lower level is idempotent.
// Invariant 5: escalation is conditional, so a stale writer cannot lose an
// update.
// ---------------------------------------------------------------------------

void testRaiseIsMonotonicAndIdempotent(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);

    auto raised = store.raiseToAtLeast(IncidentSeverity::Standard);
    require(raised.durable && raised.escalated, "raise to STANDARD must persist");
    require(raised.effectiveSeverity == IncidentSeverity::Standard,
            "effective severity must be STANDARD");

    // Same level again: idempotent, no escalation, no write.
    auto repeated = store.raiseToAtLeast(IncidentSeverity::Standard);
    require(repeated.durable, "a repeated raise must be durable");
    require(!repeated.escalated, "a repeated raise must not re-escalate");
    require(repeated.effectiveSeverity == IncidentSeverity::Standard,
            "a repeated raise must keep the same severity");

    // Lower level: must NOT lower the persisted severity.
    auto lowered = store.raiseToAtLeast(IncidentSeverity::Soft);
    require(lowered.effectiveSeverity == IncidentSeverity::Standard,
            "an automated raise must never lower the severity");
    require(!lowered.escalated, "a lower raise must not count as escalation");

    std::ifstream verify(path);
    std::string persisted;
    std::getline(verify, persisted);
    require(persisted == "STANDARD",
            "the persisted file must still say STANDARD, got: " + persisted);
}

void testRaiseFromAbsentPreservesIsolate(const TempDir& temp) {
    IncidentStateStore store(statePath(temp));
    const auto raised = store.raiseToAtLeast(IncidentSeverity::Hard);
    require(raised.durable && raised.brokenStatePersisted,
            "absence must receive a durability proof");
    require(raised.effectiveSeverity == IncidentSeverity::Isolate,
            "raising from absence must preserve ISOLATE");
    require(store.read().provenance == IncidentStateStore::Provenance::Absent,
            "ordinary raise must not create a weaker state");
}

void testSameSizeInPlaceRewriteIsUnprovable(const TempDir& temp) {
    const auto path = statePath(temp);
    writeState(path, "HARD\n");
    IncidentStateStore store(path);
    fic::core::setSecureStatePostReadHookForTests(
        [](const std::filesystem::path& target) {
            std::fstream stream(target, std::ios::in | std::ios::out);
            stream.write("SOFT\n", 5);
            stream.flush();
        });
    const auto read = store.read();
    fic::core::setSecureStatePostReadHookForTests({});
    require(read.provenance == IncidentStateStore::Provenance::Broken,
            "same-size in-place mutation must fail the state proof");
}

void testAbsentRequiresDurabilityBarrier(const TempDir& temp) {
    IncidentStateStore store(statePath(temp));
    int barriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string&) { ++barriers; return false; });
    const auto raised = store.raiseToAtLeast(IncidentSeverity::Soft);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(barriers > 0 && !raised.durable,
            "absence must not be called durable without parent fsync");
    require(store.read().provenance == IncidentStateStore::Provenance::Absent,
            "SOFT raise must not materialize missing state");
}

void testPostRenameFailureFallsBackToDurableAbsence(const TempDir& temp) {
    const auto path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);
    int barriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string&) { return ++barriers > 2; });
    const auto raised = store.raiseToAtLeast(IncidentSeverity::Hard);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(barriers >= 3 && raised.durable && raised.brokenStatePersisted,
            "failed write and retry must run durable BROKEN fallback");
    require(store.read().provenance == IncidentStateStore::Provenance::Absent,
            "reboot observation must be ISOLATE");
}

void testPostRenameFallbackPreservesReplacement(const TempDir& temp) {
    const auto path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    AtomicFileWriter::setRemovePreunlinkHookForTests(
        [&](const std::string& target) {
            ::unlink(target.c_str());
            writeState(target, "STANDARD\n");
        });
    const auto raised = store.raiseToAtLeast(IncidentSeverity::Hard);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    AtomicFileWriter::setRemovePreunlinkHookForTests({});
    require(!raised.durable && !raised.brokenStatePersisted,
            "a swapped target cannot prove durable fallback");
    require(store.read().provenance == IncidentStateStore::Provenance::Proven &&
                store.read().severity == IncidentSeverity::Standard,
            "post-rename fallback must not delete the replacement");
}

// A conditional write whose precondition was invalidated must refuse to
// replace the object instead of silently overwriting it. This is the write
// half of the lost-update protection.
void testStaleWriterCannotLoseAnUpdate(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);

    // Capture the state an optimistic writer would base its write on, then
    // let a concurrent writer escalate first.
    const auto stale = store.read();
    require(stale.provenance == IncidentStateStore::Provenance::Proven,
            "fixture precondition");

    IncidentStateStore winner(path);
    const auto escalated = winner.raiseToAtLeast(IncidentSeverity::Isolate);
    require(escalated.durable, "the winning escalation must persist");

    // The stale precondition no longer matches, so the conditional write must
    // be refused rather than replacing the winner's object.
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = stale.provenState->mode;
    options.fileOwner = stale.provenState->owner;
    options.fileGroup = stale.provenState->group;
    options.expectedTargetState = stale.provenState;

    AtomicWriteResult result;
    std::string error;
    const bool ok = AtomicFileWriter::writeWithResult(
        path.string(), "SOFT\n", options, &error, &result);
    // The refused write reports ok=false together with preconditionFailed=true:
    // nothing was replaced, and the precondition mismatch is a typed, expected
    // outcome rather than an I/O error.
    require(!ok && result.preconditionFailed && !result.installed,
            "a stale conditional write must be refused before replacing");
    require(store.read().severity == IncidentSeverity::Isolate,
            "the winning escalation must survive the stale writer");
}

// ---------------------------------------------------------------------------
// Invariant 6/7: a severity that cannot be made durable must be encoded as a
// DURABLY ABSENT BROKEN_STATE, and a replaced/unknown object must never be
// deleted.
// ---------------------------------------------------------------------------

void testDurableBrokenFallbackEncodesAbsence(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);

    // Encoding BROKEN_STATE must conditionally remove the EXACT proven object
    // and prove the absence durable. Durable absence is the ISOLATE encoding,
    // so the incident survives a reboot instead of reverting to UNLOCKED.
    const auto result = store.encodeDurableBrokenState();
    require(result.durable && result.brokenStatePersisted,
            "a proven object must be conditionally removed: " + result.detail);
    require(result.effectiveSeverity == IncidentSeverity::Isolate,
            "a BROKEN_STATE fallback means ISOLATE");
    require(!std::filesystem::exists(path),
            "the stale UNLOCKED witness must be gone");
    require(store.read().provenance == IncidentStateStore::Provenance::Absent,
            "the durable absence must read back as Absent");
}

// rename(2) published the new severity but the parent directory fsync failed.
// FIC must re-prove the EXACT installed state and retry only the durability
// barrier; a successful retry means the escalation IS durable.
void testInstalledWriteRecoversThroughDurabilityRetry(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);

    int failures = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string&) { return ++failures > 1; });
    const auto raised = store.raiseToAtLeast(IncidentSeverity::Hard);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});

    require(failures >= 2,
            "the fixture must actually have failed a durability barrier");
    require(raised.durable,
            "a successful durability retry must report durable success");
    require(!raised.brokenStatePersisted,
            "a recovered durability barrier must not fall back to BROKEN_STATE");
    require(raised.effectiveSeverity == IncidentSeverity::Hard,
            "the recovered escalation must be HARD");
    require(store.read().severity == IncidentSeverity::Hard,
            "HARD must be the persisted state after the retry");
}

// Neither the requested severity NOR a durable absence can be established:
// the runtime must still be ISOLATE and the caller must see a failed result
// so it can enter the DEGRADED runtime state. FIC must NOT report success.
void testUnconfirmableDurabilityNeverReportsSuccess(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);

    AtomicFileWriter::setDirectoryFsyncHookForTests(fsyncAlwaysFails);
    const auto raised = store.raiseToAtLeast(IncidentSeverity::Hard);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});

    require(!raised.durable,
            "an unprovable escalation must never report durable success");
    require(raised.effectiveSeverity == IncidentSeverity::Isolate,
            "an unprovable state must still mean ISOLATE");
    require(!raised.detail.empty(),
            "the caller must receive a diagnostic for the DEGRADED state");
}

void testBrokenFallbackNeverDeletesAReplacement(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "UNLOCKED\n");
    IncidentStateStore store(path);

    // Replace the object in the window between the conditional-remove proof
    // and the unlink. FIC must detect the swap and delete NOTHING.
    AtomicFileWriter::setRemovePreunlinkHookForTests(
        [&](const std::string& target) {
            ::unlink(target.c_str());
            writeState(target, "attacker controlled content\n");
            ::chmod(target.c_str(), 0640);
        });
    const auto result = store.encodeDurableBrokenState();
    AtomicFileWriter::setRemovePreunlinkHookForTests({});

    require(!result.brokenStatePersisted,
            "a replaced object must never be deleted as a BROKEN_STATE");
    require(std::filesystem::exists(path),
            "the replacement object must survive");
    std::ifstream verify(path);
    std::string persisted;
    std::getline(verify, persisted);
    require(persisted == "attacker controlled content",
            "the replacement content must be untouched, got: " + persisted);
}

void testBrokenFallbackRefusesUnprovableObject(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    // A symlink FIC cannot prove: it must be left alone, and the fail-closed
    // BROKEN_STATE reading of it stands as the persistent witness.
    const std::filesystem::path target = temp.directory / "elsewhere";
    writeState(target, "UNLOCKED\n");
    ::symlink(target.c_str(), path.c_str());

    IncidentStateStore store(path);
    const auto result = store.encodeDurableBrokenState();
    require(!result.brokenStatePersisted,
            "an unprovable object must not be removed");
    require(std::filesystem::is_symlink(path),
            "the symlink must still be in place");
    require(result.effectiveSeverity == IncidentSeverity::Isolate,
            "an unprovable object still means ISOLATE");
}

// ---------------------------------------------------------------------------
// Invariant 8: clear() NEVER uses an unlink fallback. A clear that cannot be
// proven durable fails and the previous incident stays active.
// ---------------------------------------------------------------------------

void testClearRequiresDurableUnlocked(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "HARD\n");
    IncidentStateStore store(path);

    const auto cleared = store.clear();
    require(cleared.ok, "a clear from a proven state must succeed");
    require(store.read().severity == IncidentSeverity::Unlocked,
            "a successful clear must persist UNLOCKED");
}

void testFailedClearRestoresPreviousIncident(const TempDir& temp) {
    const auto path = statePath(temp);
    writeState(path, "HARD\n");
    IncidentStateStore store(path);
    int barriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string&) { return ++barriers > 2; });
    const auto cleared = store.clear();
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!cleared.ok && cleared.effectiveSeverity == IncidentSeverity::Hard,
            "failed clear must restore previous severity");
    const auto read = store.read();
    require(read.provenance == IncidentStateStore::Provenance::Proven &&
                read.severity == IncidentSeverity::Hard,
            "restored HARD must be the live pathname");
}

void testFailedClearFallsBackToDurableBroken(const TempDir& temp) {
    const auto path = statePath(temp);
    writeState(path, "HARD\n");
    IncidentStateStore store(path);
    int barriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string&) { return ++barriers > 4; });
    const auto cleared = store.clear();
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!cleared.ok && cleared.effectiveSeverity == IncidentSeverity::Isolate,
            "failed clear/restore must become ISOLATE");
    require(store.read().provenance == IncidentStateStore::Provenance::Absent,
            "failed clear must leave durably absent BROKEN state");
}

void testClearFailsClosedWhenDurabilityIsUnprovable(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    writeState(path, "HARD\n");
    IncidentStateStore store(path);

    AtomicFileWriter::setDirectoryFsyncHookForTests(fsyncAlwaysFails);
    const auto cleared = store.clear();
    AtomicFileWriter::setDirectoryFsyncHookForTests({});

    require(!cleared.ok,
            "a clear whose durability cannot be proven must fail");
    require(cleared.effectiveSeverity == IncidentSeverity::Isolate,
            "unrecoverable clear must report ISOLATE");
    require(store.read().provenance != IncidentStateStore::Provenance::Proven ||
                store.read().severity != IncidentSeverity::Unlocked,
            "failed clear must not leave usable UNLOCKED");
}

void testClearRefusesUnprovableState(const TempDir& temp) {
    const std::filesystem::path path = statePath(temp);
    const std::filesystem::path target = temp.directory / "elsewhere";
    writeState(target, "UNLOCKED\n");
    ::symlink(target.c_str(), path.c_str());

    IncidentStateStore store(path);
    const auto cleared = store.clear();
    require(!cleared.ok, "clear must fail closed on an unprovable state");
    require(std::filesystem::is_symlink(path),
            "clear must not touch an unprovable object");
}

} // namespace

int main() {
    // The production expectation is root ownership of the state file and of
    // its parent. This suite runs unprivileged, so it proves the same proof
    // chain against the identity it actually owns instead of weakening the
    // production default.
    IncidentStateStore::setOwnershipExpectationForTests(::geteuid(), ::geteuid());

    struct Scenario {
        const char* name;
        void (*run)(const TempDir&);
    };
    const Scenario scenarios[] = {
        {"proven_unlocked_is_the_only_unlocked_state",
         testProvenUnlockedIsTheOnlyUnlockedState},
        {"missing_state_is_not_proven_unlocked",
         testMissingStateIsNotProvenUnlocked},
        {"corrupt_state_is_broken", testCorruptStateIsBroken},
        {"symlink_state_is_broken", testSymlinkStateIsBroken},
        {"wrong_metadata_state_is_broken", testWrongMetadataStateIsBroken},
        {"raise_is_monotonic_and_idempotent", testRaiseIsMonotonicAndIdempotent},
        {"raise_from_absent_preserves_isolate", testRaiseFromAbsentPreservesIsolate},
        {"same_size_in_place_rewrite_is_unprovable",
         testSameSizeInPlaceRewriteIsUnprovable},
        {"absent_requires_durability_barrier", testAbsentRequiresDurabilityBarrier},
        {"post_rename_failure_falls_back_to_durable_absence",
         testPostRenameFailureFallsBackToDurableAbsence},
        {"post_rename_fallback_preserves_replacement",
         testPostRenameFallbackPreservesReplacement},
        {"stale_writer_cannot_lose_an_update", testStaleWriterCannotLoseAnUpdate},
        {"durable_broken_fallback_encodes_absence",
         testDurableBrokenFallbackEncodesAbsence},
        {"installed_write_recovers_through_durability_retry",
         testInstalledWriteRecoversThroughDurabilityRetry},
        {"unconfirmable_durability_never_reports_success",
         testUnconfirmableDurabilityNeverReportsSuccess},
        {"broken_fallback_never_deletes_a_replacement",
         testBrokenFallbackNeverDeletesAReplacement},
        {"broken_fallback_refuses_unprovable_object",
         testBrokenFallbackRefusesUnprovableObject},
        {"clear_requires_durable_unlocked", testClearRequiresDurableUnlocked},
        {"failed_clear_restores_previous_incident", testFailedClearRestoresPreviousIncident},
        {"failed_clear_falls_back_to_durable_broken",
         testFailedClearFallsBackToDurableBroken},
        {"clear_fails_closed_when_durability_is_unprovable",
         testClearFailsClosedWhenDurabilityIsUnprovable},
        {"clear_refuses_unprovable_state", testClearRefusesUnprovableState},
    };

    for (const Scenario& scenario : scenarios) {
        try {
            TempDir temp;
            scenario.run(temp);
            std::cout << "ok - " << scenario.name << '\n';
        } catch (const std::exception& exception) {
            std::cerr << "FAIL - " << scenario.name << ": " << exception.what()
                      << '\n';
            return 1;
        }
    }
    std::cout << sizeof(scenarios) / sizeof(scenarios[0])
              << " incident state scenarios passed\n";
    return 0;
}
