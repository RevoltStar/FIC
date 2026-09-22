#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <rollback/MutationJournal.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

using fic::identity::pam::ManagedHistoryPairInspection;
using fic::identity::pam::ManagedHistoryPairState;
using fic::identity::pam::ManagedPasswordCapability;
using fic::identity::pam::ManagedPasswordSlotInspection;
using fic::identity::pam::ManagedPasswordSlotRole;
using fic::identity::pam::ManagedPasswordSlotState;
using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamManagedPasswordDomain;
using fic::identity::pam::PamManagedPasswordSlotActivationResult;
using fic::identity::pam::PamManagedPasswordSlotOwnership;
using fic::identity::pam::PamManagedPasswordSlotWriter;
using fic::identity::pam::PamManagedPasswordSlots;
using fic::rollback::MutationJournal;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto base = std::filesystem::temp_directory_path();
        root_ = base / ("fic-password-slot-writer-test-" +
                        std::to_string(::getpid()) + "-" +
                        std::to_string(counter++));
        std::filesystem::create_directories(root_);
    }
    ~TemporaryDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
    }
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    const std::filesystem::path& path() const { return root_; }

private:
    static int counter;
    std::filesystem::path root_;
};

int TemporaryDirectory::counter = 0;

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(stream)),
                        std::istreambuf_iterator<char>());
    return content;
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << content;
    require(stream.good(), "test failed to write " + path.string());
}

void removeFile(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
    require(!ec, "test failed to remove " + path.string());
}

std::filesystem::path qualityPath(const TemporaryDirectory& tree) {
    return tree.path() /
        PamManagedPasswordSlots::qualitySlot().fileName;
}

std::filesystem::path historyNormalPath(const TemporaryDirectory& tree) {
    return tree.path() /
        PamManagedPasswordSlots::historyNormalSlot().fileName;
}

std::filesystem::path historyInitialPath(const TemporaryDirectory& tree) {
    return tree.path() /
        PamManagedPasswordSlots::historyInitialSlot().fileName;
}

PolicyRef qualityPolicy() {
    return {"IDENTITY_ACCESS", "PAM", "enable_password_quality"};
}

PolicyRef historyPolicy() {
    return {"IDENTITY_ACCESS", "PAM", "enable_password_history"};
}

ManagedPwhistorySlotOptions historyOptions(unsigned remember) {
    return ManagedPwhistorySlotOptions{std::optional<unsigned>(remember),
        false};
}

std::optional<fic::rollback::MutationStatus> journalStatus(
    MutationJournal& journal, fic::rollback::MutationId id) {
    for (const auto& record : journal.records()) {
        if (record.id == id) {
            return record.status;
        }
    }
    return std::nullopt;
}

std::size_t journalActiveCount(MutationJournal& journal) {
    std::size_t count = 0;
    for (const auto& record : journal.records()) {
        if (record.isActive()) {
            ++count;
        }
    }
    return count;
}

bool prepareDomainRecord(
    MutationJournal& journal, const PolicyRef& policy,
    const std::vector<std::string>& activationIdentifiers,
    fic::rollback::MutationId& id, std::string& error) {
    fic::rollback::MutationRecord record;
    record.policy = policy;
    record.resource = "capability/" + policy.policyName;
    fic::rollback::UndoDisablePamCapability undo;
    undo.capability = policy.policyName;
    undo.topology = fic::rollback::PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = activationIdentifiers;
    record.undo = {fic::rollback::MutationBackend::Pam, undo};
    return journal.prepareMutation(record, id, error);
}

std::string neutral() {
    return PamManagedPasswordSlots::neutralBody();
}

bool renderActiveQuality(std::uint64_t id, std::string& content) {
    std::string error;
    return PamManagedPasswordSlots::renderActiveQuality(id, content, error);
}

bool renderActiveHistoryNormal(
    std::uint64_t id, const ManagedPwhistorySlotOptions& options,
    std::string& content) {
    std::string error;
    return PamManagedPasswordSlots::renderActiveHistoryNormal(
        id, options, content, error);
}

bool renderActiveHistoryInitial(
    std::uint64_t id, const ManagedPwhistorySlotOptions& options,
    std::string& content) {
    std::string error;
    return PamManagedPasswordSlots::renderActiveHistoryInitial(
        id, options, content, error);
}

// Fresh writer fixture: its own journal document inside the tree.
class Fixture {
public:
    explicit Fixture(
        PamManagedPasswordDomain domain,
        const PolicyRef& policy)
        : journal_(tree_.path() / "mutation-journal.json") {
        std::string error;
        require(journal_.initializeOrLoad(error), error);
        writer_.emplace(
            tree_.path(), journal_, policy, domain);
    }

    TemporaryDirectory& tree() { return tree_; }
    MutationJournal& journal() { return journal_; }
    PamManagedPasswordSlotWriter& writer() { return *writer_; }

private:
    TemporaryDirectory tree_;
    MutationJournal journal_;
    std::optional<PamManagedPasswordSlotWriter> writer_;
};

bool prepareQualityRecord(
    Fixture& fixture, fic::rollback::MutationId& id, std::string& error) {
    return prepareDomainRecord(
        fixture.journal(), qualityPolicy(),
        {PamManagedPasswordSlots::qualitySlot().fileName}, id, error);
}

bool prepareHistoryRecord(
    Fixture& fixture, fic::rollback::MutationId& id, std::string& error) {
    return prepareDomainRecord(
        fixture.journal(), historyPolicy(),
        {PamManagedPasswordSlots::historyNormalSlot().fileName,
            PamManagedPasswordSlots::historyInitialSlot().fileName},
        id, error);
}

} // namespace

namespace {

// §36 + negative matrix for the quality domain.
void runQualityTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: quality\n";

    // Neutral + no journal -> activation succeeds, ownership proven,
    // idempotent on the second call with the SAME mutation id.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality, qualityPolicy());
        writeFile(qualityPath(fixture.tree()), neutral());
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(fixture.writer().activateOwnedPasswordQuality(result, error),
            "quality activation should succeed: " + error);
        require(result.success && result.ownershipProven, "proof flags");
        require(result.changedSystemState, "first activation changes state");
        const std::uint64_t firstId = result.mutationId;
        require(firstId != 0, "mutation id");

        PamManagedPasswordSlotOwnership ownership;
        require(fixture.writer().proveOwnedQuality(ownership, error),
            "ownership proof: " + error);
        require(ownership.owned(), "owned");
        require(ownership.mutationId == firstId, "same id");

        PamManagedPasswordSlotActivationResult second;
        require(fixture.writer().activateOwnedPasswordQuality(second, error),
            "idempotent activation: " + error);
        require(second.success && second.ownershipProven, "idempotent proof");
        require(!second.changedSystemState,
            "idempotent activation must not rewrite bytes");
        require(second.mutationId == firstId, "idempotent id preserved");
    }

    // Negative #1: Prepared record + physical fully Active(same id):
    // read-only proof must NOT own, must report MatchingPrepared, and must
    // not complete the record to Applied.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality, qualityPolicy());
        std::string content;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareQualityRecord(fixture, id, error), error);
        require(renderActiveQuality(id, content), "render");
        writeFile(qualityPath(fixture.tree()), content);

        PamManagedPasswordSlotOwnership ownership;
        require(
            !fixture.writer().proveOwnedQuality(ownership, error),
            "Prepared must not be ownership");
        require(
            ownership.journal ==
                fic::identity::pam::PasswordSlotJournalBinding::
                    MatchingPrepared,
            "binding must be MatchingPrepared");
        require(!ownership.owned(), "owned() must be false");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Prepared,
            "read-only proof must not complete Prepared to Applied");

        // Activation over the same state completes the lifecycle.
        PamManagedPasswordSlotActivationResult result;
        require(fixture.writer().activateOwnedPasswordQuality(result, error),
            "activation should complete Prepared: " + error);
        require(
            result.success && result.ownershipProven &&
            result.mutationId == id,
            "Prepared completed with the same id");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Applied,
            "record now Applied");
    }
}
} // namespace

namespace {

void runQualityNegativeTests() {
    // Negative #2: exact-domain matching. Physical Active(42), but journal
    // record 42 belongs to the history domain -> proveOwnedQuality must
    // fail closed even though the id matches.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality, qualityPolicy());
        std::string content;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(fixture.journal().setStatus(
            id, fic::rollback::MutationStatus::Applied, error), error);
        require(renderActiveQuality(id, content), "render");
        writeFile(qualityPath(fixture.tree()), content);

        PamManagedPasswordSlotOwnership ownership;
        require(
            !fixture.writer().proveOwnedQuality(ownership, error),
            "same id with foreign domain metadata must fail closed");
        require(!ownership.owned(), "owned() must be false");
    }

    // §43: canonical Active slot without any journal record -> both proof
    // and activation fail closed and never adopt the foreign state.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality, qualityPolicy());
        std::string content;
        std::string error;
        require(renderActiveQuality(777, content), "render");
        writeFile(qualityPath(fixture.tree()), content);

        PamManagedPasswordSlotOwnership ownership;
        require(
            !fixture.writer().proveOwnedQuality(ownership, error),
            "Active without journal must not own");
        require(!ownership.owned(), "owned() must be false");

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordQuality(result, error),
            "activation over foreign Active must fail closed");
        require(
            readFile(qualityPath(fixture.tree())) == content,
            "foreign Active bytes must be untouched");
    }

    // Broken slot -> fail closed for both proof and activation.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality, qualityPolicy());
        writeFile(qualityPath(fixture.tree()), "pam_pwquality.so\n");
        std::string error;
        PamManagedPasswordSlotOwnership ownership;
        require(!fixture.writer().proveOwnedQuality(ownership, error),
            "broken slot must not own");
        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordQuality(result, error),
            "activation over broken slot must fail closed");
    }
}
} // namespace

namespace {

void runHistoryTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: history\n";

    // §37: Neutral pair -> activation as ONE logical mutation; both files
    // carry the same id; proof returns the options; idempotent.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        writeFile(historyNormalPath(fixture.tree()), neutral());
        writeFile(historyInitialPath(fixture.tree()), neutral());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "history activation should succeed: " + error);
        require(result.success && result.ownershipProven, "proof flags");
        require(result.changedSystemState, "state changed");
        const std::uint64_t firstId = result.mutationId;
        require(firstId != 0, "mutation id");

        PamManagedPasswordSlotOwnership ownership;
        require(fixture.writer().proveOwnedHistory(ownership, error),
            "ownership proof: " + error);
        require(ownership.owned(), "owned");
        require(ownership.mutationId == firstId, "same id");
        require(
            ownership.historyOptions.has_value() &&
                *ownership.historyOptions == options,
            "observed options");

        PamManagedPasswordSlotActivationResult second;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, second, error),
            "idempotent activation: " + error);
        require(second.success && second.ownershipProven, "idempotent proof");
        require(!second.changedSystemState, "no rewrite");
        require(second.mutationId == firstId, "id preserved");
    }

    // Different desired options over a proven Applied pair: fail closed,
    // no silent rewrite with a new mutation id.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        writeFile(historyNormalPath(fixture.tree()), neutral());
        writeFile(historyInitialPath(fixture.tree()), neutral());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "setup activation");
        const std::uint64_t firstId = result.mutationId;

        const ManagedPwhistorySlotOptions changed = historyOptions(16);
        PamManagedPasswordSlotActivationResult rejected;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                changed, rejected, error),
            "option transition must fail closed on this step");
        require(!rejected.ownershipProven, "no proof for rejected call");
        PamManagedPasswordSlotOwnership ownership;
        require(fixture.writer().proveOwnedHistory(ownership, error),
            "pair still owned");
        require(ownership.mutationId == firstId, "old id preserved");
    }
}
} // namespace

namespace {

void runHistoryNegativeTests() {
    // Negative #1: Prepared + full Active pair with the same id ->
    // MatchingPrepared, not owned, record stays Prepared; then activation
    // completes the lifecycle with the same id.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        std::string normalContent;
        std::string initialContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(
            renderActiveHistoryNormal(id, options, normalContent) &&
                renderActiveHistoryInitial(id, options, initialContent),
            "render pair");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), initialContent);

        PamManagedPasswordSlotOwnership ownership;
        require(
            !fixture.writer().proveOwnedHistory(ownership, error),
            "Prepared pair must not be ownership");
        require(
            ownership.journal ==
                fic::identity::pam::PasswordSlotJournalBinding::
                    MatchingPrepared,
            "binding must be MatchingPrepared");
        require(!ownership.owned(), "owned() must be false");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Prepared,
            "proof must not complete Prepared");

        PamManagedPasswordSlotActivationResult result;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "activation should complete Prepared pair: " + error);
        require(
            result.success && result.ownershipProven &&
            result.mutationId == id,
            "Prepared pair completed with the same id");
    }

    // §43: Active pair without journal -> proof and activation fail
    // closed; bytes untouched.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        std::string normalContent;
        std::string initialContent;
        std::string error;
        require(
            renderActiveHistoryNormal(555, options, normalContent) &&
                renderActiveHistoryInitial(555, options, initialContent),
            "render pair");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), initialContent);

        PamManagedPasswordSlotOwnership ownership;
        require(
            !fixture.writer().proveOwnedHistory(ownership, error),
            "foreign pair must not own");
        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "activation over foreign pair must fail closed");
        require(
            readFile(historyNormalPath(fixture.tree())) == normalContent &&
                readFile(historyInitialPath(fixture.tree())) ==
                    initialContent,
            "foreign pair bytes untouched");
    }
}
} // namespace

namespace {

void runFaultAndCompensationTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: faults\n";

    // §38: before-hook failure on the FIRST history write -> exact restore
    // of both prior bytes, Prepared discarded, no system state change.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        writeFile(historyNormalPath(fixture.tree()), neutral());
        writeFile(historyInitialPath(fixture.tree()), neutral());
        fixture.writer().setBeforeSlotWriteHookForTests(
            [](std::size_t) { return false; });

        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "injected before-failure must fail");
        require(!result.changedSystemState, "bytes restored exactly");
        require(!result.ownershipProven, "no ownership");
        require(
            readFile(historyNormalPath(fixture.tree())) == neutral() &&
                readFile(historyInitialPath(fixture.tree())) == neutral(),
            "both neutral files restored exactly");
        require(journalActiveCount(fixture.journal()) == 0,
            "Prepared discarded after proven restore");
    }

    // §39: before-hook failure on the SECOND history write -> the first
    // committed write is restored to its exact prior bytes.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        writeFile(historyNormalPath(fixture.tree()), neutral());
        writeFile(historyInitialPath(fixture.tree()), neutral());
        fixture.writer().setBeforeSlotWriteHookForTests(
            [](std::size_t slotIndex) { return slotIndex == 0; });

        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "injected second-write failure must fail");
        require(!result.changedSystemState, "fully compensated");
        require(
            readFile(historyNormalPath(fixture.tree())) == neutral() &&
                readFile(historyInitialPath(fixture.tree())) == neutral(),
            "first write rolled back exactly");
        require(journalActiveCount(fixture.journal()) == 0,
            "Prepared discarded after proven restore");
    }
}
} // namespace

namespace {

void runCompensationAndFreshVerifyTests() {
    // §39b: after-hook failure on the SECOND write (hook returns false
    // while leaving bytes committed) -> both files back to exact prior
    // bytes, Prepared discarded.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        writeFile(historyNormalPath(fixture.tree()), neutral());
        writeFile(historyInitialPath(fixture.tree()), neutral());
        fixture.writer().setAfterSlotWriteHookForTests(
            [](std::size_t slotIndex) { return slotIndex == 0; });

        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "injected after-failure must fail");
        require(!result.changedSystemState, "fully compensated");
        require(
            readFile(historyNormalPath(fixture.tree())) == neutral() &&
                readFile(historyInitialPath(fixture.tree())) == neutral(),
            "both files restored exactly after post-write failure");
        require(journalActiveCount(fixture.journal()) == 0,
            "Prepared discarded after proven restore");
    }

    // §41: fresh-verify failure path. The after-hook tampers with the
    // quality slot so the fresh re-read cannot report the exact Prepared
    // id -> the write is rolled back, no system state change, Prepared
    // discarded.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality, qualityPolicy());
        fixture.writer().setAfterSlotWriteHookForTests(
            [&fixture](std::size_t) {
                writeFile(qualityPath(fixture.tree()), "tampered\n");
                return true;
            });

        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            !fixture.writer().activateOwnedPasswordQuality(result, error),
            "tampered fresh proof must fail");
        require(!result.changedSystemState, "rolled back");
        require(!result.ownershipProven, "no ownership");
        require(journalActiveCount(fixture.journal()) == 0,
            "Prepared discarded after proven rollback");
    }
}
} // namespace

namespace {

void runCrashPartialTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: crash partial\n";

    // §40: crash-partial compensation on the next activation. Journal
    // record stays Prepared, normal slot Active(id), initial slot Neutral
    // -> the next activation must neutralize only the exact-id slot,
    // discard the Prepared record and perform a fresh activation with a
    // NEW id.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        std::string normalContent;
        std::string initialContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(
            renderActiveHistoryNormal(id, options, normalContent) &&
                renderActiveHistoryInitial(id, options, initialContent),
            "render pair");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        PamManagedPasswordSlotOwnership ownership;
        require(!fixture.writer().proveOwnedHistory(ownership, error),
            "partial pair must not own");

        PamManagedPasswordSlotActivationResult result;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "next activation should recover the crash-partial: " + error);
        require(
            result.success && result.ownershipProven &&
            result.changedSystemState,
            "recovered with a fresh mutation");
        require(result.mutationId != id, "new mutation id");
        require(journalStatus(fixture.journal(), id) == std::nullopt,
            "stale Prepared discarded");
        require(
            journalStatus(fixture.journal(), result.mutationId) ==
                fic::rollback::MutationStatus::Applied,
            "new record Applied");
    }

    // Foreign-id partial (slot Active with another id, record Prepared)
    // must NOT be compensated: fail closed.
    {
        Fixture fixture(PamManagedPasswordDomain::History, historyPolicy());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        std::string foreignNormal;
        std::string error;
        fic::rollback::MutationId foreignId = 0;
        require(prepareHistoryRecord(fixture, foreignId, error), error);
        require(
            renderActiveHistoryNormal(foreignId + 1, options, foreignNormal),
            "render foreign partial");
        writeFile(historyNormalPath(fixture.tree()), foreignNormal);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        PamManagedPasswordSlotActivationResult rejected;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, rejected, error),
            "foreign-id partial must fail closed");
    }
}
} // namespace

int main() {
    try {
        runQualityTests();
        runQualityNegativeTests();
        runHistoryTests();
        runHistoryNegativeTests();
        runFaultAndCompensationTests();
        runCompensationAndFreshVerifyTests();
        runCrashPartialTests();
        std::cout << "PamManagedPasswordSlotWriterTests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PamManagedPasswordSlotWriterTests FAILED: "
                  << error.what() << "\n";
        return 1;
    }
}
