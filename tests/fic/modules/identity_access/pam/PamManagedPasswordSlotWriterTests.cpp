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

const fic::rollback::MutationRecord* findRecord(
    MutationJournal& journal, fic::rollback::MutationId id) {
    for (const auto& record : journal.records()) {
        if (record.id == id) {
            return &record;
        }
    }
    return nullptr;
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

// Fresh writer fixture: its own journal document inside the tree. The
// canonical PolicyRef is derived inside the writer from the domain (P1-2):
// tests use exactly the production API.
class Fixture {
public:
    explicit Fixture(PamManagedPasswordDomain domain)
        : journal_(tree_.path() / "mutation-journal.json") {
        std::string error;
        require(journal_.initializeOrLoad(error), error);
        writer_.emplace(tree_.path(), journal_, domain);
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
    // Canonical Step 3 journal payload (P1-3): the permanent hook profile
    // id, never the slot filename.
    return prepareDomainRecord(
        fixture.journal(), qualityPolicy(),
        {"fic-password-quality-hook"}, id, error);
}

bool prepareHistoryRecord(
    Fixture& fixture, fic::rollback::MutationId& id, std::string& error) {
    // Canonical Step 3 journal payload (P1-3): ONE dual-stack hook profile
    // id for both physical slots.
    return prepareDomainRecord(
        fixture.journal(), historyPolicy(),
        {"fic-password-history-hook"}, id, error);
}

} // namespace

namespace {

// §36 + negative matrix for the quality domain.
void runQualityTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: quality\n";

    // Neutral + no journal -> activation succeeds, ownership proven,
    // idempotent on the second call with the SAME mutation id.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality);
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
        Fixture fixture(PamManagedPasswordDomain::Quality);
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
        Fixture fixture(PamManagedPasswordDomain::Quality);
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
        Fixture fixture(PamManagedPasswordDomain::Quality);
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
        Fixture fixture(PamManagedPasswordDomain::Quality);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
        Fixture fixture(PamManagedPasswordDomain::Quality);
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
        Fixture fixture(PamManagedPasswordDomain::History);
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
    // must NOT be compensated: fail closed, zero physical mutation.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
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
        require(!rejected.ownershipProven, "no ownership");
        require(!rejected.changedSystemState,
            "P1-4: foreign-id partial must not change the system state");
        require(
            readFile(historyNormalPath(fixture.tree())) == foreignNormal &&
                readFile(historyInitialPath(fixture.tree())) == neutral(),
            "foreign-id partial bytes must be untouched");
    }
}
} // namespace

namespace {

// P1-2 canonical domain mapping (security identity, not caller input).
void requireCanonicalDomainMapping() {
    require(
        PamManagedPasswordSlotWriter::canonicalPolicyRef(
            PamManagedPasswordDomain::Quality) ==
            PolicyRef{"IDENTITY_ACCESS", "PAM", "enable_password_quality"},
        "quality domain must map to enable_password_quality");
    require(
        PamManagedPasswordSlotWriter::canonicalPolicyRef(
            PamManagedPasswordDomain::History) ==
            PolicyRef{"IDENTITY_ACCESS", "PAM", "enable_password_history"},
        "history domain must map to enable_password_history");
}

} // namespace

namespace {

// P1-3 + P1-2: the journal payload identity created by real activations.
void runJournalPayloadTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: journal payload\n";
    requireCanonicalDomainMapping();

    // Quality: activation must journal the permanent hook profile id and
    // the canonical policy/resource identity.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality);
        writeFile(qualityPath(fixture.tree()), neutral());
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(fixture.writer().activateOwnedPasswordQuality(result, error),
            "quality activation: " + error);
        const fic::rollback::MutationRecord* record =
            findRecord(fixture.journal(), result.mutationId);
        require(record != nullptr, "quality record exists");
        const auto* payload =
            std::get_if<fic::rollback::UndoDisablePamCapability>(
                &record->undo.payload);
        require(payload != nullptr, "quality PAM payload");
        require(
            payload->activationIdentifiers ==
                std::vector<std::string>{"fic-password-quality-hook"},
            "quality activationIdentifiers must be exactly the permanent "
            "hook profile id (P1-3)");
        require(
            record->policy ==
                PamManagedPasswordSlotWriter::canonicalPolicyRef(
                    PamManagedPasswordDomain::Quality),
            "quality canonical PolicyRef (P1-2)");
        require(
            record->resource == "capability/enable_password_quality",
            "quality canonical resource");
    }

    // History: ONE dual-stack hook profile identifier for both slots.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        writeFile(historyNormalPath(fixture.tree()), neutral());
        writeFile(historyInitialPath(fixture.tree()), neutral());
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "history activation: " + error);
        const fic::rollback::MutationRecord* record =
            findRecord(fixture.journal(), result.mutationId);
        require(record != nullptr, "history record exists");
        const auto* payload =
            std::get_if<fic::rollback::UndoDisablePamCapability>(
                &record->undo.payload);
        require(payload != nullptr, "history PAM payload");
        require(
            payload->activationIdentifiers ==
                std::vector<std::string>{"fic-password-history-hook"},
            "history activationIdentifiers must be exactly the single "
            "dual-stack hook profile id (P1-3)");
        require(
            record->policy ==
                PamManagedPasswordSlotWriter::canonicalPolicyRef(
                    PamManagedPasswordDomain::History),
            "history canonical PolicyRef (P1-2)");
        require(
            record->resource == "capability/enable_password_history",
            "history canonical resource");
    }
}
} // namespace

namespace {

// P1-1: witness-aware journal lifecycle gates.
void runJournalLifecycleTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: journal lifecycle\n";

    // Raw load() on a virgin path: usable == true but
    // lifecycleInitialized == false. The writer must NOT treat this as
    // operational provenance: activation runs the witness-aware lifecycle
    // (virgin bootstrap here) first and only then mutates.
    {
        TemporaryDirectory tree;
        MutationJournal journal(tree.path() / "mutation-journal.json");
        std::string error;
        require(journal.load(error), "raw load of a virgin path");
        require(journal.usable(), "raw load is usable");
        require(!journal.lifecycleInitialized(),
            "raw load must NOT establish the witness-aware lifecycle");

        writeFile(qualityPath(tree), neutral());
        PamManagedPasswordSlotWriter writer(
            tree.path(), journal, PamManagedPasswordDomain::Quality);
        PamManagedPasswordSlotActivationResult result;
        require(writer.activateOwnedPasswordQuality(result, error),
            "activation must recover through the witness-aware lifecycle: " +
                error);
        require(result.success && result.ownershipProven, "activated");
        require(journal.lifecycleInitialized(),
            "lifecycle established by the writer before the mutation");
        require(std::filesystem::exists(journal.witnessPath()),
            "witness exists after operational initialization");
    }

    // Raw-loaded EXISTING journal with a missing witness: the operational
    // writer migrates through the witness-aware lifecycle (durable witness
    // creation) before any mutation.
    {
        TemporaryDirectory tree;
        const auto journalPath = tree.path() / "mutation-journal.json";
        {
            MutationJournal bootstrap(journalPath);
            std::string error;
            require(bootstrap.initializeOrLoad(error), error);
        }
        removeFile(journalPath.string() + ".initialized");

        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), "raw load");
        require(
            journal.usable() && !journal.lifecycleInitialized(),
            "raw-loaded existing journal without witness");

        writeFile(qualityPath(tree), neutral());
        PamManagedPasswordSlotWriter writer(
            tree.path(), journal, PamManagedPasswordDomain::Quality);
        PamManagedPasswordSlotActivationResult result;
        require(writer.activateOwnedPasswordQuality(result, error),
            "operational migration must precede the mutation: " + error);
        require(result.success && result.ownershipProven, "activated");
        require(std::filesystem::exists(journal.witnessPath()),
            "witness created by the migration");
        require(journal.lifecycleInitialized(), "lifecycle initialized");
    }

    // Read-only raw-load negative (missing witness): J exists, W missing,
    // raw load succeeds; proveOwnedQuality must FAIL, create NO witness
    // and leave journal and slot bytes untouched.
    {
        TemporaryDirectory tree;
        const auto journalPath = tree.path() / "mutation-journal.json";
        {
            MutationJournal bootstrap(journalPath);
            std::string error;
            require(bootstrap.initializeOrLoad(error), error);
        }
        removeFile(journalPath.string() + ".initialized");

        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), "raw load");
        require(
            journal.usable() && !journal.lifecycleInitialized(),
            "raw-loaded existing journal without witness");

        // Canonical Active physical slot matching an Applied record of the
        // same domain — the proof would succeed if the lifecycle gate were
        // bypassed.
        PolicyRef policy =
            PamManagedPasswordSlotWriter::canonicalPolicyRef(
                PamManagedPasswordDomain::Quality);
        fic::rollback::MutationId id = 0;
        require(
            prepareDomainRecord(
                journal, policy, {"fic-password-quality-hook"}, id, error),
            error);
        require(
            journal.setStatus(
                id, fic::rollback::MutationStatus::Applied, error),
            error);
        std::string content;
        require(renderActiveQuality(id, content), "render");
        writeFile(qualityPath(tree), content);

        PamManagedPasswordSlotWriter writer(
            tree.path(), journal, PamManagedPasswordDomain::Quality);
        PamManagedPasswordSlotOwnership ownership;
        require(!writer.proveOwnedQuality(ownership, error),
            "read-only proof must fail closed without a witness");
        require(!ownership.owned(), "owned() must be false");
        require(!std::filesystem::exists(journal.witnessPath()),
            "read-only proof must NOT create the witness");
        require(journalActiveCount(journal) == 1, "journal untouched");
        require(
            readFile(qualityPath(tree)) == content, "slot bytes untouched");
    }

    // Read-only valid-witness positive: J + valid W exist; a fresh journal
    // object has not yet published the lifecycle; the read-only validation
    // proves the persistent pair and ownership succeeds without any write.
    {
        TemporaryDirectory tree;
        const auto journalPath = tree.path() / "mutation-journal.json";
        {
            MutationJournal bootstrap(journalPath);
            std::string error;
            require(bootstrap.initializeOrLoad(error), error);
            PolicyRef policy =
                PamManagedPasswordSlotWriter::canonicalPolicyRef(
                    PamManagedPasswordDomain::Quality);
            fic::rollback::MutationId id = 0;
            require(
                prepareDomainRecord(
                    bootstrap, policy, {"fic-password-quality-hook"}, id,
                    error),
                error);
            require(
                bootstrap.setStatus(
                    id, fic::rollback::MutationStatus::Applied, error),
                error);
            std::string content;
            require(renderActiveQuality(id, content), "render");
            writeFile(qualityPath(tree), content);
        }
        MutationJournal journal(journalPath);
        require(!journal.lifecycleInitialized(),
            "fresh journal object has not published the lifecycle");

        PamManagedPasswordSlotWriter writer(
            tree.path(), journal, PamManagedPasswordDomain::Quality);
        PamManagedPasswordSlotOwnership ownership;
        std::string error;
        require(writer.proveOwnedQuality(ownership, error),
            "read-only validation must prove the persistent pair: " + error);
        require(ownership.owned(), "owned");
        require(journal.usable(), "usable after validation");
        require(journal.lifecycleInitialized(),
            "lifecycle established by the read-only validation");
        require(std::filesystem::exists(journal.witnessPath()),
            "witness was pre-existing, not created by the proof");
    }
}
} // namespace

namespace {

// P1-3 negative: the legacy erroneous payload (slot filenames as
// activationIdentifiers) must classify as foreign in the canonical Step 3
// domain — ownership proof fails closed even with the exact same id and
// policy.
void runLegacyPayloadNegativeTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: legacy payload\n";

    // Quality record with the legacy slot-filename payload.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality);
        std::string content;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(
            prepareDomainRecord(
                fixture.journal(), qualityPolicy(),
                {PamManagedPasswordSlots::qualitySlot().fileName}, id,
                error),
            error);
        require(
            fixture.journal().setStatus(
                id, fic::rollback::MutationStatus::Applied, error),
            error);
        require(renderActiveQuality(id, content), "render");
        writeFile(qualityPath(fixture.tree()), content);

        PamManagedPasswordSlotOwnership ownership;
        require(!fixture.writer().proveOwnedQuality(ownership, error),
            "legacy slot-filename payload must not own (P1-3)");
        require(!ownership.owned(), "owned() must be false");
    }

    // History record with the legacy two-slot-filenames payload.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        const ManagedPwhistorySlotOptions options = historyOptions(12);
        std::string normalContent;
        std::string initialContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(
            prepareDomainRecord(
                fixture.journal(), historyPolicy(),
                {PamManagedPasswordSlots::historyNormalSlot().fileName,
                    PamManagedPasswordSlots::historyInitialSlot().fileName},
                id, error),
            error);
        require(
            fixture.journal().setStatus(
                id, fic::rollback::MutationStatus::Applied, error),
            error);
        require(
            renderActiveHistoryNormal(id, options, normalContent) &&
                renderActiveHistoryInitial(id, options, initialContent),
            "render pair");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), initialContent);

        PamManagedPasswordSlotOwnership ownership;
        require(!fixture.writer().proveOwnedHistory(ownership, error),
            "legacy two-filename payload must not own (P1-3)");
        require(!ownership.owned(), "owned() must be false");
    }
}
} // namespace

namespace {

// P1-4: changedSystemState accumulates across the Prepared crash-partial
// recovery phase and the subsequent fresh activation.
void runRecoveryAccountingTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: recovery accounting\n";

    // Entry state: normal Active(id) + initial Neutral (exact crash
    // partial). The recovery neutralizes the Active slot (real physical
    // change); the subsequent fresh activation fails BEFORE its first
    // write. The overall result must keep changedSystemState == true
    // because the physical state changed relative to the entry state:
    // BEFORE: Active(id) + Neutral, AFTER: Neutral + Neutral.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
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

        // The recovery neutralization write (the first index-0 write) is
        // allowed to commit; the FRESH activation's first write (the
        // second index-0 write) fails BEFORE any physical commit. This
        // isolates the recovery-phase physical change from any fresh-phase
        // write.
        fixture.writer().setBeforeSlotWriteHookForTests(
            [indexZeroWrites = 0](std::size_t slotIndex) mutable {
                return slotIndex != 0 || ++indexZeroWrites <= 1;
            });

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "fresh activation must fail on the injected fault");
        require(!result.ownershipProven, "no ownership");
        require(result.changedSystemState,
            "P1-4: recovery neutralization must survive the fresh "
            "activation failure");
        require(
            readFile(historyNormalPath(fixture.tree())) == neutral() &&
                readFile(historyInitialPath(fixture.tree())) == neutral(),
            "final physical state: both slots neutral");
        require(journalStatus(fixture.journal(), id) == std::nullopt,
            "stale Prepared discarded by the recovery");
        require(journalActiveCount(fixture.journal()) == 0,
            "no active records remain (fresh Prepared compensated)");
    }

    // Same entry state, but the fresh activation succeeds: the recovery
    // and the fresh mutation both count (explicit accumulated accounting).
    {
        Fixture fixture(PamManagedPasswordDomain::History);
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

        PamManagedPasswordSlotActivationResult result;
        require(
            fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "recovery + fresh activation: " + error);
        require(
            result.success && result.ownershipProven &&
                result.changedSystemState,
            "physical change accumulated across both phases");
        require(result.mutationId != id, "new mutation id");
    }
}
} // namespace

namespace {

// P1-5/P1-6: neutralizeSlotForPreparedCompensation reports its physical-
// change outcome independently of success/failure, and its exact-ID proof
// is bound to the same PamConfigFileSnapshot that performs the conditional
// write. These tests drive the helper through the public activation API
// and cover, for the Prepared crash-partial recovery phase:
//   B. failure before any physical commit       -> changedSystemState false
//   C. installed write + proven exact rollback  -> changedSystemState false
//   D1. write success + fresh-proof failure     -> changedSystemState true
//   D2. installed write + failed rollback (external replacement; UID-
//       independent)                            -> changedSystemState true
//   T1. concurrent Active(A) -> Active(B) between proof and write ->
//       conditional write fails closed, B untouched, changed=false
// (A: successful neutralization changed=true and E: recovery success +
// fresh failure changed=true are covered by runCrashPartialTests and
// runRecoveryAccountingTests; F: foreign-id partial changed=false and
// bytes untouched is covered by runCrashPartialTests too.)
void runNeutralizationAccountingTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: neutralization "
                 "accounting\n";
    const ManagedPwhistorySlotOptions options = historyOptions(12);

    // B: the before-write fault fires on the recovery neutralization write
    // (slot index 0) BEFORE any physical commit: the helper must fail with
    // changedSystemState == false and the entry state must be untouched.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        std::string normalContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(
            renderActiveHistoryNormal(id, options, normalContent),
            "render normal");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        fixture.writer().setBeforeSlotWriteHookForTests(
            [](std::size_t) { return false; });

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "neutralization before-fault must fail the activation");
        require(!result.ownershipProven, "no ownership");
        require(
            !result.changedSystemState,
            "B: pre-commit neutralization failure must not report a "
            "system change");
        require(
            readFile(historyNormalPath(fixture.tree())) == normalContent,
            "B: normal slot entry bytes untouched");
        require(
            readFile(historyInitialPath(fixture.tree())) == neutral(),
            "B: initial slot entry bytes untouched");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Prepared,
            "B: Prepared record must stay for the existing lifecycle");
    }

    // C: the after-write fault fires AFTER the neutralization write was
    // physically installed: the helper rolls the exact prior bytes back
    // and proves the restoration, so the physical entry state is fully
    // restored and changedSystemState == false is correct.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        std::string normalContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(
            renderActiveHistoryNormal(id, options, normalContent),
            "render normal");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        fixture.writer().setAfterSlotWriteHookForTests(
            [](std::size_t) { return false; });

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "neutralization after-fault must fail the activation");
        require(!result.ownershipProven, "no ownership");
        require(
            !result.changedSystemState,
            "C: installed write with a proven exact rollback must not "
            "report a system change");
        require(
            readFile(historyNormalPath(fixture.tree())) == normalContent,
            "C: normal slot exactly restored to Active(prepared id)");
        require(
            readFile(historyInitialPath(fixture.tree())) == neutral(),
            "C: initial slot untouched");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Prepared,
            "C: Prepared record must stay (helper failed before discard)");
    }

    // D1 (mandatory regression): the compensation write SUCCEEDS
    // physically, then the fresh post-write proof fails (the after-hook
    // leaves the write committed but tampers the slot into a Broken
    // body). The helper must return failure WITH changedSystemState ==
    // true and the top-level activation must propagate it.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        std::string normalContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(
            renderActiveHistoryNormal(id, options, normalContent),
            "render normal");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        const std::filesystem::path normalPath =
            historyNormalPath(fixture.tree());
        const std::string tamperedBody =
            "# FIC managed password slot: state=active\nmutation=nope\n";
        fixture.writer().setAfterSlotWriteHookForTests(
            [normalPath, tamperedBody](std::size_t slotIndex) {
                if (slotIndex != 0) {
                    return true;
                }
                // The neutralization write is committed: tamper the slot
                // so the fresh post-write proof fails while the physical
                // mutation stands.
                writeFile(normalPath, tamperedBody);
                return true;
            });

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "D1: fresh-proof failure inside neutralization must fail the "
            "activation");
        require(!result.ownershipProven, "D1: no ownership");
        require(
            result.changedSystemState,
            "D1: committed neutralization write followed by a failed "
            "fresh proof must report changedSystemState == true");
        require(
            readFile(normalPath) == tamperedBody,
            "D1: the physically installed (tampered) state must remain "
            "visible — no silent clean-failure claim");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Prepared,
            "D1: Prepared record must stay (recovery did not complete)");
    }

    // D2 (installed write + rollback failure, UID-independent): the
    // after-hook fires AFTER the neutralization was physically installed
    // and committed, then performs an EXTERNAL replacement of the target
    // and fails the write. The exact rollback must refuse to touch the
    // foreign state (mutated identity/content mismatch) and fail closed:
    // the physical change remains and changedSystemState must be true.
    // Unlike the previous chmod-based variant this does not rely on DAC
    // permission denial, so it is deterministic under root and non-root.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        std::string normalContent;
        std::string error;
        fic::rollback::MutationId id = 0;
        require(prepareHistoryRecord(fixture, id, error), error);
        require(
            renderActiveHistoryNormal(id, options, normalContent),
            "render normal");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        const std::filesystem::path normalPath =
            historyNormalPath(fixture.tree());
        const std::string foreignBody =
            "# FIC managed password slot: state=active\n"
            "capability=password\nmutation=999999\n";
        fixture.writer().setAfterSlotWriteHookForTests(
            [normalPath, foreignBody](std::size_t slotIndex) {
                if (slotIndex != 0) {
                    return true;
                }
                // The neutralization bytes are installed and owned by the
                // transaction: an external actor now replaces the target
                // and the write reports failure. Rollback ownership over
                // the foreign state is gone, deterministically for any
                // uid.
                writeFile(normalPath, foreignBody);
                return false;
            });

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "D2: installed write with failed rollback must fail the "
            "activation");
        require(!result.ownershipProven, "D2: no ownership");
        require(
            result.changedSystemState,
            "D2: installed write whose rollback failed must report "
            "changedSystemState == true");
        require(
            readFile(historyNormalPath(fixture.tree())) == foreignBody,
            "D2: the foreign replacement must remain untouched — rollback "
            "must not restore FIC bytes over external state");
        require(
            readFile(historyInitialPath(fixture.tree())) == neutral(),
            "D2: initial slot untouched");
        require(
            journalStatus(fixture.journal(), id) ==
                fic::rollback::MutationStatus::Prepared,
            "D2: Prepared record must stay for the existing lifecycle");
    }

    // T1 (P1-6 mandatory regression, concurrent foreign replacement between
    // the exact-ID proof and the conditional write): the before-hook fires
    // after the proof of Active(A) but BEFORE the transaction write and
    // replaces the slot with canonical Active(B), B != A. The conditional
    // write must fail on the expectedTargetState mismatch BEFORE any
    // install; the snapshot stays Captured, so rollback must be a no-op and
    // must NEVER restore Active(A) over the foreign Active(B). FIC did not
    // install anything, so changedSystemState must stay false even though
    // the on-disk state differs from the proof snapshot.
    {
        Fixture fixture(PamManagedPasswordDomain::History);
        std::string normalContent;
        std::string error;
        fic::rollback::MutationId idA = 0;
        require(prepareHistoryRecord(fixture, idA, error), error);
        require(
            renderActiveHistoryNormal(idA, options, normalContent),
            "render Active(A)");
        writeFile(historyNormalPath(fixture.tree()), normalContent);
        writeFile(historyInitialPath(fixture.tree()), neutral());

        const std::filesystem::path normalPath =
            historyNormalPath(fixture.tree());
        const std::uint64_t idB = idA + 1;
        std::string foreignActiveB;
        require(
            renderActiveHistoryNormal(idB, options, foreignActiveB),
            "render Active(B)");
        require(foreignActiveB != normalContent, "B bytes differ from A");

        fixture.writer().setBeforeSlotWriteHookForTests(
            [normalPath, foreignActiveB](std::size_t slotIndex) {
                if (slotIndex != 0) {
                    return true;
                }
                // External actor: Active(A) -> Active(B) after the proof,
                // before the conditional write. Proceed with the write so
                // the transaction itself must detect the state mismatch.
                writeFile(normalPath, foreignActiveB);
                return true;
            });

        PamManagedPasswordSlotActivationResult result;
        require(
            !fixture.writer().activateOwnedPasswordHistory(
                options, result, error),
            "T1: conditional write over a concurrently replaced target "
            "must fail closed");
        require(!result.ownershipProven, "T1: no ownership");
        require(
            !result.changedSystemState,
            "T1: FIC installed nothing — an external replacement must not "
            "be reported as a FIC system change");
        require(
            readFile(normalPath) == foreignActiveB,
            "T1: foreign Active(B) must remain byte-for-byte untouched — "
            "FIC must not neutralize B and must not restore A over B");
        require(
            readFile(historyInitialPath(fixture.tree())) == neutral(),
            "T1: initial slot untouched");
        require(
            journalStatus(fixture.journal(), idA) ==
                fic::rollback::MutationStatus::Prepared,
            "T1: Prepared(A) must remain for the existing recovery "
            "lifecycle");
        require(journalActiveCount(fixture.journal()) == 1,
            "T1: no additional journal records (no FIC write happened)");
    }
}

// C2 per-identity lifecycle: partial-state propagation contract of
// activateC2Slot() (see the PamManagedPasswordSlotActivationResult
// mutationId failure contract).
void runC2LifecycleTests() {
    std::cout << "PamManagedPasswordSlotWriterTests: C2 lifecycle\n";

    // W-C2: the journal Prepared -> Applied completion fails AFTER the
    // physical slot write persisted and was freshly proven. The failure
    // must be honest (changedSystemState) and must propagate the exact
    // outstanding Prepared activation id to the caller; the caller then
    // compensates it through compensateC2ActiveSlot().
    {
        Fixture fixture(PamManagedPasswordDomain::Quality);
        writeFile(qualityPath(fixture.tree()), neutral());
        fixture.writer().setJournalCompletionFaultHookForTests(
            [] { return false; });
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(!fixture.writer().activateC2Slot(
                ManagedPasswordSlotRole::Quality, historyOptions(3),
                result, error),
            "W-C2: journal completion failure must fail the activation");
        require(result.changedSystemState,
            "W-C2: the physical mutation persisted — honest accounting");
        require(!result.ownershipProven, "W-C2: no ownership");
        require(result.mutationId != 0,
            "W-C2: exact outstanding mutation id propagated");
        const std::uint64_t id = result.mutationId;
        const auto* record = findRecord(fixture.journal(), id);
        require(record != nullptr, "W-C2: journal record exists");
        require(record->status == fic::rollback::MutationStatus::Prepared,
            "W-C2: the record stays Prepared for the caller compensation");
        // Caller-side exact-id compensation.
        bool changed = false;
        require(fixture.writer().compensateC2ActiveSlot(
                ManagedPasswordSlotRole::Quality, id, changed, error),
            "W-C2: exact-id caller compensation: " + error);
        require(changed, "W-C2: compensation changed the system state");
        require(readFile(qualityPath(fixture.tree())) == neutral(),
            "W-C2: slot neutralized");
        require(findRecord(fixture.journal(), id) == nullptr,
            "W-C2: exact Prepared record discarded");
    }

    // W-C2-clean: a failure that the writer fully compensated internally
    // (no physical write committed, Prepared discarded) must report NO
    // caller-compensatable state (mutationId == 0), so the executor never
    // attempts to neutralize an already Neutral slot.
    {
        Fixture fixture(PamManagedPasswordDomain::Quality);
        writeFile(qualityPath(fixture.tree()), neutral());
        fixture.writer().setBeforeSlotWriteHookForTests(
            [](std::size_t) { return false; });
        PamManagedPasswordSlotActivationResult result;
        std::string error;
        require(!fixture.writer().activateC2Slot(
                ManagedPasswordSlotRole::Quality, historyOptions(3),
                result, error),
            "W-C2-clean: write failure must fail the activation");
        require(!result.changedSystemState,
            "W-C2-clean: fully compensated internal failure");
        require(result.mutationId == 0,
            "W-C2-clean: no caller-compensatable state remains");
        require(journalActiveCount(fixture.journal()) == 0,
            "W-C2-clean: Prepared record discarded");
        require(readFile(qualityPath(fixture.tree())) == neutral(),
            "W-C2-clean: slot stays Neutral");
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
        runJournalPayloadTests();
        runJournalLifecycleTests();
        runLegacyPayloadNegativeTests();
        runRecoveryAccountingTests();
        runNeutralizationAccountingTests();
        runC2LifecycleTests();
        std::cout << "PamManagedPasswordSlotWriterTests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PamManagedPasswordSlotWriterTests FAILED: "
                  << error.what() << "\n";
        return 1;
    }
}
