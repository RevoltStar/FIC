// Step 4 read-only password slot attach validator tests: slot topology +
// journal provenance (quality + history pair), Rule G/I/J semantics and
// read-only guarantees, by the model of PamSlotAttachValidatorTests.cpp.
#include "modules/identity_access/pam/PamSlotAttachValidator.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <array>
#include <algorithm>
#include <optional>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

namespace fs = std::filesystem;

using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamAuthUpdateTopologyManagerOptions;
using fic::identity::pam::PamManagedPasswordSlots;
using fic::identity::pam::PamSlotAttachVerdict;
using fic::rollback::MutationBackend;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::PamTopologyKind;
using fic::rollback::UndoDisablePamCapability;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path, const std::string& content,
               mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    // Fresh file (never truncate in place): models conffile provisioning
    // and avoids O_TRUNC side effects for read-only fixture files.
    ::unlink(path.c_str());
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    mode);
    require(fd >= 0, "cannot create " + path.string());
    ssize_t written = 0;
    while (static_cast<std::size_t>(written) < content.size()) {
        const ssize_t count =
            ::write(fd, content.data() + written, content.size() -
                          static_cast<std::size_t>(written));
        require(count > 0, "cannot write " + path.string());
        written += count;
    }
    require(::close(fd) == 0, "cannot close " + path.string());
    ::chmod(path.c_str(), mode);
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "cannot read " + path.string());
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

// Snapshot of every persistent artifact the validator must not modify.
struct StateFingerprint {
    std::vector<std::pair<fs::path, std::string>> files;
};

class TestTree {
public:
    TestTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-pam-pwd-attach-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "mkdtemp failed");
        root = created;
        fs::create_directories(root / "pam.d");
        fs::create_directories(root / "security");
        fs::create_directories(root / "var/lib/pam");
        writeFile(root / "security/pam_unix.so", "fixture\n", 0555);
        writeFile(root / "security/pam_pwquality.so", "fixture\n", 0555);
        writeFile(root / "security/pam_pwhistory.so", "fixture\n", 0555);
        writeFile(root / "pam.d/passwd", "password required pam_unix.so\n");
    }

    ~TestTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    fs::path root;
    fs::path stateDir() const { return root / "var/lib/pam"; }
    fs::path journalPath() const { return root / "db/mutations.json"; }
    fs::path confPath() const { return root / "security/pwhistory.conf"; }
    fs::path stackPath() const { return root / "pam.d/common-password"; }
    fs::path stateFilePath() const { return stateDir() / "password"; }
    std::array<fs::path, 3> slotPaths() const {
        return {root / "pam.d/fic-password-quality",
                root / "pam.d/fic-password-history",
                root / "pam.d/fic-password-history-initial"};
    }

    fic::platform::PamPlatformConfig platform() const {
        fic::platform::PamPlatformConfig platform;
        platform.configDirectories = {root / "pam.d"};
        platform.moduleDirectories = {root / "security"};
        platform.scopes = {
            {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
        platform.capabilities = {
            {fic::platform::PamCapability::PasswordQuality,
             fic::platform::PamProviderKind::PamPwquality,
             fic::platform::PamScope::EffectivePasswordStack,
             root / "security/pwquality.conf",
             fic::platform::PamTopologyStrategyKind::PamAuthUpdate},
            {fic::platform::PamCapability::PasswordHistory,
             fic::platform::PamProviderKind::PamPwhistory,
             fic::platform::PamScope::EffectivePasswordStack,
             confPath(),
             fic::platform::PamTopologyStrategyKind::PamAuthUpdate,
             {},
             std::nullopt,
             fic::platform::PamIdentitySubjectScope::AllPamSubjects,
             fic::platform::PamCapabilityConfigurationMode::
                 ModuleArguments}};
        return platform;
    }

    static const char* kDistroQualityStack;
    static const char* kPlainStack;
};

const char* TestTree::kDistroQualityStack =
    "password requisite pam_pwquality.so retry=3\n"
    "password required pam_unix.so\n";

const char* TestTree::kPlainStack = "password required pam_unix.so\n";

std::string neutralSlot() {
    return PamManagedPasswordSlots::neutralBody();
}

std::string activeQualitySlot(std::uint64_t id) {
    std::string content;
    std::string error;
    require(
        PamManagedPasswordSlots::renderActiveQuality(id, content, error),
        "renderActiveQuality: " + error);
    return content;
}

std::string activeHistoryNormalSlot(
    std::uint64_t id, const ManagedPwhistorySlotOptions& options) {
    std::string content;
    std::string error;
    require(
        PamManagedPasswordSlots::renderActiveHistoryNormal(
            id, options, content, error),
        "renderActiveHistoryNormal: " + error);
    return content;
}

std::string activeHistoryInitialSlot(
    std::uint64_t id, const ManagedPwhistorySlotOptions& options) {
    std::string content;
    std::string error;
    require(
        PamManagedPasswordSlots::renderActiveHistoryInitial(
            id, options, content, error),
        "renderActiveHistoryInitial: " + error);
    return content;
}


UndoDisablePamCapability qualityUndo() {
    UndoDisablePamCapability undo;
    undo.capability = "enable_password_quality";
    undo.topology = PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = {"fic-password-quality-hook"};
    return undo;
}

UndoDisablePamCapability historyUndo() {
    UndoDisablePamCapability undo;
    undo.capability = "enable_password_history";
    undo.topology = PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = {"fic-password-history-hook"};
    return undo;
}

std::uint64_t seedJournal(const fs::path& path, const std::string& policy,
                          const std::string& resource,
                          fic::rollback::UndoAction undo,
                          MutationStatus status) {
    fs::create_directories(path.parent_path());
    MutationJournal journal(path);
    std::string error;
    require(journal.initializeOrLoad(error), error);
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", policy};
    record.resource = resource;
    record.undo = std::move(undo);
    std::uint64_t id = 0;
    require(journal.prepareMutation(std::move(record), id, error), error);
    require(journal.setStatus(id, status, error), error);
    return id;
}

std::uint64_t seedQualityJournal(const fs::path& path,
                                 MutationStatus status) {
    return seedJournal(
        path, "enable_password_quality",
        "capability/enable_password_quality",
        fic::rollback::UndoAction{MutationBackend::Pam, qualityUndo()},
        status);
}

// Initializes the journal into a proven witness-aware persistent state
// WITHOUT any domain record (Unbound provenance for both password
// domains). This models the normal daemon runtime state on a system where
// FIC never activated a password capability.
void seedEmptyJournal(const fs::path& path) {
    fs::create_directories(path.parent_path());
    // Fully reset the persistent (journal, witness) pair first: an
    // existing witness would route initializeOrLoad into the migration
    // branch against whatever records the previous test case left behind.
    std::error_code ignored;
    fs::remove(path, ignored);
    fs::remove(path.string() + ".initialized", ignored);
    MutationJournal journal(path);
    std::string error;
    require(journal.initializeOrLoad(error), error);
}

std::uint64_t seedHistoryJournal(const fs::path& path,
                                 MutationStatus status) {
    return seedJournal(
        path, "enable_password_history",
        "capability/enable_password_history",
        fic::rollback::UndoAction{MutationBackend::Pam, historyUndo()},
        status);
}

const char* kPasswordStateClean = "# no FIC or distro profiles selected\n";

fic::platform::PlatformExecutableResolver resolver() {
    return fic::platform::PlatformExecutableResolver(
        fic::platform::PlatformExecutables{},
        {.enforceTrustedOwnership = false});
}

PamSlotAttachVerdict validate(const TestTree& tree,
                              const fs::path& journalPath,
                              std::string& error) {
    auto platform = tree.platform();
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.root / "pam.d";
    PamSlotAttachVerdict verdict;
    require(
        fic::identity::pam::validatePamPasswordSlotAttach(
            platform, {"passwd"}, resolver(), journalPath, options,
            verdict, error),
        error);
    return verdict;
}

void requireSafe(const TestTree& tree, const fs::path& journalPath) {
    std::string error;
    const PamSlotAttachVerdict verdict = validate(tree, journalPath, error);
    require(verdict.safeToAttach,
            "expected safe verdict, got: " + verdict.detail + " | err: " + error);
}

// Step 5B: run the same validation with the explicit Attached phase.
PamSlotAttachVerdict validateAttached(const TestTree& tree,
                                      const fs::path& journalPath) {
    auto platform = tree.platform();
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.root / "pam.d";
    PamSlotAttachVerdict verdict;
    std::string error;
    require(
        fic::identity::pam::validatePamPasswordSlotAttach(
            platform, {"passwd"}, resolver(), journalPath, options,
            fic::identity::pam::PamAttachmentValidationPhase::Attached,
            verdict, error),
        error);
    return verdict;
}

void checkAttachedPhase(const TestTree& tree, bool safe,
                        const std::string& substring = {}) {
    const PamSlotAttachVerdict verdict =
        validateAttached(tree, tree.journalPath());
    require(safe == verdict.safeToAttach,
            std::string("expected ") + (safe ? "safe" : "unsafe") +
                " attached-phase verdict, got: " + verdict.detail +
                " | safeToAttach=" + (verdict.safeToAttach ? "1" : "0"));
    if (!safe && !substring.empty()) {
        require(verdict.detail.find(substring) != std::string::npos,
                "attached detail \"" + verdict.detail +
                    "\" does not mention \"" + substring + "\"");
    }
}

void requireUnsafe(const TestTree& tree, const fs::path& journalPath,
                   const std::string& substring = {}) {
    std::string error;
    const PamSlotAttachVerdict verdict = validate(tree, journalPath, error);
    require(!verdict.safeToAttach,
            "expected unsafe verdict, got safe: " + verdict.detail);
    if (!substring.empty()) {
        require(verdict.detail.find(substring) != std::string::npos,
                "detail \"" + verdict.detail +
                    "\" does not mention \"" + substring + "\"");
    }
}

void writeStack(const TestTree& tree, const char* content) {
    // The service file itself (no include indirection in the fixture).
    writeFile(tree.root / "pam.d/passwd", content);
}

void writePasswordState(const TestTree& tree, const char* content) {
    writeFile(tree.stateFilePath(), content);
}

// Initialized Neutral baseline: both domains are Unbound. Virgin pre-attach
// is covered independently by testVirginAndJournalMatrix.
void testAllNeutralPass(const TestTree& tree) {
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    seedEmptyJournal(tree.journalPath());
    requireSafe(tree, tree.journalPath());
}

// 2. Active slots with matching Applied journal records + FIC quality as
// the token producer (hook include in the stack): safe. The active FIC
// quality provider replaces the distro provider, so the distro selection
// stays unselected and the parsed stack carries exactly the FIC provider
// (this models the final Step 5 FIC-owned topology). The FIC history
// include is already attached and expanded in place (the slot bodies are
// canonical Active), so the history rule sits in the stack between the
// producer and pam_unix.
void testActiveOwnedPass(const TestTree& tree) {
    const std::uint64_t qualityId =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(qualityId));
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    // FIC quality hook include as the token producer before the history
    // hook include (Rule G, FIC provider scenario).
    writeStack(
        tree,
        "password include fic-password-quality\n"
        "password include fic-password-history\n"
        "password required pam_unix.so\n");
    writePasswordState(tree, "Module: fic-password-quality-hook\n"
                             "Module: fic-password-history-hook\n");
    requireSafe(tree, tree.journalPath());
}

// 14/15. The validator is strictly read-only on the PASS and FAIL paths.
StateFingerprint snapshot(const TestTree& tree) {
    StateFingerprint state;
    std::vector<fs::path> paths;
    for (const auto& entry : fs::recursive_directory_iterator(tree.root)) {
        paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end());
    for (const auto& path : paths) {
        const auto status = fs::symlink_status(path);
        std::string value = std::to_string(static_cast<int>(status.type())) + ":";
        if (fs::is_symlink(status)) value += fs::read_symlink(path).string();
        else if (fs::is_regular_file(status)) value += readFile(path);
        state.files.emplace_back(path, value);
    }
    return state;
}

void requireUnchanged(const StateFingerprint& before,
                      const StateFingerprint& after) {
    require(before.files.size() == after.files.size(),
            "validator changed the set of persisted files");
    for (std::size_t index = 0; index < before.files.size(); ++index) {
        require(before.files[index].first == after.files[index].first &&
                    before.files[index].second == after.files[index].second,
                "validator modified " + before.files[index].first.string());
    }
}

void testReadOnlyOnPass(const TestTree& tree) {
    testActiveOwnedPass(tree);
    const StateFingerprint before = snapshot(tree);
    requireSafe(tree, tree.journalPath());
    requireUnchanged(before, snapshot(tree));
}

// 3. Active history pair without any pam_pwquality token producer
// (history-only): Unsupported, fail closed (Rule G). The quality slot is
// seeded with clean Unbound provenance so the stale-journal gate does not
// shadow the Rule G verdict.
void testHistoryOnlyFails(const TestTree& tree) {
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    // Re-seed the history record into the FRESH Unbound journal so the
    // quality domain stays Unbound (stale-journal gate) while the history
    // pair remains journal-bound (ownership proof + Rule G verdict).
    fs::remove(tree.journalPath());
    fs::remove(MutationJournal(tree.journalPath()).witnessPath());
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t reboundHistoryId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  reboundHistoryId, ManagedPwhistorySlotOptions{10u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  reboundHistoryId,
                  ManagedPwhistorySlotOptions{10u, true}));
    writeStack(tree, "password include fic-password-history\n"
                     "password required pam_unix.so\n");
    writePasswordState(tree, "Module: fic-password-history-hook\n");
    std::string error;
    const PamSlotAttachVerdict verdict =
        validate(tree, tree.journalPath(), error);
    require(!verdict.safeToAttach,
            "history-only must fail closed (Rule G), got: " +
                verdict.detail);
    require(verdict.detail.find("Rule G") != std::string::npos,
            "history-only detail should mention Rule G: " + verdict.detail);
    const StateFingerprint before = snapshot(tree);
    requireUnchanged(before, snapshot(tree));
}


// 4. Missing slot file: fail closed (missing != Neutral). The journal is
// reset to Unbound so the missing-slot verdict is not shadowed by stale
// provenance from a previous test case.
void testMissingSlotFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    fs::remove(tree.root / "pam.d/fic-password-history-initial");
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath());
}

// 5. Modified (broken) slot body: fail closed.
void testBrokenSlotFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    writeFile(tree.root / "pam.d/fic-password-quality",
              "# FIC managed password slot: state=neutral\n# tail\n");
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath());
}

// 6. Active quality slot without journal provenance: fail closed.
void testActiveQualityWithoutJournalFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(777));
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath());
}

// 7. Wrong journal policy identity (foreign capability record): fail
// closed.
void testWrongPolicyIdentityFails(const TestTree& tree) {
    const std::uint64_t id =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(id));
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    // Re-seed the same id with a foreign policy identity: rewrite the
    // journal through the public seed helper with mismatched metadata.
    // The record identity stays self-consistent (journal validation
    // requires policy == undo.capability), but the record belongs to the
    // HISTORY domain while the marker sits in the QUALITY slot: the
    // metadata proof must reject it. The history record also makes the
    // neutral history pair stale-provenance (an additional fail-closed
    // gate).
    fs::remove(tree.journalPath());
    fs::remove(MutationJournal(tree.journalPath()).witnessPath());
    const std::uint64_t foreignId = seedJournal(
        tree.journalPath(), "enable_password_history",
        "capability/enable_password_history",
        fic::rollback::UndoAction{MutationBackend::Pam, historyUndo()},
        MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(foreignId));
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath());
}


// 8. Rule I: two pam_pwquality.so in the Primary stack (external + FIC
// active slot): fail closed.
void testDuplicatePwqualityFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t qualityId =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(qualityId));
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    // The FIC quality hook include is attached: the slot body's
    // pam_pwquality.so rule appears in the parsed stack IN ADDITION to the
    // distro rule -> two providers.
    writeStack(
        tree,
        "password requisite pam_pwquality.so retry=3\n"
        "password include fic-password-quality\n"
        "password required pam_unix.so\n");
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "Rule I");
}

// 9. Rule I: external distro pwquality present (selected + parsed) while
// the FIC quality slot is active: ownership conflict, fail closed.
void testExternalQualityWithFicActiveFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t qualityId =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(qualityId));
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    writeStack(tree, TestTree::kDistroQualityStack);
    writePasswordState(tree, "Module: pwquality\n");
    requireUnsafe(tree, tree.journalPath(), "Rule I");
}

// 10. Rule I/JRN hybrid: distro profile selected but the distro provider
// is absent from the parsed stack while the FIC quality slot is active.
// The selection-vs-provider XOR ownership conflict (Rule I) still fails
// closed: the selection state already requests the distro provider and a
// later regeneration can reintroduce it as a duplicate producer. (This is
// the strengthened P1-3 semantics: selection is read regardless of the
// providerCount.)
void testSelectedWithoutStackIsNotExternal(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t qualityId =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(qualityId));
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, "Module: pwquality\n");
    requireUnsafe(tree, tree.journalPath(), "Rule I");
}

// 11. Rule J: active FIC history with remember=0: fail closed.
void testRememberZeroFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{0u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{0u, true}));
    writeStack(tree, "password requisite pam_pwquality.so\n"
                     "password include fic-password-history\n"
                     "password required pam_unix.so\n");
    writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
    requireUnsafe(tree, tree.journalPath(), "remember=0");
}

// 12. Rule J: root enforcement is independent of history effectiveness,
// including when the capability applies to AllPamSubjects.
void testHistoryRootOptionMatrix() {
    for (const bool enforceForRoot : {false, true}) {
        for (const unsigned remember : {10u, 0u}) {
            TestTree tree;
            seedEmptyJournal(tree.journalPath());
            const auto historyId =
                seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
            const ManagedPwhistorySlotOptions options{remember, enforceForRoot};
            writeFile(tree.slotPaths()[0], neutralSlot());
            writeFile(tree.slotPaths()[1], activeHistoryNormalSlot(historyId, options));
            writeFile(tree.slotPaths()[2], activeHistoryInitialSlot(historyId, options));
            writeStack(tree, "password requisite pam_pwquality.so\n"
                             "password include fic-password-history\n"
                             "password required pam_unix.so\n");
            writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
            const auto before = snapshot(tree);
            if (remember > 0) requireSafe(tree, tree.journalPath());
            else requireUnsafe(tree, tree.journalPath(), "remember=0");
            requireUnchanged(before, snapshot(tree));
        }
    }
}

void testReadOnlyOnFail(const TestTree& tree) {
    testRememberZeroFails(tree);
    const StateFingerprint before = snapshot(tree);
    requireUnsafe(tree, tree.journalPath(), "remember=0");
    requireUnchanged(before, snapshot(tree));
}

// ---------------------------------------------------------------------------
// P1-4 hardening tests: Neutral slot ⇔ journal Unbound provenance.
// ---------------------------------------------------------------------------

// JRN1: quality Neutral + Applied quality record: stale provenance, fail
// closed. The validator must never treat the domain as unbound.
void testNeutralQualityAppliedJournalFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    (void)seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "stale provenance");
}

// JRN2: quality Neutral + Prepared quality record: unresolved crash
// provenance, fail closed (recovery is the runtime responsibility, never
// the read-only validator's).
void testNeutralQualityPreparedJournalFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    (void)seedQualityJournal(tree.journalPath(), MutationStatus::Prepared);
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "unresolved crash provenance");
}

// JRN3: history Neutral pair + Applied history record: stale provenance,
// fail closed.
void testNeutralHistoryAppliedJournalFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    (void)seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "stale provenance");
}

// JRN3b: history Neutral pair + Prepared history record: fail closed.
void testNeutralHistoryPreparedJournalFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    (void)seedHistoryJournal(tree.journalPath(), MutationStatus::Prepared);
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "unresolved crash provenance");
}

// JRN4b: Neutral + no domain records anywhere: safe from the provenance
// perspective (the journal is freshly re-initialized to Unbound).
void testNeutralUnboundJournalPasses(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireSafe(tree, tree.journalPath());
}

// JRN5: multiple active records of the same domain: Conflict, fail
// closed (never pick one by chance).
void testMultipleDomainRecordsConflict(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    (void)seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    (void)seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "fail closed");
}

// JRN6: read-only fingerprint on the stale-journal FAIL path: the
// validator must not repair, complete or discard the stale record.
void testReadOnlyOnStaleJournalFail(const TestTree& tree) {
    testNeutralQualityAppliedJournalFails(tree);
    const StateFingerprint before = snapshot(tree);
    requireUnsafe(tree, tree.journalPath(), "stale provenance");
    requireUnchanged(before, snapshot(tree));
}

// ---------------------------------------------------------------------------
// P1-2 hardening through the validator: explicit jump graphs (62).
// ---------------------------------------------------------------------------

// G-jump-a: quality textually BEFORE history, but the quality success
// jumps over the history rule: history bypass, fail closed.
void testValidatorRejectsJumpOverHistory(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    // The history include IS attached (slot active) but its position is
    // irrelevant: the quality success action jumps over it. The distro
    // pwquality selection is modeled (selected + the single in-graph
    // provider) so the Rule I topology check passes and the jump verdict
    // is reachable.
    writeStack(
        tree,
        "password [success=1 default=ignore] pam_pwquality.so retry=3\n"
        "password include fic-password-history\n"
        "password required pam_unix.so use_authtok\n");
    writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
    requireUnsafe(tree, tree.journalPath(), "Rule G");
}

// G-jump-b: producer bypass via jump: a preceding success jump skips the
// quality producer entirely, so the history rule runs without a token
// producer (fail closed).
void testValidatorRejectsJumpOverProducer(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    // quality textually before history, but the FIRST rule's success jump
    // lands after the quality rule (skipping the producer). The distro
    // pwquality selection is modeled so the Rule I topology check passes
    // and the jump verdict is reachable.
    writeStack(
        tree,
        "password [success=1 default=ignore] pam_permit.so\n"
        "password requisite pam_pwquality.so retry=3\n"
        "password include fic-password-history\n"
        "password required pam_unix.so use_authtok\n");
    writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
    requireUnsafe(tree, tree.journalPath(), "Rule G");
}

// G-jump-c: history textually FIRST (before the producer): no token can
// exist yet on the successful path, fail closed.
void testValidatorRejectsHistoryBeforeProducer(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeStack(
        tree,
        "password include fic-password-history\n"
        "password requisite pam_pwquality.so retry=3\n"
        "password required pam_unix.so use_authtok\n");
    writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
    requireUnsafe(tree, tree.journalPath(), "Rule G");
}

// Rule I (I3): provider present but no distro selection with both FIC
// domains neutral: unmanaged topology, fail closed.
void testProviderWithoutSelectionFails(const TestTree& tree) {
    seedEmptyJournal(tree.journalPath());
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kDistroQualityStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "unmanaged topology");
}

// Fresh fixtures for each case prevent old selection/config/provenance from
// masking the invariant under test.
void provisionNeutral(const TestTree& tree) {
    for (const auto& slot : tree.slotPaths()) writeFile(slot, neutralSlot());
}

void provisionHistory(const TestTree& tree, ManagedPwhistorySlotOptions options) {
    const auto id = seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.slotPaths()[1], activeHistoryNormalSlot(id, options));
    writeFile(tree.slotPaths()[2], activeHistoryInitialSlot(id, options));
}

void checkReadOnly(const TestTree& tree, bool safe, const std::string& detail = {}) {
    const auto before = snapshot(tree);
    if (safe) requireSafe(tree, tree.journalPath());
    else requireUnsafe(tree, tree.journalPath(), detail);
    requireUnchanged(before, snapshot(tree));
}

void testQualityOnlyMatrix() {
    {
        TestTree tree;
        provisionNeutral(tree);
        writeStack(tree, "password include fic-password-quality\n"
                         "password include fic-password-quality\n"
                         "password required pam_unix.so\n");
        checkReadOnly(tree, false, "duplicate managed password include");
    }
    for (const bool owned : {false, true}) {
        TestTree tree;
        provisionNeutral(tree);
        if (owned) {
            const auto id = seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
            writeFile(tree.slotPaths()[0], activeQualitySlot(id));
            writeStack(tree, "password include fic-password-quality\n"
                             "password required pam_unix.so\n");
            writePasswordState(tree, "Module: fic-password-quality-hook\n");
        } else {
            writeStack(tree, TestTree::kDistroQualityStack);
            writePasswordState(tree, "Module: pwquality\n");
        }
        checkReadOnly(tree, true);
    }
}

void testVirginAndJournalMatrix() {
    TestTree virgin;
    provisionNeutral(virgin);
    checkReadOnly(virgin, true); // No state database, hooks, db directory or J/W.
    require(!fs::exists(virgin.journalPath()) &&
            !fs::exists(MutationJournal(virgin.journalPath()).witnessPath()) &&
            !fs::exists(virgin.journalPath().parent_path()), "virgin validation bootstrapped state");
    writeFile(virgin.slotPaths()[0], activeQualitySlot(1));
    checkReadOnly(virgin, false, "ownership");
    for (int scenario = 0; scenario < 6; ++scenario) {
        TestTree tree;
        provisionNeutral(tree);
        seedEmptyJournal(tree.journalPath());
        const auto witness = MutationJournal(tree.journalPath()).witnessPath();
        if (scenario == 0) fs::remove(tree.journalPath());
        if (scenario == 1) fs::remove(witness);
        if (scenario == 2) writeFile(witness, "invalid\n");
        if (scenario == 3) writeFile(tree.journalPath(), "invalid\n");
        if (scenario == 4) {
            fs::remove(tree.journalPath());
            fs::remove(witness);
            fs::create_symlink(tree.root / "missing", witness);
        }
        checkReadOnly(tree, scenario == 5);
    }
}

void testSlotSymlinks() {
    for (std::size_t index = 0; index < 3; ++index) {
        TestTree tree;
        provisionNeutral(tree);
        const auto target = tree.root / "neutral-target";
        writeFile(target, neutralSlot());
        fs::remove(tree.slotPaths()[index]);
        fs::create_symlink(target, tree.slotPaths()[index]);
        checkReadOnly(tree, false, "symlink");
    }
}

void testExactAttachmentMatrix() {
    struct Case { bool history; const char* selection; const char* graph; const char* diagnostic; };
    const Case cases[] = {
        {false, "", "password requisite pam_pwquality.so retry=3\n", "not selected"},
        {false, "Module: fic-password-quality-hook\n", "password requisite pam_pwquality.so retry=3\n", "exactly one password include"},
        {false, "", "password include fic-password-quality\n", "not selected"},
        {false, "Module: fic-password-quality-hook-extra\n", "password include fic-password-quality\n", "not selected"},
        {false, "Module: fic-password-quality-hook\n", "password substack fic-password-quality\n", "requires password include"},
        {false, "Module: fic-password-quality-hook\n", "@include fic-password-quality\n", "requires password include"},
        {false, "Module: fic-password-quality-hook\n", "password include fic-password-quality\npassword include fic-password-quality\n", "Rule I"},
        {true, "Module: pwquality\n", "password include fic-password-history\n", "not selected"},
        {true, "Module: pwquality\nModule: fic-password-history-hook\n", "password requisite pam_pwhistory.so use_authtok\n", "exactly one password include"},
        {true, "Module: pwquality\nModule: fic-password-history-hook\n", "password include fic-password-history-initial\n", "history-initial"},
        {true, "Module: pwquality\nModule: fic-password-history-hook\n", "password substack fic-password-history\n", "requires password include"},
        {true, "Module: pwquality\nModule: fic-password-history-hook\n", "password include fic-password-history\npassword requisite pam_pwhistory.so use_authtok\n", "exactly one pam_pwhistory.so"},
        {true, "Module: pwquality\nModule: fic-password-history-hook\n", "password include fic-password-history\npassword include fic-password-history\n", "exactly one password include"},
    };
    for (const auto& c : cases) {
        TestTree tree;
        provisionNeutral(tree);
        std::string graph;
        if (c.history) {
            provisionHistory(tree, {10u, true});
            graph = "password requisite pam_pwquality.so retry=3\n";
        } else {
            const auto id = seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
            writeFile(tree.slotPaths()[0], activeQualitySlot(id));
        }
        graph += c.graph;
        graph += "password required pam_unix.so\n";
        writeStack(tree, graph.c_str());
        writePasswordState(tree, c.selection);
        // Step 5B: missing selected hooks / missing generated attachment are
        // exactly the detached states the PreAttach phase must ACCEPT (Step
        // 5C attaches the hooks afterwards). Structural live-graph defects
        // (substack/@include instead of the managed include, duplicate
        // includes, foreign providers) still fail in both phases.
        const bool structural =
            std::string(c.diagnostic).find("requires password include") !=
                std::string::npos ||
            std::string(c.diagnostic) == "Rule I" ||
            std::string(c.diagnostic) == "exactly one password include" ||
            std::string(c.diagnostic).find("exactly one pam_pwhistory.so") !=
                std::string::npos ||
            std::string(c.diagnostic) == "history-initial";
        if (structural) checkReadOnly(tree, false, c.diagnostic);
        else {
            // Detached Active state: PASS in PreAttach, FAIL in Attached.
            checkReadOnly(tree, true);
            checkAttachedPhase(tree, false, c.diagnostic);
        }
    }
    // Exact include filename alone is insufficient: PAM resolves a foreign
    // same-name file from a higher-priority configuration directory.
    for (const bool history : {false, true}) {
        TestTree tree;
        provisionNeutral(tree);
        const auto slot = history ? tree.slotPaths()[1] : tree.slotPaths()[0];
        if (history) provisionHistory(tree, {10u, true});
        else writeFile(slot, activeQualitySlot(seedQualityJournal(tree.journalPath(), MutationStatus::Applied)));
        auto platform = tree.platform();
        platform.configDirectories.insert(platform.configDirectories.begin(), tree.root / "foreign");
        writeFile(tree.root / "foreign" / slot.filename(), readFile(slot));
        writeStack(tree, history
            ? "password requisite pam_pwquality.so\npassword include fic-password-history\npassword required pam_unix.so\n"
            : "password include fic-password-quality\npassword required pam_unix.so\n");
        writePasswordState(tree, history
            ? "Module: pwquality\nModule: fic-password-history-hook\n"
            : "Module: fic-password-quality-hook\n");
        const auto before = snapshot(tree);
        PamAuthUpdateTopologyManagerOptions options;
        options.configDirectory = tree.root / "pam.d";
        options.stateDirectory = tree.stateDir();
        PamSlotAttachVerdict verdict;
        std::string error;
        require(fic::identity::pam::validatePamPasswordSlotAttach(platform, {"passwd"}, resolver(),
                    tree.journalPath(), options, verdict, error), error);
        require(!verdict.safeToAttach && verdict.detail.find("source is not") != std::string::npos,
                "foreign same-name slot accepted: " + verdict.detail);
        requireUnchanged(before, snapshot(tree));
    }
    TestTree foreign;
    provisionNeutral(foreign);
    writeStack(foreign, "password requisite pam_pwquality.so\n"
                       "password requisite pam_pwhistory.so use_authtok\n"
                       "password required pam_unix.so\n");
    writePasswordState(foreign, "Module: pwquality\n");
    checkReadOnly(foreign, false, "foreign history provider");
}

void testConfigModeMatrix() {
    struct Case { std::optional<std::string> config; bool safe; const char* detail; int object = 0; };
    const Case cases[] = {
        {"remember = 10\nenforce_for_root\n", true, ""},
        {"enforce_for_root\n", true, ""}, // Documented nonzero remember default.
        {"remember = 0\nenforce_for_root\n", false, "remember=0"},
        {"remember = 10\n", true, ""},
        {"", true, ""}, // Both options absent: preserve documented defaults.
        {std::nullopt, true, ""},
        {"remember = 0\n", false, "remember=0"},
        {"remember\nenforce_for_root\n", false, "malformed"},
        {"remember = ten\nenforce_for_root\n", false, "malformed"},
        {"remember = 4294967296\nenforce_for_root\n", false, "malformed"},
        {"remember = 10\nremember = 0\nenforce_for_root\n", false, "duplicate"},
        {"remember = 10\nremember = 20\nenforce_for_root\n", false, "duplicate"},
        {"remember = 10\nremember = 10\nenforce_for_root\n", false, "duplicate"},
        {"remember = 10\nenforce_for_root\nenforce_for_root\n", false, "duplicate"},
        {"remember = 10\nenforce_for_root = false\n", false, "malformed"},
        {"remember = 10\nenforce_for_root extra\n", false, "malformed"},
        {"remember = 10\nenforce_for_root\nretry = 3\ndebug\n", true, ""},
        {std::nullopt, false, "non-regular", 1},
        {std::nullopt, false, "unreadable", 2},
        {std::nullopt, false, "non-regular", 3},
        {std::nullopt, false, "non-regular", 4},
    };
    for (const auto& c : cases) {
        TestTree tree;
        provisionNeutral(tree);
        provisionHistory(tree, {}); // Real conf-mode canonical no-argument pair.
        writeStack(tree, "password requisite pam_pwquality.so\n"
                         "password include fic-password-history\n"
                         "password required pam_unix.so\n");
        writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
        if (c.config) writeFile(tree.confPath(), *c.config);
        if (c.object == 1) fs::create_directory(tree.confPath());
        if (c.object == 2) writeFile(tree.confPath(), "blocking regular parent");
        if (c.object == 3) fs::create_symlink(tree.root / "missing", tree.confPath());
        if (c.object == 4) require(::mkfifo(tree.confPath().c_str(), 0600) == 0, "mkfifo");
        auto platform = tree.platform();
        if (c.object == 2) platform.capabilities[1].configPath = tree.confPath() / "unreadable";
        platform.capabilities[1].configurationMode = fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile;
        PamAuthUpdateTopologyManagerOptions options;
        options.configDirectory = tree.root / "pam.d";
        options.stateDirectory = tree.stateDir();
        const auto before = snapshot(tree);
        PamSlotAttachVerdict verdict;
        std::string error;
        require(fic::identity::pam::validatePamPasswordSlotAttach(platform, {"passwd"}, resolver(),
                    tree.journalPath(), options, verdict, error), error);
        require(verdict.safeToAttach == c.safe && (c.safe || verdict.detail.find(c.detail) != std::string::npos),
                "config-mode verdict: " + verdict.detail);
        requireUnchanged(before, snapshot(tree));
    }
}

void testExternalQualityHistoryPass() {
    TestTree tree;
    provisionNeutral(tree);
    provisionHistory(tree, {10u, true});
    writeFile(tree.root / "pam.d/passwd", "@include common-password\n");
    writeFile(tree.stackPath(), "password requisite pam_pwquality.so\n"
                                "password include fic-password-history\n"
                                "password required pam_unix.so\n");
    writePasswordState(tree, "Module: pwquality\nModule: fic-password-history-hook\n");
    checkReadOnly(tree, true);
    const auto before = snapshot(tree);
    PamAuthUpdateTopologyManagerOptions options;
    options.configDirectory = tree.root / "pam.d";
    options.stateDirectory = tree.stateDir();
    PamSlotAttachVerdict verdict;
    std::string error;
    require(fic::identity::pam::validatePamPasswordSlotAttach(tree.platform(), {"passwd", "common-password"}, resolver(),
                tree.journalPath(), options, verdict, error) && verdict.safeToAttach, verdict.detail + error);
    requireUnchanged(before, snapshot(tree));
}

// P2: the empty-services invariant is phase-agnostic. The per-service
// loop is the only live-topology examination in both phases, so an empty
// service list must fail closed in PreAttach AND Attached — never
// produce a vacuous safe verdict. Unsafe is not an error: the validator
// must return true with an empty error in both phases, and stay strictly
// read-only.
void testEmptyServicesFailsClosedInBothPhases(const TestTree& tree) {
    provisionNeutral(tree);
    seedEmptyJournal(tree.journalPath());
    auto platform = tree.platform();
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.root / "pam.d";
    const auto runPhase =
        [&](fic::identity::pam::PamAttachmentValidationPhase phase) {
            PamSlotAttachVerdict verdict;
            std::string error;
            const bool ran = fic::identity::pam::validatePamPasswordSlotAttach(
                platform, {}, resolver(), tree.journalPath(), options,
                phase, verdict, error);
            require(ran && error.empty(),
                    "empty-services validation must run to a verdict "
                    "(an unsafe verdict is not an error): " + error);
            require(!verdict.safeToAttach,
                    "empty services must fail closed (phase " +
                        std::to_string(static_cast<int>(phase)) + "): " +
                        verdict.detail);
            require(verdict.detail.find("empty service list") !=
                        std::string::npos,
                    "empty-services detail should mention the empty "
                    "service list: " + verdict.detail);
            return verdict;
        };
    const StateFingerprint before = snapshot(tree);
    const PamSlotAttachVerdict pre =
        runPhase(fic::identity::pam::PamAttachmentValidationPhase::PreAttach);
    const PamSlotAttachVerdict attached =
        runPhase(fic::identity::pam::PamAttachmentValidationPhase::Attached);
    require(pre.detail == attached.detail,
            "empty-services verdict must be phase-agnostic: \"" +
                pre.detail + "\" vs \"" + attached.detail + "\"");
    requireUnchanged(before, snapshot(tree));
}

} // namespace

int main() {
    const auto paths = fic::core::FicProductPaths::production();
    std::string pathsError;
    if (!fic::core::FicRuntimePaths::initialize(paths, pathsError)) {
        std::cerr << "FicRuntimePaths::initialize failed: " << pathsError
                  << '\n';
        return EXIT_FAILURE;
    }
    try {
        testQualityOnlyMatrix();
        testVirginAndJournalMatrix();
        testSlotSymlinks();
        testExactAttachmentMatrix();
        testConfigModeMatrix();
        testExternalQualityHistoryPass();
        TestTree tree;
        testAllNeutralPass(tree);
        testActiveOwnedPass(tree);
        testHistoryOnlyFails(tree);
        testMissingSlotFails(tree);
        testBrokenSlotFails(tree);
        testActiveQualityWithoutJournalFails(tree);
        testWrongPolicyIdentityFails(tree);
        testDuplicatePwqualityFails(tree);
        testExternalQualityWithFicActiveFails(tree);
        testSelectedWithoutStackIsNotExternal(tree);
        testRememberZeroFails(tree);
        testHistoryRootOptionMatrix();
        testReadOnlyOnPass(tree);
        testReadOnlyOnFail(tree);
        // P1-4: Neutral ⇔ Unbound journal provenance.
        testNeutralQualityAppliedJournalFails(tree);
        testNeutralQualityPreparedJournalFails(tree);
        testNeutralHistoryAppliedJournalFails(tree);
        testNeutralHistoryPreparedJournalFails(tree);
        testNeutralUnboundJournalPasses(tree);
        testMultipleDomainRecordsConflict(tree);
        testReadOnlyOnStaleJournalFail(tree);
        // P1-2: explicit jump graphs through the validator.
        testValidatorRejectsJumpOverHistory(tree);
        testValidatorRejectsJumpOverProducer(tree);
        testValidatorRejectsHistoryBeforeProducer(tree);
        // P1-3: selection/provider topology matrix.
        testProviderWithoutSelectionFails(tree);
        // P2-1: conf-mode typed remember semantics.
        // P2: empty service list is a phase-agnostic fail-closed invariant.
        testEmptyServicesFailsClosedInBothPhases(tree);
    } catch (const std::exception& exception) {
        std::cerr << "PamPasswordSlotAttachValidatorTests failed: "
                  << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "PamPasswordSlotAttachValidatorTests passed\n";
    return EXIT_SUCCESS;
}

