// Step 4 read-only password slot attach validator tests: slot topology +
// journal provenance (quality + history pair), Rule G/I/J semantics and
// read-only guarantees, by the model of PamSlotAttachValidatorTests.cpp.
#include "modules/identity_access/pam/PamSlotAttachValidator.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <array>
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
            "expected safe verdict, got: " + verdict.detail);
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

// 1. All slots neutral + no external provider: safe (neutral baseline).
void testAllNeutralPass(const TestTree& tree) {
    for (const fs::path& slot : tree.slotPaths()) {
        writeFile(slot, neutralSlot());
    }
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
    requireSafe(tree, tree.journalPath());
}

// 2. Active slots with matching Applied journal records + FIC quality as
// the token producer (hook include in the stack): safe.
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
        "password requisite pam_pwquality.so retry=3\n"
        "password required pam_unix.so\n");
    writePasswordState(tree, kPasswordStateClean);
    requireSafe(tree, tree.journalPath());
}


// 14/15. The validator is strictly read-only on the PASS and FAIL paths.
StateFingerprint snapshot(const TestTree& tree) {
    StateFingerprint state;
    std::error_code ignored;
    std::vector<fs::path> paths;
    for (const fs::path& slot : tree.slotPaths()) {
        paths.push_back(slot);
    }
    paths.push_back(tree.journalPath());
    paths.push_back(MutationJournal(tree.journalPath()).witnessPath());
    paths.push_back(tree.stackPath());
    paths.push_back(tree.stateFilePath());
    paths.push_back(tree.confPath());
    for (const fs::path& path : paths) {
        if (fs::is_regular_file(path, ignored)) {
            state.files.emplace_back(path, readFile(path));
        }
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
// (history-only): Unsupported, fail closed (Rule G).
void testHistoryOnlyFails(const TestTree& tree) {
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, true}));
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, kPasswordStateClean);
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


// 4. Missing slot file: fail closed (missing != Neutral).
void testMissingSlotFails(const TestTree& tree) {
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
    // metadata proof must reject it.
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

// 10. Rule I: distro profile selected but pam_pwquality.so missing from
// the parsed stack: external NOT present (state selection alone does not
// prove a provider), FIC active slot stays safe.
void testSelectedWithoutStackIsNotExternal(const TestTree& tree) {
    const std::uint64_t qualityId =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality",
              activeQualitySlot(qualityId));
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    writeStack(tree, TestTree::kPlainStack);
    writePasswordState(tree, "Module: pwquality\n");
    requireSafe(tree, tree.journalPath());
}

// 11. Rule J: active FIC history with remember=0: fail closed.
void testRememberZeroFails(const TestTree& tree) {
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{0u, true}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{0u, true}));
    writeStack(tree, TestTree::kDistroQualityStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "remember=0");
}

// 12. Rule J: enforce_for_root=false with AllPamSubjects scope: fail
// closed.
void testEnforceForRootMissingFails(const TestTree& tree) {
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history",
              activeHistoryNormalSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, false}));
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              activeHistoryInitialSlot(
                  historyId, ManagedPwhistorySlotOptions{10u, false}));
    writeStack(tree, TestTree::kDistroQualityStack);
    writePasswordState(tree, kPasswordStateClean);
    requireUnsafe(tree, tree.journalPath(), "enforce_for_root");
}

// 13. Rule J: conf-mode remember=0 in pwhistory.conf: fail closed.
void testConfModeRememberZeroFails(const TestTree& tree) {
    writeFile(tree.root / "pam.d/fic-password-quality", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history", neutralSlot());
    writeFile(tree.root / "pam.d/fic-password-history-initial",
              neutralSlot());
    writeStack(tree, TestTree::kDistroQualityStack);
    writePasswordState(tree, kPasswordStateClean);
    auto platform = tree.platform();
    platform.capabilities[1].configurationMode =
        fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile;
    writeFile(tree.confPath(), "remember = 0\nenforce_for_root = true\n");
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.root / "pam.d";
    PamSlotAttachVerdict verdict;
    std::string error;
    require(
        fic::identity::pam::validatePamPasswordSlotAttach(
            platform, {"passwd"}, resolver(), tree.journalPath(), options,
            verdict, error),
        error);
    require(!verdict.safeToAttach,
            "expected conf-mode remember=0 to fail closed, got safe");
    require(verdict.detail.find("remember=0") != std::string::npos,
            "conf-mode detail should mention remember=0: " + verdict.detail);
}


void testReadOnlyOnFail(const TestTree& tree) {
    testRememberZeroFails(tree);
    const StateFingerprint before = snapshot(tree);
    requireUnsafe(tree, tree.journalPath(), "remember=0");
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
        testEnforceForRootMissingFails(tree);
        testConfModeRememberZeroFails(tree);
        testReadOnlyOnPass(tree);
        testReadOnlyOnFail(tree);
    } catch (const std::exception& exception) {
        std::cerr << "PamPasswordSlotAttachValidatorTests failed: "
                  << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "PamPasswordSlotAttachValidatorTests passed\n";
    return EXIT_SUCCESS;
}

