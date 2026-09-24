// Step 5B safe bootstrap tests for the three FIC managed password slots:
// existence-only provisioning contract (exclusive canonical neutral
// creation for genuinely absent paths, untouched existing regular files,
// fail-closed symlink/directory/special handling, idempotence, honest
// changedSystemState accounting, no journal/witness mutation) plus the
// bootstrap/validator separation proofs, by the model of
// PamPasswordSlotAttachValidatorTests.cpp.
#include "modules/identity_access/pam/PamManagedPasswordSlotBootstrap.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamSlotAttachValidator.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace fs = std::filesystem;

using fic::identity::pam::ManagedPasswordSlotRole;
using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamAttachmentValidationPhase;
using fic::identity::pam::PamAuthUpdateTopologyManagerOptions;
using fic::identity::pam::PamManagedPasswordSlotBootstrap;
using fic::identity::pam::PamManagedPasswordSlotBootstrapOptions;
using fic::identity::pam::PamManagedPasswordSlotBootstrapResult;
using fic::identity::pam::PamManagedPasswordSlotBootstrapStatus;
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
            ::write(fd, content.data() + written,
                    content.size() - static_cast<std::size_t>(written));
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

PamManagedPasswordSlotBootstrapOptions testOptions() {
    PamManagedPasswordSlotBootstrapOptions options;
    // Unit tests may run unprivileged: expect the running identity while
    // exercising the exact same fchmod/fchown enforcement path.
    options.slotOwner = ::geteuid();
    options.slotGroup = ::getegid();
    return options;
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

// Full persistent-state fingerprint: file type, symlink target, exact
// content, inode and metadata. Used to prove that the bootstrap (and the
// validator on top of it) leaves every existing artifact untouched.
struct StateFingerprint {
    struct Entry {
        fs::path path;
        unsigned type = 0;
        std::string linkTarget;
        std::string content;
        mode_t mode = 0;
        uid_t uid = 0;
        gid_t gid = 0;
        dev_t device = 0;
        ino_t inode = 0;
        std::int64_t mtimeSec = 0;
        std::int64_t mtimeNsec = 0;
    };
    std::vector<Entry> entries;
};

StateFingerprint snapshot(const fs::path& root) {
    StateFingerprint state;
    std::vector<fs::path> paths;
    std::error_code ignored;
    for (const auto& entry : fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied,
             ignored)) {
        paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end());
    for (const auto& path : paths) {
        StateFingerprint::Entry element;
        element.path = path;
        const auto status = fs::symlink_status(path);
        element.type = static_cast<unsigned>(status.type());
        if (fs::is_symlink(status)) {
            element.linkTarget = fs::read_symlink(path).string();
        } else if (fs::is_regular_file(status)) {
            element.content = readFile(path);
            struct stat info {};
            require(::stat(path.c_str(), &info) == 0,
                    "stat failed for " + path.string());
            element.mode = info.st_mode & 07777;
            element.uid = info.st_uid;
            element.gid = info.st_gid;
            element.device = info.st_dev;
            element.inode = info.st_ino;
            element.mtimeSec =
                static_cast<std::int64_t>(info.st_mtim.tv_sec);
            element.mtimeNsec =
                static_cast<std::int64_t>(info.st_mtim.tv_nsec);
        }
        state.entries.push_back(std::move(element));
    }
    return state;
}

void requireUnchanged(const StateFingerprint& before,
                      const StateFingerprint& after,
                      const std::string& context) {
    require(before.entries.size() == after.entries.size(),
            context + ": changed the set of persisted files");
    for (std::size_t index = 0; index < before.entries.size(); ++index) {
        const auto& oldEntry = before.entries[index];
        const auto& newEntry = after.entries[index];
        require(oldEntry.path == newEntry.path &&
                    oldEntry.type == newEntry.type &&
                    oldEntry.linkTarget == newEntry.linkTarget &&
                    oldEntry.content == newEntry.content &&
                    oldEntry.mode == newEntry.mode &&
                    oldEntry.uid == newEntry.uid &&
                    oldEntry.gid == newEntry.gid &&
                    oldEntry.device == newEntry.device &&
                    oldEntry.inode == newEntry.inode &&
                    oldEntry.mtimeSec == newEntry.mtimeSec &&
                    oldEntry.mtimeNsec == newEntry.mtimeNsec,
                context + ": modified " + oldEntry.path.string());
    }
}

class TestTree {
public:
    TestTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-pam-pwd-bootstrap-XXXXXX")
                .string();
        char* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "mkdtemp failed");
        root = created;
        fs::create_directories(pamDirectory());
        fs::create_directories(root / "security");
        fs::create_directories(stateDir());
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
    fs::path pamDirectory() const { return root / "pam.d"; }
    fs::path stateDir() const { return root / "var/lib/pam"; }
    fs::path journalPath() const { return root / "db/mutations.json"; }
    fs::path stackPath() const { return root / "pam.d/passwd"; }
    fs::path stateFilePath() const { return stateDir() / "password"; }
    std::array<fs::path, 3> slotPaths() const {
        return {pamDirectory() / "fic-password-quality",
                pamDirectory() / "fic-password-history",
                pamDirectory() / "fic-password-history-initial"};
    }

    fic::platform::PamPlatformConfig platform() const {
        fic::platform::PamPlatformConfig platform;
        platform.configDirectories = {pamDirectory()};
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
             root / "security/pwhistory.conf",
             fic::platform::PamTopologyStrategyKind::PamAuthUpdate,
             {},
             std::nullopt,
             fic::platform::PamIdentitySubjectScope::AllPamSubjects,
             fic::platform::PamCapabilityConfigurationMode::
                 ModuleArguments}};
        return platform;
    }
};

const char* kPasswordStateClean = "# no FIC or distro profiles selected\n";

fic::platform::PlatformExecutableResolver resolver() {
    return fic::platform::PlatformExecutableResolver(
        fic::platform::PlatformExecutables{},
        {.enforceTrustedOwnership = false});
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

// Strictly read-only PreAttach validation on top of the fixture tree.
PamSlotAttachVerdict validatePreAttach(const TestTree& tree,
                                       std::string& error) {
    auto platform = tree.platform();
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.pamDirectory();
    PamSlotAttachVerdict verdict;
    require(
        fic::identity::pam::validatePamPasswordSlotAttach(
            platform, {"passwd"}, resolver(), tree.journalPath(), options,
            PamAttachmentValidationPhase::PreAttach, verdict, error),
        error);
    return verdict;
}

void writeStack(const TestTree& tree, const char* content) {
    writeFile(tree.stackPath(), content);
}

void writePasswordState(const TestTree& tree, const char* content) {
    writeFile(tree.stateFilePath(), content);
}

// Shared bootstrap runner with the test identity/mode expectations.
bool runBootstrap(const TestTree& tree,
                  PamManagedPasswordSlotBootstrapResult& result,
                  std::string& error) {
    PamManagedPasswordSlotBootstrap bootstrap(tree.pamDirectory(),
                                              testOptions());
    return bootstrap.run(result, error);
}

void requireCreatedNeutral(
    const PamManagedPasswordSlotBootstrapResult& result,
    const TestTree& tree) {
    require(result.slots.size() == 3, "expected three slot outcomes");
    for (std::size_t index = 0; index < result.slots.size(); ++index) {
        const auto& slot = result.slots[index];
        require(!slot.failed,
                "slot " + slot.path.string() + " failed: " + slot.error);
        require(slot.status == PamManagedPasswordSlotBootstrapStatus::Created,
                "slot " + slot.path.string() + " was not created");
        require(slot.path == tree.slotPaths()[index],
                "unexpected slot path " + slot.path.string());
    }
    require(result.changedSystemState,
            "creating all three slots must report changedSystemState");
    for (const auto& slot : tree.slotPaths()) {
        require(readFile(slot) == PamManagedPasswordSlots::neutralBody(),
                "slot " + slot.string() + " is not exactly canonical neutral");
        struct stat info {};
        require(::lstat(slot.c_str(), &info) == 0, "lstat " + slot.string());
        require(S_ISREG(info.st_mode),
                "slot is not a regular file: " + slot.string());
        require((info.st_mode & 07777) == 0644,
                "slot mode is not 0644: " + slot.string());
        require(info.st_uid == ::geteuid() && info.st_gid == ::getegid(),
                "slot owner diverges from the expected identity: " +
                    slot.string());
    }
}

void requireAlreadyPresent(
    const PamManagedPasswordSlotBootstrapResult& result) {
    require(result.slots.size() == 3, "expected three slot outcomes");
    for (const auto& slot : result.slots) {
        require(!slot.failed,
                "slot " + slot.path.string() + " failed: " + slot.error);
        require(slot.status ==
                    PamManagedPasswordSlotBootstrapStatus::AlreadyPresent,
                "slot " + slot.path.string() + " was unexpectedly modified");
    }
}

// 11.1 All absent: three canonical neutral regular files are created, no
// journal/witness appears, and the repeated run is a fingerprint-identical
// no-op.
void testAllAbsentCreatesNeutral() {
    TestTree tree;
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(runBootstrap(tree, result, error), error);
    requireCreatedNeutral(result, tree);
    require(!fs::exists(tree.journalPath()),
            "bootstrap must not create the mutation journal");
    require(!fs::exists(tree.journalPath().string() + ".initialized"),
            "bootstrap must not create the journal witness");

    const StateFingerprint before = snapshot(tree.root);
    PamManagedPasswordSlotBootstrapResult second;
    require(runBootstrap(tree, second, error), error);
    requireAlreadyPresent(second);
    require(!second.changedSystemState,
            "idempotent bootstrap must not report changedSystemState");
    requireUnchanged(before, snapshot(tree.root),
                     "repeated bootstrap run");
}

// 11.2 Existing Neutral: byte-identical and metadata-identical no-op.
void testExistingNeutralUntouched() {
    TestTree tree;
    for (const auto& slot : tree.slotPaths()) {
        writeFile(slot, PamManagedPasswordSlots::neutralBody());
    }
    const StateFingerprint before = snapshot(tree.root);
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(runBootstrap(tree, result, error), error);
    requireAlreadyPresent(result);
    require(!result.changedSystemState, "neutral no-op changed the system");
    requireUnchanged(before, snapshot(tree.root),
                     "bootstrap over existing neutral slots");
}

// 11.11 Durability fault (test seam of the atomic writer): the parent
// directory fsync fails after the publish. The run must fail closed, keep
// the honest changedSystemState accounting (the slot IS physically there)
// and the retry must complete idempotently.
void testDurabilityFailureFailsClosed() {
    TestTree tree;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    const bool ran = runBootstrap(tree, result, error);
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!ran, "a durability failure must fail the bootstrap");
    require(result.changedSystemState,
            "an installed-but-unconfirmed creation is a system change");
    require(!result.slots.empty() && result.slots[0].failed,
            "the failing slot must carry the failure");
    require(result.slots[0].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "the installed slot must be reported as created");
    require(readFile(tree.slotPaths()[0]) ==
                PamManagedPasswordSlots::neutralBody(),
            "the installed slot must carry the canonical neutral bytes");
    require(!fs::exists(tree.slotPaths()[1]) &&
                !fs::exists(tree.slotPaths()[2]),
            "fail-fast must not attempt later slots");

    // Recovery: with durability working again, the run completes and the
    // previously installed slot is an AlreadyPresent no-op.
    result = PamManagedPasswordSlotBootstrapResult{};
    require(runBootstrap(tree, result, error), error);
    require(result.slots[0].status ==
                PamManagedPasswordSlotBootstrapStatus::AlreadyPresent,
            "the installed slot must not be rewritten");
    require(result.slots[1].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "the missing second slot must be created");
    require(result.slots[2].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "the missing third slot must be created");
    // All three slots physically hold the exact canonical neutral bytes
    // after the recovery run; slot 0 keeps its AlreadyPresent outcome
    // (the durability-confirmed creation is never rewritten).
    for (const auto& slot : tree.slotPaths()) {
        require(readFile(slot) == PamManagedPasswordSlots::neutralBody(),
                "slot " + slot.string() +
                    " is not exactly canonical neutral after recovery");
    }
}

// 11.3 Existing valid Active with MatchingApplied journal/witness fixture:
// slot bytes, journal document and witness are untouched.
void testExistingActiveWithJournalUntouched() {
    TestTree tree;
    const std::uint64_t qualityId =
        seedQualityJournal(tree.journalPath(), MutationStatus::Applied);
    const std::uint64_t historyId =
        seedHistoryJournal(tree.journalPath(), MutationStatus::Applied);
    const ManagedPwhistorySlotOptions options{10u, true};
    writeFile(tree.slotPaths()[0], activeQualitySlot(qualityId));
    writeFile(tree.slotPaths()[1],
              activeHistoryNormalSlot(historyId, options));
    writeFile(tree.slotPaths()[2],
              activeHistoryInitialSlot(historyId, options));
    const StateFingerprint before = snapshot(tree.root);
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(runBootstrap(tree, result, error), error);
    requireAlreadyPresent(result);
    require(!result.changedSystemState,
            "bootstrap must never rewrite an active slot");
    requireUnchanged(before, snapshot(tree.root),
                     "bootstrap over active slots + journal + witness");
}

// 11.4/12.2 Existing corrupt regular file: bootstrap is an existence no-op
// (never repairs), and the PreAttach validator fails the same tree UNSAFE.
void testCorruptRegularNotRepairedThenValidatorUnsafe() {
    TestTree tree;
    writeFile(tree.slotPaths()[0], "# corrupted foreign content\n");
    writeFile(tree.slotPaths()[1], PamManagedPasswordSlots::neutralBody());
    writeFile(tree.slotPaths()[2], PamManagedPasswordSlots::neutralBody());
    const StateFingerprint before = snapshot(tree.root);
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(runBootstrap(tree, result, error), error);
    requireAlreadyPresent(result);
    require(!result.changedSystemState,
            "bootstrap must not repair or rewrite a corrupt slot");
    requireUnchanged(before, snapshot(tree.root),
                     "bootstrap over a corrupt slot");

    writeStack(tree, "password required pam_unix.so\n");
    writePasswordState(tree, kPasswordStateClean);
    const StateFingerprint validatorBefore = snapshot(tree.root);
    std::string validationError;
    const PamSlotAttachVerdict verdict =
        validatePreAttach(tree, validationError);
    require(!verdict.safeToAttach,
            "corrupt slot must fail the PreAttach validation: " +
                verdict.detail);
    requireUnchanged(validatorBefore, snapshot(tree.root),
                     "validator after bootstrap");
}

// 11.5 Symlink to a regular target: bootstrap fails closed, the target is
// untouched.
void testSymlinkSlotFailsClosed() {
    const fs::path target =
        fs::temp_directory_path() / "fic-pam-bootstrap-symlink-target";
    writeFile(target, "victim\n");
    TestTree tree;
    std::error_code ignored;
    fs::create_symlink(target, tree.slotPaths()[0], ignored);
    require(fs::is_symlink(tree.slotPaths()[0]), "symlink fixture failed");
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(!runBootstrap(tree, result, error),
            "symlink slot must fail the bootstrap");
    require(result.slots.size() == 1, "fail-fast must stop after slot 1");
    require(result.slots[0].failed, "first slot must carry the failure");
    require(readFile(target) == "victim\n", "symlink target was modified");
    fs::remove(target, ignored);
}

// 11.6 Dangling symlink: fails closed exactly like a live symlink.
void testDanglingSymlinkSlotFailsClosed() {
    TestTree tree;
    std::error_code ignored;
    fs::create_symlink(tree.root / "nowhere", tree.slotPaths()[1], ignored);
    require(fs::is_symlink(tree.slotPaths()[1]),
            "dangling symlink fixture failed");
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(!runBootstrap(tree, result, error),
            "dangling symlink slot must fail the bootstrap");
    require(result.slots.size() == 2, "fail-fast must stop after slot 2");
    require(result.slots[1].failed, "second slot must carry the failure");
    require(fs::is_symlink(tree.slotPaths()[1]),
            "dangling symlink was replaced");
}

// 11.7 Directory occupying the slot path: fails closed, never removed.
void testDirectorySlotFailsClosed() {
    TestTree tree;
    fs::create_directories(tree.slotPaths()[2]);
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(!runBootstrap(tree, result, error),
            "directory slot must fail the bootstrap");
    require(result.slots[2].failed, "third slot must carry the failure");
    require(fs::is_directory(tree.slotPaths()[2]),
            "directory was removed by the bootstrap");
}

// 11.8 FIFO (special file): fails closed.
void testFifoSlotFailsClosed() {
    TestTree tree;
    require(::mkfifo(tree.slotPaths()[0].c_str(), 0644) == 0,
            "mkfifo fixture failed");
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(!runBootstrap(tree, result, error),
            "FIFO slot must fail the bootstrap");
    require(result.slots[0].failed, "first slot must carry the failure");
    struct stat info {};
    require(::lstat(tree.slotPaths()[0].c_str(), &info) == 0,
            "lstat on the FIFO");
    require(S_ISFIFO(info.st_mode), "FIFO was replaced by the bootstrap");
}

// 11.9 Partial existing state: only the genuinely absent slots are
// created; the existing neutral slot is untouched.
void testPartialExistingState() {
    TestTree tree;
    writeFile(tree.slotPaths()[1], PamManagedPasswordSlots::neutralBody());
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(runBootstrap(tree, result, error), error);
    require(result.slots.size() == 3, "expected three slot outcomes");
    require(result.slots[0].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "absent quality slot must be created");
    require(result.slots[1].status ==
                PamManagedPasswordSlotBootstrapStatus::AlreadyPresent,
            "existing history slot must not be touched");
    require(result.slots[2].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "absent history-initial slot must be created");
    require(result.changedSystemState, "two creations are a system change");
    require(readFile(tree.slotPaths()[1]) ==
                PamManagedPasswordSlots::neutralBody(),
            "existing neutral slot diverged");
}

// 11.10 Failure during creation (injected pre-write fault): fail-fast,
// honest accounting (earlier creation stays reported), later slots never
// attempted; the retry completes the provisioning.
void testFailureDuringCreation() {
    TestTree tree;
    PamManagedPasswordSlotBootstrap bootstrap(tree.pamDirectory(),
                                              testOptions());
    std::size_t calls = 0;
    bootstrap.setBeforeSlotWriteHookForTests(
        [&calls](std::size_t slotIndex) {
            ++calls;
            return slotIndex != 1;  // fail exactly the history slot
        });
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(!bootstrap.run(result, error),
            "injected failure must fail the bootstrap");
    require(error.find("injected failure") != std::string::npos,
            "failure diagnostic must carry the fault: " + error);
    require(result.slots.size() == 2, "fail-fast must stop after slot 2");
    require(!result.slots[0].failed &&
                result.slots[0].status ==
                    PamManagedPasswordSlotBootstrapStatus::Created,
            "first slot must stay proven-created");
    require(result.slots[1].failed, "second slot must carry the failure");
    require(result.changedSystemState,
            "the created first slot is a real system change");
    require(!fs::exists(tree.slotPaths()[2]),
            "no slot after the failed one may be attempted");
    require(calls == 2, "the hook must run exactly per attempted slot");

    // The retry is idempotent-safe: the existing creation is a no-op
    // (AlreadyPresent, never rewritten) and the remaining slots are
    // provisioned.
    result = PamManagedPasswordSlotBootstrapResult{};
    require(runBootstrap(tree, result, error), error);
    require(result.slots.size() == 3, "expected three slot outcomes");
    require(result.slots[0].status ==
                PamManagedPasswordSlotBootstrapStatus::AlreadyPresent,
            "the retry must not rewrite the durability-confirmed slot");
    require(result.slots[1].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "the retry must provision the second slot");
    require(result.slots[2].status ==
                PamManagedPasswordSlotBootstrapStatus::Created,
            "the retry must provision the third slot");
    for (const auto& slot : tree.slotPaths()) {
        require(readFile(slot) == PamManagedPasswordSlots::neutralBody(),
                "slot " + slot.string() +
                    " is not exactly canonical neutral after the retry");
    }
    require(fs::exists(tree.slotPaths()[2]),
            "the retry must provision the remaining slot");
}

// 12.1 Fresh absent slots: bootstrap, then the PreAttach validation is
// SAFE and strictly read-only; no journal/witness was created along the
// whole path. Proves the separation: bootstrap = existence, validator =
// validity.
void testBootstrapThenValidatorSafe() {
    TestTree tree;
    PamManagedPasswordSlotBootstrapResult result;
    std::string error;
    require(runBootstrap(tree, result, error), error);

    writeStack(tree, "password required pam_unix.so\n");
    writePasswordState(tree, kPasswordStateClean);
    const StateFingerprint before = snapshot(tree.root);
    std::string validationError;
    const PamSlotAttachVerdict verdict =
        validatePreAttach(tree, validationError);
    require(verdict.safeToAttach,
            "bootstrapped neutral slots must be PreAttach-safe: " +
                verdict.detail + " | err: " + validationError);
    requireUnchanged(before, snapshot(tree.root),
                     "validator after a fresh bootstrap");
    require(!fs::exists(tree.journalPath()),
            "validator must not create the journal");
    require(!fs::exists(tree.journalPath().string() + ".initialized"),
            "validator must not create the witness");
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
        testAllAbsentCreatesNeutral();
        testExistingNeutralUntouched();
        testDurabilityFailureFailsClosed();
        testExistingActiveWithJournalUntouched();
        testCorruptRegularNotRepairedThenValidatorUnsafe();
        testSymlinkSlotFailsClosed();
        testDanglingSymlinkSlotFailsClosed();
        testDirectorySlotFailsClosed();
        testFifoSlotFailsClosed();
        testPartialExistingState();
        testFailureDuringCreation();
        testBootstrapThenValidatorSafe();
    } catch (const std::exception& exception) {
        std::cerr << "PamManagedPasswordSlotBootstrapTests failed: "
                  << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "PamManagedPasswordSlotBootstrapTests passed\n";
    return EXIT_SUCCESS;
}