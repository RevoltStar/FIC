#include "modules/identity_access/pam/PamSlotAttachValidator.h"

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

namespace fs = std::filesystem;

using fic::identity::pam::PamAuthUpdateTopologyManagerOptions;
using fic::identity::pam::PamSlotAttachVerdict;
using fic::platform::PamFaillockStrategy;
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
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "cannot write " + path.string());
    output << content;
    output.close();
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

StateFingerprint fingerprint(const fs::path& journalPath,
                             const std::array<fs::path, 4>& slots) {
    StateFingerprint state;
    std::error_code ignored;
    for (const fs::path& path : slots) {
        if (fs::is_regular_file(path, ignored)) {
            state.files.emplace_back(path, readFile(path));
        }
    }
    if (fs::is_regular_file(journalPath, ignored)) {
        state.files.emplace_back(journalPath, readFile(journalPath));
    }
    const fs::path witness = MutationJournal(journalPath).witnessPath();
    if (fs::is_regular_file(witness, ignored)) {
        state.files.emplace_back(witness, readFile(witness));
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

class TestTree {
public:
    TestTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-pam-slot-attach-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "mkdtemp failed");
        root = created;
        fs::create_directories(root / "pam.d");
        fs::create_directories(root / "security");
        fs::create_directories(root / "var/lib/pam");
        writeFile(root / "security/pam_faillock.so", "fixture\n", 0555);
        writeFile(root / "security/pam_unix.so", "fixture\n", 0555);
        writeFile(root / "pam.d/common-auth", kClean);
        writeFile(root / "pam.d/common-account",
                  "account required pam_unix.so\n");
    }

    ~TestTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    fs::path root;
    fs::path stateDir() const { return root / "var/lib/pam"; }
    fs::path journalPath() const { return root / "db/mutations.json"; }
    std::array<fs::path, 4> slotPaths() const {
        return {root / "pam.d/fic-faillock-preauth",
                root / "pam.d/fic-faillock-authfail",
                root / "pam.d/fic-faillock-authsucc",
                root / "pam.d/fic-faillock-account"};
    }

    fic::platform::PamPlatformConfig platform() const {
        fic::platform::PamPlatformConfig platform;
        platform.configDirectories = {root / "pam.d"};
        platform.moduleDirectories = {root / "security"};
        platform.scopes = {
            {fic::platform::PamScope::EffectiveAuthenticationStack,
             {"common-auth"}},
            {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
        platform.capabilities = {
            {fic::platform::PamCapability::AuthenticationLockout,
             fic::platform::PamProviderKind::PamFaillock,
             fic::platform::PamScope::EffectiveAuthenticationStack,
             root / "security/faillock.conf",
             fic::platform::PamTopologyStrategyKind::PamAuthUpdate}};
        platform.capabilities.front().supportedFaillockStrategies = {
            PamFaillockStrategy::PreauthRequired,
            PamFaillockStrategy::PreauthRequisite,
            PamFaillockStrategy::Authsucc};
        platform.capabilities.front().defaultFaillockStrategy =
            PamFaillockStrategy::PreauthRequired;
        // Mirrors the Debian/Ubuntu profiles: every strategy uses the same
        // four permanent hook identifiers.
        const std::vector<std::string> hooks = {
            "fic-faillock-hook-preauth", "fic-faillock-hook-authfail",
            "fic-faillock-hook-authsucc", "fic-faillock-hook-account"};
        platform.capabilities.front().strategyActivations = {
            {PamFaillockStrategy::PreauthRequisite, hooks},
            {PamFaillockStrategy::PreauthRequired, hooks},
            {PamFaillockStrategy::Authsucc, hooks}};
        return platform;
    }

    static const char* kClean;
};

const char* TestTree::kClean =
    "auth [success=1 default=ignore] pam_unix.so nullok\n"
    "auth requisite pam_deny.so\n"
    "auth required pam_permit.so\n";

const std::array<std::pair<const char*, bool>, 4> kSlots = {{
    {"preauth", false},
    {"authfail", false},
    {"authsucc", false},
    {"account", true},
}};

std::string neutralSlot(const std::string& name, bool account) {
    return "#@FIC_PAM_SLOT_NEUTRAL version=1 "
           "capability=enable_authentication_lockout slot=" +
           name + "\n" + (account ? "account" : "auth") +
           " optional pam_deny.so\n";
}

std::string activeSlot(const std::string& name, const std::string& rule,
                       const std::string& strategyName, std::uint64_t id) {
    return "#@FIC_PAM_SLOT_BEGIN version=1 "
           "capability=enable_authentication_lockout mutation=" +
           std::to_string(id) + " slot=" + name + " strategy=" + strategyName +
           "\n" + rule + "\n" +
           "#@FIC_PAM_SLOT_END capability=enable_authentication_lockout "
           "mutation=" +
           std::to_string(id) + " slot=" + name + "\n";
}

std::string strategyName(PamFaillockStrategy strategy) {
    switch (strategy) {
    case PamFaillockStrategy::PreauthRequisite:
        return "preauth_requisite";
    case PamFaillockStrategy::PreauthRequired:
        return "preauth_required";
    case PamFaillockStrategy::Authsucc:
        return "authsucc";
    }
    throw std::runtime_error("unknown strategy");
}

// Writes the exact canonical active topology of one strategy. Every slot
// not used by the strategy stays canonical neutral.
void writeActiveTopology(const TestTree& tree, PamFaillockStrategy strategy,
                         std::uint64_t mutationId) {
    const std::string name = strategyName(strategy);
    const std::array<fs::path, 4> paths = tree.slotPaths();
    for (std::size_t index = 0; index < kSlots.size(); ++index) {
        const std::string slot = kSlots[index].first;
        const bool account = kSlots[index].second;
        bool used = true;
        std::string rule;
        if (slot == "preauth") {
            used = strategy != PamFaillockStrategy::Authsucc;
            rule = std::string("auth ") +
                (strategy == PamFaillockStrategy::PreauthRequisite
                     ? "requisite"
                     : "required") +
                " pam_faillock.so preauth";
        } else if (slot == "authfail") {
            rule = "auth [default=die] pam_faillock.so authfail";
        } else if (slot == "authsucc") {
            used = strategy == PamFaillockStrategy::Authsucc;
            rule = "auth required pam_faillock.so authsucc";
        } else {
            used = strategy != PamFaillockStrategy::Authsucc;
            rule = "account required pam_faillock.so";
        }
        writeFile(paths[index],
                  used ? activeSlot(slot, rule, name, mutationId)
                       : neutralSlot(slot, account));
    }
}

void writeNeutralTopology(const TestTree& tree) {
    const std::array<fs::path, 4> paths = tree.slotPaths();
    for (std::size_t index = 0; index < kSlots.size(); ++index) {
        writeFile(paths[index],
                  neutralSlot(kSlots[index].first, kSlots[index].second));
    }
}

// Seeds a real journal on disk and returns the assigned mutation id.
std::uint64_t seedJournal(const fs::path& path, const char* module,
                          const char* submodule, const std::string& policy,
                          const std::string& resource,
                          fic::rollback::UndoAction undo,
                          MutationStatus status) {
    fs::create_directories(path.parent_path());
    MutationJournal journal(path);
    std::string error;
    require(journal.initializeOrLoad(error), error);
    MutationRecord record;
    record.policy = {module, submodule, policy};
    record.resource = resource;
    record.undo = std::move(undo);
    std::uint64_t id = 0;
    require(journal.prepareMutation(std::move(record), id, error), error);
    require(journal.setStatus(id, status, error), error);
    return id;
}

std::uint64_t seedOwnedJournal(const fs::path& path, MutationStatus status) {
    UndoDisablePamCapability undo;
    undo.capability = "enable_authentication_lockout";
    undo.topology = PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = {
        "fic-faillock-hook-preauth", "fic-faillock-hook-authfail",
        "fic-faillock-hook-authsucc", "fic-faillock-hook-account"};
    return seedJournal(path, "IDENTITY_ACCESS", "PAM",
                       "enable_authentication_lockout",
                       "capability/enable_authentication_lockout",
                       {MutationBackend::Pam, undo}, status);
}

std::uint64_t seedForeignPamJournal(const fs::path& path,
                                    const std::string& capability,
                                    const std::vector<std::string>& ids) {
    UndoDisablePamCapability undo;
    undo.capability = capability;
    undo.topology = PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = ids;
    return seedJournal(path, "IDENTITY_ACCESS", "PAM", capability,
                       "capability/" + capability, {MutationBackend::Pam, undo},
                       MutationStatus::Applied);
}

std::uint64_t seedForeignBackendJournal(const fs::path& path) {
    fic::rollback::UndoRemoveManagedSetting undo;
    undo.key = "env_keep";
    undo.appliedValue = "FAKE";
    return seedJournal(path, "NET", "SUDO", "sudo_env_keep", "env_keep",
                       {MutationBackend::Sudo, undo}, MutationStatus::Applied);
}

PamSlotAttachVerdict validate(const TestTree& tree,
                              const fs::path& journalPath,
                              std::string& error) {
    auto platform = tree.platform();
    const fs::path pamAuthUpdate = tree.root / "bin/pam-auth-update";
    writeFile(pamAuthUpdate, "#!/bin/sh\nexit 0\n", 0755);
    fic::platform::PlatformExecutables executableConfig;
    executableConfig.entries = {
        {fic::platform::ExecutableId::PamAuthUpdate, {pamAuthUpdate}}};
    const fic::platform::PlatformExecutableResolver resolver(
        executableConfig, {.enforceTrustedOwnership = false});
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.root / "pam.d";
    PamSlotAttachVerdict verdict;
    require(fic::identity::pam::validatePamSlotAttach(
                platform, platform.capabilities.front(), {"common-auth"},
                resolver, journalPath, options, verdict, error),
            error);
    return verdict;
}

void requireSafe(const TestTree& tree, const fs::path& journalPath) {
    std::string error = "sentinel";
    const PamSlotAttachVerdict verdict = validate(tree, journalPath, error);
    require(verdict.safeToAttach,
            "expected safe-to-attach verdict, got: " + verdict.detail);
    require(error.empty(), "safe verdict unexpectedly set an error");
}

void requireUnsafe(const TestTree& tree, const fs::path& journalPath) {
    std::string error = "sentinel";
    const PamSlotAttachVerdict verdict = validate(tree, journalPath, error);
    require(!verdict.safeToAttach,
            "expected fail-closed verdict, got: safe (" + verdict.detail + ")");
    require(error.empty(), "unsafe verdict must not be an operational error");
}

// 2 + 9. Fresh install: canonical neutral slots, no journal at all.
void testFreshNeutralSlotsPass(const TestTree& tree) {
    writeNeutralTopology(tree);
    requireSafe(tree, tree.root / "db/absent-journal.json");
}

// 9. Canonical neutral slots with an existing empty journal.
void testNeutralSlotsWithEmptyJournalPass(const TestTree& tree) {
    writeNeutralTopology(tree);
    fs::create_directories(tree.journalPath().parent_path());
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.initializeOrLoad(error), error);
    requireSafe(tree, tree.journalPath());
}

// 3. Reinstall with active slots bound to an exact matching journal record.
void testActiveSlotsWithMatchingJournalPass(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    requireSafe(tree, tree.journalPath());
}

// 3a. A Prepared (crash-window) record still proves the owned state.
void testActiveSlotsWithPreparedJournalPass(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Prepared);
    writeActiveTopology(tree, PamFaillockStrategy::Authsucc, id);
    requireSafe(tree, tree.journalPath());
}

// 4. Active slots without any journal: fail closed before attach.
void testActiveSlotsWithoutJournalFail(const TestTree& tree) {
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, 41);
    requireUnsafe(tree, tree.root / "db/absent-journal.json");
}

// 4a. Active slots with an existing but record-less journal.
void testActiveSlotsWithEmptyJournalFail(const TestTree& tree) {
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, 41);
    fs::create_directories(tree.journalPath().parent_path());
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.initializeOrLoad(error), error);
    requireUnsafe(tree, tree.journalPath());
}

// 5. Active slots referencing a mutation id the journal does not carry.
void testActiveSlotsWithWrongMutationIdFail(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    require(id != 999, "unexpected journal id");
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, 999);
    requireUnsafe(tree, tree.journalPath());
}

// 5a. Non-active journal provenance cannot prove active slots.
void testRolledBackJournalFails(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::RolledBack);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    requireUnsafe(tree, tree.journalPath());
}

// 5b. Journal records proving another capability/domain/backend: fail closed.
void testWrongOwnershipPayloadFails(const TestTree& tree) {
    seedForeignPamJournal(tree.journalPath(), "enable_password_history",
                          {"fic-pwhistory"});
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, 1);
    requireUnsafe(tree, tree.journalPath());

    seedForeignPamJournal(tree.journalPath(), "enable_authentication_lockout",
                          {"fic-faillock-hook-preauth"});
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, 2);
    requireUnsafe(tree, tree.journalPath());

    seedForeignBackendJournal(tree.journalPath());
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, 1);
    requireUnsafe(tree, tree.journalPath());
}

// 6. Mixed mutation ids across the slot topology: fail closed.
void testMixedMutationIdsFail(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    writeFile(tree.root / "pam.d/fic-faillock-authfail",
              activeSlot("authfail",
                         "auth [default=die] pam_faillock.so authfail",
                         "preauth_required", id + 1));
    requireUnsafe(tree, tree.journalPath());
}

// 7. Partial active strategy (authfail left neutral): fail closed.
void testPartialStrategyFails(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    writeFile(tree.root / "pam.d/fic-faillock-authfail",
              neutralSlot("authfail", false));
    requireUnsafe(tree, tree.journalPath());
}

// 7a. A missing slot file cannot be proven either.
void testMissingSlotFails(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    std::error_code ignored;
    fs::remove(tree.root / "pam.d/fic-faillock-account", ignored);
    requireUnsafe(tree, tree.journalPath());
}

// 8. Malformed marker: fail closed.
void testMalformedSlotFails(const TestTree& tree) {
    writeNeutralTopology(tree);
    writeFile(tree.root / "pam.d/fic-faillock-preauth",
              "#@FIC_PAM_SLOT_BEGIN broken\nauth required pam_faillock.so\n");
    requireUnsafe(tree, tree.journalPath());
}

// 8a. Modified active-slot body (foreign tail): fail closed.
void testModifiedSlotBodyFails(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    writeFile(tree.root / "pam.d/fic-faillock-account",
              activeSlot("account", "account required pam_faillock.so",
                         "preauth_required", id) +
                  "# foreign tail\n");
    requireUnsafe(tree, tree.journalPath());
}

// 10. The validator is strictly read-only on the PASS path.
void testValidatorIsReadOnlyOnPass(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id);
    const StateFingerprint before =
        fingerprint(tree.journalPath(), tree.slotPaths());
    requireSafe(tree, tree.journalPath());
    const StateFingerprint after =
        fingerprint(tree.journalPath(), tree.slotPaths());
    requireUnchanged(before, after);
}

// 10a. The validator is strictly read-only on the FAIL path.
void testValidatorIsReadOnlyOnFail(const TestTree& tree) {
    const std::uint64_t id =
        seedOwnedJournal(tree.journalPath(), MutationStatus::Applied);
    writeActiveTopology(tree, PamFaillockStrategy::PreauthRequired, id + 5);
    const StateFingerprint before =
        fingerprint(tree.journalPath(), tree.slotPaths());
    requireUnsafe(tree, tree.journalPath());
    const StateFingerprint after =
        fingerprint(tree.journalPath(), tree.slotPaths());
    requireUnchanged(before, after);
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
        testFreshNeutralSlotsPass(tree);
        testNeutralSlotsWithEmptyJournalPass(tree);
        testActiveSlotsWithMatchingJournalPass(tree);
        testActiveSlotsWithPreparedJournalPass(tree);
        testActiveSlotsWithoutJournalFail(tree);
        testActiveSlotsWithEmptyJournalFail(tree);
        testActiveSlotsWithWrongMutationIdFail(tree);
        testRolledBackJournalFails(tree);
        testWrongOwnershipPayloadFails(tree);
        testMixedMutationIdsFail(tree);
        testPartialStrategyFails(tree);
        testMissingSlotFails(tree);
        testMalformedSlotFails(tree);
        testModifiedSlotBodyFails(tree);
        testValidatorIsReadOnlyOnPass(tree);
        testValidatorIsReadOnlyOnFail(tree);
    } catch (const std::exception& exception) {
        std::cerr << "PamSlotAttachValidatorTests failed: " << exception.what()
                  << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "PamSlotAttachValidatorTests passed\n";
    return EXIT_SUCCESS;
}
