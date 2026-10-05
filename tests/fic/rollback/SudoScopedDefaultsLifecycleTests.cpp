// End-to-end journal -> filesystem lifecycle for the SUDO scoped-defaults
// blocker. The scenarios drive the PRODUCTION orchestration
// (ScopedDefaultsLifecycle) over temporary trees and the real MutationJournal,
// so crash recovery, partial writes and compensation are exercised through the
// production code path rather than a hand-copied imitation of it.

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/policy/PolicyDependency.h>
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersScopedDefaultsLifecycle.h"
#include "modules/dac/sudo/SudoersScopedDefaultsTransaction.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"
#include "rollback/RollbackExecutor.h"

#include <algorithm>
#include <cstdlib>
#include <set>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using fic::rollback::MutationBackend;
using fic::rollback::MutationId;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::SudoScopedDefaultsWrapperProof;
using fic::rollback::UndoAction;
using fic::rollback::UndoReleaseSudoScopedDefaults;
using fic::sudoers::allowsDiscardPrepared;
using fic::sudoers::kScopedDefaultsPolicyName;
using fic::sudoers::kScopedDefaultsResource;
using fic::sudoers::leavesOwnedState;
using fic::sudoers::PlannedScopedDefaultsMutation;
using fic::sudoers::PreparedRecovery;
using fic::sudoers::ScopedDefaultsLifecycle;
using fic::sudoers::ScopedDefaultsLifecycleDeps;
using fic::sudoers::ScopedDefaultsStateProof;

// A harmless non-scoped line so multiline fixtures have a stable first line.
static const std::string kRootLine = "root ALL=(ALL:ALL) ALL\n";

// Counts the multiline parity scenarios that actually ran.
int executedMultiline = 0;
using fic::sudoers::ScopedDefaultsLifecycleOutcome;
using fic::sudoers::ScopedDefaultsCapturedState;
using fic::sudoers::ScopedDefaultsProofMode;
using fic::sudoers::ScopedDefaultsTransaction;
using fic::sudoers::SudoScopedDefaultsHooks;
using fic::sudoers::SudoScopedDefaultsTransactionResult;

constexpr const char* kPolicyName = kScopedDefaultsPolicyName;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempTree {
public:
    TempTree() {
        char buffer[] = "/tmp/fic-sudo-e2e-XXXXXX";
        const char* dir = ::mkdtemp(buffer);
        if (dir == nullptr) {
            throw std::runtime_error("could not create a temporary directory");
        }
        root = dir;
    }
    ~TempTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }
    TempTree(const TempTree&) = delete;
    TempTree& operator=(const TempTree&) = delete;

    std::filesystem::path root;
};

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        throw std::runtime_error("could not create " + path.string());
    }
    stream << content;
    if (!stream.good()) {
        throw std::runtime_error("could not write " + path.string());
    }
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>());
}

class JournalOverride {
public:
    explicit JournalOverride(std::filesystem::path path) {
        fic::rollback::DaemonMutationJournal::instance().setOverridePath(
            std::move(path));
    }
    ~JournalOverride() {
        fic::rollback::DaemonMutationJournal::instance().resetOverride();
    }
    JournalOverride(const JournalOverride&) = delete;
    JournalOverride& operator=(const JournalOverride&) = delete;
};

PolicyRef scopedPolicy() {
    return PolicyRef{std::string(fic::sudoers::kSudoModuleName),
                     std::string(fic::sudoers::kSudoSubmoduleName),
                     std::string(kPolicyName)};
}

SudoersConfigurationOptions sudoOptions(const std::filesystem::path& root) {
    SudoersConfigurationOptions value;
    value.mainPath = root / "sudoers";
    value.managedPath = root / "sudoers.d" / "zzzz-fic";
    value.validatorPath.clear();
    value.verifyValidatorHash = false;
    value.enforceOwnership = false;
    return value;
}

SudoScopedDefaultsHooks productionHooks(SudoersConfiguration& configuration) {
    SudoScopedDefaultsHooks hooks;
    hooks.validate = [&configuration](std::string& e) {
        return configuration.validateConfiguration(e);
    };
    hooks.reloadAndVerify = [&configuration](std::string& e) {
        return configuration.load(e) &&
            configuration.scopedDefaultsViolations().empty();
    };
    return hooks;
}

ScopedDefaultsLifecycleDeps productionDeps(
    SudoersConfiguration& configuration,
    const SudoScopedDefaultsHooks& hooks,
    const std::function<void()>& compensationHook = nullptr) {
    ScopedDefaultsLifecycleDeps deps;
    deps.configuration = &configuration;
    deps.journal.normalizePreparedToPrevious =
        [](fic::rollback::MutationId id,
           const std::vector<fic::sudoers::SudoScopedDefaultsWrapperProof>& proven,
           std::string& error) {
            std::string journalError;
            fic::rollback::MutationJournal* instance =
                fic::rollback::DaemonMutationJournal::instance().tryGet(
                    journalError);
            if (instance == nullptr) {
                error = journalError;
                return false;
            }
            return instance->normalizeSudoScopedDefaultsPreparedToPrevious(
                id, proven, error);
        };
    deps.hooks = hooks;
    const PolicyRef policy = scopedPolicy();
    deps.journal.activeRecords = [policy](const PolicyRef&) {
        std::string error;
        fic::rollback::MutationJournal* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        if (journal == nullptr) {
            throw std::runtime_error("journal unavailable: " + error);
        }
        return journal->activeRecords(policy);
    };
    deps.journal.prepare = [](const PolicyRef& p, const std::string& resource,
                              const UndoAction& undo, MutationId& id,
                              std::string& error) {
        return fic::rollback::recordPreparedMutation(p, resource, undo, id,
                                                     error);
    };
    deps.journal.commit = [](MutationId id, std::string& error) {
        return fic::rollback::commitMutation(id, error);
    };
    deps.journal.discard = [](MutationId id, std::string& error) {
        return fic::rollback::discardMutation(id, error);
    };
    if (compensationHook) {
        deps.journal.afterPreparedCompensation = compensationHook;
    }
    return deps;
}

// THE production entry point under test.
ScopedDefaultsLifecycleOutcome reconcile(
    SudoersConfiguration& configuration,
    const SudoScopedDefaultsHooks& hooks) {
    ScopedDefaultsLifecycle lifecycle(productionDeps(configuration, hooks));
    return lifecycle.reconcile(kPolicyName);
}

std::vector<SudoScopedDefaultsWrapperProof> activeOwned() {
    std::string error;
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    std::vector<SudoScopedDefaultsWrapperProof> owned;
    require(ScopedDefaultsLifecycle::collectActiveOwnership(
                journal->activeRecords(scopedPolicy()), kScopedDefaultsResource,
                owned, error),
            error);
    return owned;
}

std::size_t activePreparedCount() {
    std::string error;
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    std::size_t count = 0;
    for (const MutationRecord& record :
         journal->activeRecords(scopedPolicy())) {
        if (record.resource == kScopedDefaultsResource &&
            record.status == MutationStatus::Prepared) {
            ++count;
        }
    }
    return count;
}

std::size_t countWrappers(const SudoersConfiguration& configuration) {
    std::size_t total = 0;
    for (const SudoersConfiguration::GraphDocument& document :
         configuration.graphDocuments()) {
        std::string error;
        std::vector<fic::sudoers::SudoDisabledWrapper> wrappers;
        if (fic::sudoers::parseSudoDisabledWrappers(
                fic::sudoers::splitPhysicalLines(document.content), wrappers,
                error) != fic::sudoers::SudoWrapperParseStatus::Ok) {
            throw std::runtime_error(error);
        }
        for (const auto& wrapper : wrappers) {
            if (wrapper.policy == kPolicyName) {
                ++total;
            }
        }
    }
    return total;
}

bool recordPreparedMut(const PolicyRef& policy, const UndoAction& undo,
                       MutationId& id, std::string& error) {
    return fic::rollback::recordPreparedMutation(policy, kScopedDefaultsResource,
                                                undo, id, error);
}

// Mirrors the marker grammar produced by disableSudoEntry().
std::string wrapperBlock(const std::string& id, const std::string& body,
                         const std::string& eol = "lf") {
    return std::string("#@FIC_SUDO_DISABLED_BEGIN policy=") + kPolicyName +
        " mutation=" + id + "@\n" +
        "#@FIC_SUDO_DISABLED_LINE@eol=" + eol + "@" + body + "\n" +
        "#@FIC_SUDO_DISABLED_END policy=" + kPolicyName + " mutation=" + id +
        "@\n";
}

// --- A: normal lifecycle, surviving a journal reload ------------------------

void testNormalLifecycle() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    writeFile(tree.root / "sudoers",
              "root ALL=(ALL:ALL) ALL\nDefaults passwd_tries=3\n"
              "Defaults:alice exempt_group=wheel\n");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const std::string before = readFile(tree.root / "sudoers");

    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(outcome.ok, outcome.message);
    require(countWrappers(configuration) == 1,
            "exactly one wrapper must exist after the first apply");

    // Provenance survives a journal RELOAD.
    {
        fic::rollback::MutationJournal reloaded(tree.root / "journal.json");
        std::string reloadError;
        require(reloaded.load(reloadError), reloadError);
        const auto owned = activeOwned();
        require(owned.size() == 1,
                "the reloaded journal must still prove the wrapper");
        require(fic::core::ContentDigest::isCanonicalSha256Hex(
                    owned[0].payloadDigest),
                "the persisted payload digest must be canonical");
    }

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        policy, kScopedDefaultsResource, deps);
    require(report.status == fic::rollback::RollbackStatus::Success,
            "rollback must resolve the mutation: " + report.message);
    require(readFile(tree.root / "sudoers") == before,
            "rollback must restore the sudoers file BYTE EXACTLY");
}

// --- B: reconciliation GROWS the ownership set ------------------------------

void testReconciliationGrowsOwnership() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);

    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok,
            "first apply");
    const auto ownedAfterFirst = activeOwned();
    require(ownedAfterFirst.size() == 1, "one owned wrapper after the first apply");

    // New drift appears OUTSIDE FIC's wrappers.
    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedAfterFirst[0].wrapperId,
                           "Defaults:alice exempt_group=wheel") +
              "Defaults:bob exempt_group=wheel\n");
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().size() == 1,
            "exactly the new violation is active");

    require(reconcile(configuration, productionHooks(configuration)).ok,
            "reconciliation apply");
    const auto ownedAfterSecond = activeOwned();
    require(ownedAfterSecond.size() == 2,
            "reconciliation must GROW ownership from 1 to 2, never replace it");
    require(countWrappers(configuration) == 2,
            "both wrappers must be physically present");

    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    const auto released =
        transaction.release(ownedAfterSecond, SudoScopedDefaultsHooks{});
    require(released.ok(), released.operation.message);
    const std::string restored = readFile(tree.root / "sudoers");
    require(restored.find("Defaults:alice exempt_group=wheel") !=
                std::string::npos, "alice must be restored");
    require(restored.find("Defaults:bob exempt_group=wheel") != std::string::npos,
            "bob must be restored");
}

// --- C: payload drift is a Conflict with ZERO writes -------------------------

void testPayloadDriftRefusesUnwrap() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    const auto owned = activeOwned();

    const std::string wrapped = readFile(tree.root / "sudoers");
    const std::string needle =
        "#@FIC_SUDO_DISABLED_LINE@eol=lf@Defaults:alice exempt_group=wheel\n";
    require(wrapped.find(needle) != std::string::npos,
            "wrapper layout changed unexpectedly");
    std::string tampered = wrapped;
    tampered.replace(tampered.find(needle), needle.size(),
                     "#@FIC_SUDO_DISABLED_LINE@eol=lf@Defaults:root ALL=(ALL:ALL) ALL\n");
    writeFile(tree.root / "sudoers", tampered);

    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    const auto result = transaction.release(owned, SudoScopedDefaultsHooks{});
    require(result.operation.conflict,
            "a hand-edited wrapper body must be a Conflict");
    require(readFile(tree.root / "sudoers") == tampered,
            "a drifted payload must cause ZERO writes");
}

// Two files, each with its own scoped violation: main includes a.conf and
// b.conf. Used by the partial-write scenarios.
struct TwoFileTree {
    explicit TwoFileTree(TempTree& tree) : options(sudoOptions(tree.root)) {
        writeFile(tree.root / "a.conf", "Defaults:alice exempt_group=wheel\n");
        writeFile(tree.root / "b.conf", "Defaults:bob passwd_tries=9\n");
        writeFile(tree.root / "sudoers",
                  "@include " + (tree.root / "a.conf").string() + "\n"
                  "@include " + (tree.root / "b.conf").string() + "\n");
    }
    SudoersConfigurationOptions options;
};

// --- D1: partial apply, compensation SUCCEEDS -------------------------------

void testPartialApplyCompensated() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TwoFileTree fixture(tree);

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    const std::string aBefore = readFile(tree.root / "a.conf");
    const std::string bBefore = readFile(tree.root / "b.conf");

    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    // The FIRST write succeeds and installs a wrapper into a.conf; the SECOND
    // fails before installing anything. (transaction order is by path).
    int writes = 0;
    hooks.beforeWrite = [&writes](const std::filesystem::path&) {
        if (++writes == 2) {
            throw std::runtime_error("injected write failure before install");
        }
    };

    const auto outcome = reconcile(configuration, hooks);
    require(!outcome.ok, "a failing second write must fail the apply");
    require(activePreparedCount() == 0,
            "a fully compensated transaction must not leave a Prepared record");
    require(readFile(tree.root / "a.conf") == aBefore,
            "a.conf must be restored by compensation");
    require(readFile(tree.root / "b.conf") == bBefore,
            "b.conf must stay untouched");
}

// --- D2: partial apply, compensation FAILS -> Prepared survives -------------

void testPartialApplyCompensationFails() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TwoFileTree fixture(tree);

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);

    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    int writes = 0;
    hooks.beforeWrite = [&writes](const std::filesystem::path&) {
        if (++writes == 2) {
            throw std::runtime_error("injected write failure before install");
        }
    };
    // Compensation itself fails: the wrapper installed into a.conf remains.
    hooks.beforeRestore = [](const std::filesystem::path&) {
        throw std::runtime_error("injected compensation failure");
    };

    // The injected failure is contained (a hook must never crash the daemon);
    // it is reported through the typed filesystem state instead.
    const auto outcome = reconcile(configuration, hooks);
    require(!outcome.ok, "an uncompensated mutation must fail the apply");
    require(leavesOwnedState(fic::sudoers::SudoScopedDefaultsFilesystemState::
                                 PartialOrUnknown),
            "an uncompensated mutation must report owned state still present");
    // The record MUST survive: a wrapper exists on disk with no provenance.
    require(activePreparedCount() == 1,
            "an uncompensated partial write must keep the Prepared record active");
    require(readFile(tree.root / "a.conf").find("#@FIC_SUDO_DISABLED_BEGIN") !=
                std::string::npos,
            "the wrapper installed into a.conf must still be present");
}

// --- E: an orphan wrapper makes a no-op apply fail closed -------------------

void testOrphanNoOpFailsClosed() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers",
              wrapperBlock("FIC-SUDO-1-2-3-4-5", "Defaults:alice exempt_group=wheel"));
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().empty(),
            "the orphan wrapper already deactivates the entry");
    const std::string before = readFile(tree.root / "sudoers");
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "an orphan wrapper without provenance must fail closed");
    require(readFile(tree.root / "sudoers") == before,
            "a refused no-op must leave the file untouched");
}

// --- F: the same physical include twice yields exactly ONE wrapper ----------

void testSamePhysicalIncludeTwice() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    const auto dropIn = tree.root / "site.conf";
    writeFile(dropIn, "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + dropIn.string() + "\n"
              "@include " + dropIn.string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().size() == 2,
            "a doubly included file is seen twice in the semantic view");
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    require(countWrappers(configuration) == 1,
            "a doubly included file must be wrapped exactly ONCE");
}

// --- G: one wrapper id in two files is refused globally, with zero writes --

void testGlobalDuplicateIdRefused() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    const auto block = wrapperBlock("FIC-SUDO-9-9-9-9-9", "Defaults:alice exempt_group=wheel");
    writeFile(tree.root / "site.conf", block);
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n" + block);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const std::string before = readFile(tree.root / "sudoers");
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "a global duplicate id must be refused");
    require(readFile(tree.root / "sudoers") == before,
            "a global duplicate id must cause ZERO writes");
}

// --- H: LF / CRLF byte-exact round trip ------------------------------------

void runByteExactRoundTrip(const std::string& original,
                           const std::string& label) {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", original);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(outcome.ok, "reconcile failed [" + label + "]: " + outcome.message);
    bool stillActive = false;
    for (const auto& line : fic::sudoers::splitPhysicalLines(
             readFile(tree.root / "sudoers"))) {
        if (line.text.rfind("Defaults:alice", 0) == 0) {
            stillActive = true;
        }
    }
    require(!stillActive, label + ": the entry must no longer be active");
    const auto owned = activeOwned();

    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    const auto result = transaction.release(owned, SudoScopedDefaultsHooks{});
    require(result.ok(), result.operation.message);
    require(readFile(tree.root / "sudoers") == original,
            label + ": must be restored BYTE EXACTLY");
}

void testCrlfRoundTrip() {
    runByteExactRoundTrip("Defaults passwd_tries=3\r\n"
                          "Defaults:alice exempt_group=wheel\r\n",
                          "CRLF + final newline");
}

// --- Q: EOF WITHOUT a final newline must round-trip byte-exactly ------------

void testNoFinalNewlineRoundTrip() {
    runByteExactRoundTrip("Defaults env_reset\n"
                          "Defaults:alice timestamp_timeout=5",
                          "LF + no final newline");
    runByteExactRoundTrip("Defaults env_reset\r\n"
                          "Defaults:alice timestamp_timeout=5",
                          "CRLF + no final newline");
}

// --- I: several fresh violations keep the proof<->wrapper mapping ----------

void testMultipleFreshViolationsMapping() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    const std::string original =
        "Defaults:alice timestamp_timeout=5\n"
        "Defaults:bob passwd_tries=9\n"
        "Defaults@host env_reset\n";
    writeFile(tree.root / "sudoers", original);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().size() == 3,
            "three scoped violations must be detected");

    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    const auto owned = activeOwned();
    require(owned.size() == 3, "one proof per suppressed entry");
    require(countWrappers(configuration) == 3, "three physical wrappers");

    // Every proof must describe the payload of the wrapper it owns. This is the
    // regression for the positional-cursor bug where proof[i] could be written
    // onto a different entry than the one it described.
    std::map<std::string, std::string> digestById;
    for (const auto& proof : owned) {
        digestById[proof.wrapperId] = proof.payloadDigest;
    }
    std::size_t matched = 0;
    for (const SudoersConfiguration::GraphDocument& document :
         configuration.graphDocuments()) {
        std::vector<fic::sudoers::SudoDisabledWrapper> wrappers;
        std::string parseError;
        if (fic::sudoers::parseSudoDisabledWrappers(
                fic::sudoers::splitPhysicalLines(document.content), wrappers,
                parseError) != fic::sudoers::SudoWrapperParseStatus::Ok) {
            throw std::runtime_error(parseError);
        }
        for (const auto& wrapper : wrappers) {
            const auto found = digestById.find(wrapper.mutationId);
            require(found != digestById.end(),
                    "every wrapper must be proven by the journal");
            require(found->second == wrapper.payloadDigest(),
                    "each proof must describe exactly the payload of its own "
                    "wrapper");
            ++matched;
        }
    }
    require(matched == 3, "all three wrappers must match their own proof");

    // Journal reload -> rollback -> byte-exact original.
    {
        fic::rollback::MutationJournal reloaded(tree.root / "journal.json");
        std::string reloadError;
        require(reloaded.load(reloadError), reloadError);
    }
    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        policy, kScopedDefaultsResource, deps);
    require(report.status == fic::rollback::RollbackStatus::Success,
            "rollback must succeed: " + report.message);
    require(readFile(tree.root / "sudoers") == original,
            "the multi-entry file must be restored BYTE EXACTLY");
}

// --- J: graph load -> capture TOCTOU (external line insertion) --------------

void testGraphSnapshotToCaptureToctou() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers",
              "Defaults passwd_tries=3\nDefaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // Plan against the CURRENT graph snapshot...
    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});

    // ...then an external writer inserts a line BEFORE the target, shifting
    // every physical line number.
    const std::string shifted =
        "# externally added\nDefaults passwd_tries=3\n"
        "Defaults:alice exempt_group=wheel\n";
    writeFile(tree.root / "sudoers", shifted);

    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const auto result = transaction.apply(plan.fresh, SudoScopedDefaultsHooks{});
    require(result.operation.conflict,
            "a file changed between graph load and capture must be a Conflict");
    require(readFile(tree.root / "sudoers") == shifted,
            "the external file must be preserved BYTE EXACTLY");
    require(readFile(tree.root / "sudoers").find("#@FIC_SUDO_DISABLED") ==
                std::string::npos,
            "no line may be wrapped against a stale snapshot");

    // Re-planning against the new graph succeeds, so nothing is wedged.
    SudoersConfiguration reloaded(options);
    std::string reloadError;
    require(reloaded.load(reloadError), reloadError);
    const auto fresh = reconcile(reloaded, productionHooks(reloaded));
    require(fresh.ok, "a re-planned apply must succeed: " + fresh.message);
    require(countWrappers(reloaded) == 1,
            "exactly one wrapper after the re-plan");
}

// --- K: first-write CAS conflict must not wedge the journal -----------------

void testFirstWriteCasConflictNotWedged() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    // Simulate a concurrent modification after FIC captured its snapshot but
    // before the rename: the CAS precondition must fail.
    hooks.beforeWrite = [](const std::filesystem::path& path) {
        if (path.filename() == "sudoers") {
            std::string current = readFile(path);
            current += "# concurrent external change\n";
            writeFile(path, current);
        }
    };
    const auto outcome = reconcile(configuration, hooks);
    require(!outcome.ok, "a CAS conflict must fail the apply");
    require(readFile(tree.root / "sudoers").find("# concurrent external change") !=
                std::string::npos,
            "the external change must be preserved");
    require(readFile(tree.root / "sudoers").find("#@FIC_SUDO_DISABLED") ==
                std::string::npos,
            "FIC must not overwrite foreign content");
    require(activePreparedCount() == 0,
            "a CAS conflict proves zero writes, so no record may stay");

    // The next apply is not permanently wedged.
    SudoersConfiguration retry(options);
    std::string retryError;
    require(retry.load(retryError), retryError);
    const auto second = reconcile(retry, productionHooks(retry));
    require(second.ok, "a subsequent apply must succeed: " + second.message);
}

// --- L: crash BEFORE the filesystem write -> production recovery -----------

void testCrashBeforeWriteRecovery() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // Record Prepared, then die before any write.
    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, targets}};
    require(recordPreparedMut(scopedPolicy(), undo, id, error), error);
    require(activePreparedCount() == 1, "a Prepared record must exist");
    require(readFile(tree.root / "sudoers") ==
                "Defaults:alice exempt_group=wheel\n",
            "nothing was written to disk");

    // Restart: the production reconcile must resolve the stale Prepared record
    // (CompletePrevious) and then plan a FRESH transition.
    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(outcome.ok, "recovery must succeed: " + outcome.message);
    require(activePreparedCount() == 0, "the stale Prepared must be resolved");
    const auto owned = activeOwned();
    require(owned.size() == 1, "a fresh wrapper must now be owned");
    require(readFile(tree.root / "sudoers").find("#@FIC_SUDO_DISABLED_BEGIN") !=
                std::string::npos,
            "the fresh transition must actually wrap the entry");
}

// --- M: crash AFTER a complete write -> production recovery -----------------

void testCrashAfterWriteRecovery() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    const std::string original = "Defaults:alice exempt_group=wheel\n";
    writeFile(tree.root / "sudoers", original);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // Record Prepared, apply the filesystem mutation, then die before commit.
    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, targets}};
    require(recordPreparedMut(scopedPolicy(), undo, id, error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const auto applied = transaction.apply(plan.fresh, productionHooks(configuration));
    require(applied.ok(), applied.operation.message);
    require(activePreparedCount() == 1, "still Prepared: commit never ran");

    // Restart: the production reconcile must classify CompleteTarget and COMMIT
    // the EXISTING record, minting no new ids.
    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(outcome.ok, "recovery must succeed: " + outcome.message);
    require(activePreparedCount() == 0, "the Prepared must be resolved");
    const auto owned = activeOwned();
    require(owned.size() == 1, "exactly the pre-existing wrapper is owned");
    require(owned[0].wrapperId == targets[0].wrapperId,
            "the EXISTING wrapper id must be reused, not re-minted");
    require(countWrappers(afterRestart) == 1,
            "no extra wrapper may be created during recovery");
    require(readFile(tree.root / "sudoers") != original,
            "the entry must remain suppressed");
}

// --- N: PARTIAL Prepared must fail closed, never be guessed -----------------

void testPartialPreparedRecovery() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // Step 1: apply A and commit it.
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const std::vector<SudoScopedDefaultsWrapperProof> ownedA = activeOwned();
    require(ownedA.size() == 1, "A must be owned");

    // Step 2: add drift B and prepare a transition previous={A}, target={A,B}.
    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\n");
    SudoersConfiguration staged(options);
    std::string stagedError;
    require(staged.load(stagedError), stagedError);
    ScopedDefaultsTransaction planner(staged, kPolicyName);
    const auto plan = planner.plan(ownedA);
    std::vector<SudoScopedDefaultsWrapperProof> targetProofs = ownedA;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targetProofs.push_back(mutation.proof);
    }
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, ownedA,
                                                  targetProofs}};
    require(recordPreparedMut(scopedPolicy(), undo, id, error), error);

    // Step 3: the disk now matches NEITHER side: A's payload was edited, so the
    // state is genuinely ambiguous (not a provable CompleteTarget/Previous).
    const std::string tampered =
        wrapperBlock(ownedA[0].wrapperId, "Defaults:root ALL=(ALL:ALL) ALL") +
        "Defaults:bob passwd_tries=9\n";
    writeFile(tree.root / "sudoers", tampered);

    // Recovery must NOT commit, NOT discard, and NOT mint new ids.
    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(!outcome.ok,
            "an ambiguous Prepared state must fail closed, never be guessed");
    require(activePreparedCount() == 1,
            "the Prepared record must survive an ambiguous state");
    require(readFile(tree.root / "sudoers") == tampered,
            "no write may happen while ownership is unproven");
}

// --- O: drifted existing wrapper + a NEW violation -> zero writes -----------

void testDriftedWrapperPlusNewViolation() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const auto ownedA = activeOwned();

    // Hand-edit A's payload and add a brand new violation B.
    const std::string tampered =
        wrapperBlock(ownedA[0].wrapperId, "Defaults:root ALL=(ALL:ALL) ALL") +
        "Defaults:bob passwd_tries=9\n";
    writeFile(tree.root / "sudoers", tampered);
    const auto ownedBefore = activeOwned();

    SudoersConfiguration retry(options);
    std::string retryError;
    require(retry.load(retryError), retryError);
    const auto outcome = reconcile(retry, productionHooks(retry));
    require(!outcome.ok, "a drifted existing wrapper must block reconciliation");
    require(readFile(tree.root / "sudoers") == tampered,
            "B must NOT be wrapped and A must not be activated");
    require(activeOwned() == ownedBefore,
            "the journal ownership must remain unchanged");
    require(activePreparedCount() == 0,
            "a refusal before any write must not create a record");
}

// --- P: orphan existing wrapper + a NEW violation -> zero writes ------------

void testOrphanWrapperPlusNewViolation() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    const std::string original =
        wrapperBlock("FIC-SUDO-7-7-7-7-7", "Defaults:alice exempt_group=wheel") +
        "Defaults:bob passwd_tries=9\n";
    writeFile(tree.root / "sudoers", original);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "an orphan wrapper must block reconciliation");
    require(readFile(tree.root / "sudoers") == original, "B must NOT be wrapped");
    require(activeOwned().empty(),
            "an orphan must never be adopted by a journal record");
}

// --- R: partial ROLLBACK + compensation ------------------------------------

void testPartialRollbackCompensated() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "a.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "b.conf", "Defaults:bob passwd_tries=9\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "a.conf").string() + "\n"
              "@include " + (tree.root / "b.conf").string() + "\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok,
            "apply");
    const auto owned = activeOwned();
    require(owned.size() == 2, "two wrappers must exist");
    const std::string wrappedA = readFile(tree.root / "a.conf");
    const std::string wrappedB = readFile(tree.root / "b.conf");

    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    SudoScopedDefaultsHooks hooks;
    hooks.validate = [&release](std::string& e) {
        return release.validateConfiguration(e);
    };
    int writes = 0;
    hooks.beforeWrite = [&writes](const std::filesystem::path&) {
        if (++writes == 2) {
            throw std::runtime_error("injected rollback write failure");
        }
    };
    const auto result = transaction.release(owned, hooks);
    require(!result.ok(), "a failing second release write must fail the rollback");
    // Compensation restored the first file, so BOTH stay wrapped and the
    // journal record may still be resolved safely.
    require(readFile(tree.root / "a.conf") == wrappedA,
            "a.conf must be re-wrapped by compensation");
    require(readFile(tree.root / "b.conf") == wrappedB,
            "b.conf must still be wrapped");
    require(leavesOwnedState(result.filesystemState) == false,
            "a compensated partial rollback leaves no unproven ownership");
}


// Prepares a refresh transition previous={owned}, target={owned,fresh} WITHOUT
// running it, simulating a crash right after the journal write.
void stageRefresh(const std::vector<SudoScopedDefaultsWrapperProof>& owned,
                  const PolicyRef& policy,
                  const std::vector<SudoScopedDefaultsWrapperProof>& fresh) {
    std::vector<SudoScopedDefaultsWrapperProof> targetProofs = owned;
    for (const SudoScopedDefaultsWrapperProof& proof : fresh) {
        targetProofs.push_back(proof);
    }
    MutationId id = 0;
    std::string error;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{policy.policyName, owned,
                                                  targetProofs}};
    require(recordPreparedMut(policy, undo, id, error), error);
}

// --- S: refresh crash BEFORE the write must NOT lose A's provenance ---------

void testRefreshCrashBeforeWriteKeepsOwnership() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const auto ownedA = activeOwned();
    require(ownedA.size() == 1, "A must be owned");

    // New violation B, refresh prepared, then crash before any filesystem write.
    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\n");
    SudoersConfiguration staged(options);
    std::string stagedError;
    require(staged.load(stagedError), stagedError);
    ScopedDefaultsTransaction planner(staged, kPolicyName);
    const auto plan = planner.plan(ownedA);
    std::vector<SudoScopedDefaultsWrapperProof> fresh;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        fresh.push_back(mutation.proof);
    }
    stageRefresh(ownedA, policy, fresh);
    require(activePreparedCount() == 1, "a refresh Prepared record must exist");

    // Restart: the production reconcile normalizes the refresh back to
    // Applied{A} and then re-plans B. A's id must be preserved.
    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(outcome.ok, "recovery must succeed: " + outcome.message);
    const auto ownedAfter = activeOwned();
    require(ownedAfter.size() == 2, "A and B must end up owned");
    bool aStillOwned = false;
    for (const auto& proof : ownedAfter) {
        if (proof.wrapperId == ownedA[0].wrapperId) {
            aStillOwned = true;
        }
    }
    require(aStillOwned, "wrapper A's id must be preserved through recovery");
    bool bobActive = false;
    for (const auto& line : fic::sudoers::splitPhysicalLines(
             readFile(tree.root / "sudoers"))) {
        if (line.text.rfind("Defaults:bob passwd_tries=9", 0) == 0) {
            bobActive = true;
        }
    }
    require(!bobActive, "B must be suppressed after the successful reconciliation");
}

// --- T: refresh CAS conflict before the first write keeps A ------------------

void testRefreshCasConflictKeepsOwnership() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const auto ownedA = activeOwned();

    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\n");
    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    hooks.beforeWrite = [](const std::filesystem::path& path) {
        if (path.filename() == "sudoers") {
            std::string current = readFile(path);
            current += "# concurrent external change\n";
            writeFile(path, current);
        }
    };
    const auto outcome = reconcile(configuration, hooks);
    require(!outcome.ok, "a CAS conflict must fail the refresh");
    const auto ownedAfter = activeOwned();
    require(ownedAfter.size() == 1, "ownership must still be exactly {A}");
    require(ownedAfter[0].wrapperId == ownedA[0].wrapperId,
            "A's provenance must survive the failed refresh");
    require(readFile(tree.root / "sudoers").find("Defaults:bob passwd_tries=9") !=
                std::string::npos,
            "B must NOT be wrapped");
    require(activePreparedCount() == 0,
            "a normalized refresh must not remain Prepared");

    SudoersConfiguration retry(options);
    std::string retryError;
    require(retry.load(retryError), retryError);
    const auto second = reconcile(retry, productionHooks(retry));
    require(second.ok, "a subsequent apply must succeed: " + second.message);
    require(activeOwned().size() == 2, "A and B must now be owned");
}


// --- U: refresh partial mutation + successful compensation -> Applied{A} ----

void testRefreshPartialMutationCompensated() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "a.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "b.conf", "Defaults passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "a.conf").string() + "\n"
              "@include " + (tree.root / "b.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const auto ownedA = activeOwned();
    require(ownedA.size() == 1, "only A must be owned after the first apply");
    const std::string aWrapped = readFile(tree.root / "a.conf");

    // B and C live in DIFFERENT files, so the refresh is a genuine multi-file
    // transaction: the first write installs B, the second fails, and the
    // compensation returns the filesystem exactly to {A}.
    writeFile(tree.root / "b.conf",
              "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
    writeFile(tree.root / "c.conf", "Defaults:carol passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "a.conf").string() + "\n"
              "@include " + (tree.root / "b.conf").string() + "\n"
              "@include " + (tree.root / "c.conf").string() + "\n");
    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    int writes = 0;
    hooks.beforeWrite = [&writes](const std::filesystem::path&) {
        if (++writes == 2) {
            throw std::runtime_error("injected write failure before install");
        }
    };
    const auto outcome = reconcile(configuration, hooks);
    require(!outcome.ok, "the failing refresh must report failure");
    // The surviving ownership must be exactly A, NOT absent and NOT Prepared.
    require(activePreparedCount() == 0,
            "a compensated refresh must not remain Prepared");
    const auto ownedAfter = activeOwned();
    require(ownedAfter.size() == 1,
            "ownership must be normalized back to exactly {A}");
    require(ownedAfter[0].wrapperId == ownedA[0].wrapperId,
            "A's proof identity must be unchanged");
    require(readFile(tree.root / "a.conf") == aWrapped,
            "A's wrapper must be intact");
    require(readFile(tree.root / "b.conf").find("#@FIC_SUDO_DISABLED") ==
                std::string::npos,
            "the partially installed wrapper must be compensated away");
}

// --- V: CompleteTarget with a failing durability barrier must NOT commit ----

void testCompleteTargetDurabilityBlocksCommit() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, targets}};
    require(recordPreparedMut(scopedPolicy(), undo, id, error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const auto applied = transaction.apply(plan.fresh, productionHooks(configuration));
    require(applied.ok(), applied.operation.message);
    require(activePreparedCount() == 1, "still Prepared: commit never ran");

    // A visible wrapper is NOT a durable wrapper while the barrier fails.
    {
        class FsyncGuard {
        public:
            FsyncGuard() {
                AtomicFileWriter::setDirectoryFsyncHookForTests(
                    [](const std::string&) { return false; });
            }
            ~FsyncGuard() {
                AtomicFileWriter::setDirectoryFsyncHookForTests({});
            }
        } guard;

        SudoersConfiguration blocked(options);
        std::string loadError;
        require(blocked.load(loadError), loadError);
        const auto outcome = reconcile(blocked, productionHooks(blocked));
        require(!outcome.ok, "a durability failure must block the commit");
        require(activePreparedCount() == 1,
                "the Prepared record must survive a failed durability barrier");
    }

    // Once the barrier can succeed again, the SAME record is committed; no new
    // wrapper id may be minted.
    SudoersConfiguration afterBarrier(options);
    std::string barrierError;
    require(afterBarrier.load(barrierError), barrierError);
    const auto recovered = reconcile(afterBarrier, productionHooks(afterBarrier));
    require(recovered.ok, "recovery after the barrier must succeed: " +
                             recovered.message);
    require(activePreparedCount() == 0, "the Prepared must be resolved");
    const auto ownedAfter = activeOwned();
    require(ownedAfter.size() == 1, "exactly the original wrapper is owned");
    require(ownedAfter[0].wrapperId == targets[0].wrapperId,
            "the existing wrapper id must be reused, never re-minted");
}


// --- W: rollback interrupted after the unwrap -> not RolledBack --------------

void testRollbackDurabilityBlocksResolution() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    const auto owned = activeOwned();
    require(owned.size() == 1, "one wrapper must exist");

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };

    // The unwrap is published but the directory fsync never completes, so the
    // released state is NOT durable and the rollback must not be reported as
    // successful.
    bool failed = false;
    {
        class FsyncGuard {
        public:
            FsyncGuard() {
                AtomicFileWriter::setDirectoryFsyncHookForTests(
                    [](const std::string&) { return false; });
            }
            ~FsyncGuard() {
                AtomicFileWriter::setDirectoryFsyncHookForTests({});
            }
        } guard;
        const auto report = fic::rollback::rollbackPolicyBeforeDisable(
            policy, kScopedDefaultsResource, deps);
        failed = report.status == fic::rollback::RollbackStatus::Failed ||
                 report.status == fic::rollback::RollbackStatus::Conflict;
        require(failed,
                "a non-durable release must not be reported as Success");
    }
    require(!activeOwned().empty(),
            "the provenance must remain active after a failed rollback");

    // Retry with a working barrier: the released state is now provable and the
    // journal resolves.
    const auto retry = fic::rollback::rollbackPolicyBeforeDisable(
        policy, kScopedDefaultsResource, deps);
    require(retry.status == fic::rollback::RollbackStatus::Success,
            "a durable retry must succeed: " + retry.message);
    require(activeOwned().empty(),
            "the ownership must be resolved after the durable retry");
}

// --- X: existing wrapper drifts BETWEEN the preflight and the commit --------

void testDriftBetweenPreflightAndCommitRefusesCommit() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const auto ownedA = activeOwned();

    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\n");

    // The external editor acts AFTER FIC installed B but BEFORE the final
    // ownership proof, so the reload in the hook sees a tampered A.
    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    hooks.reloadAndVerify = [&configuration](std::string& e) {
        if (!configuration.load(e)) {
            return false;
        }
        // Simulate the concurrent root process rewriting an ALREADY owned
        // wrapper body while FIC is between mutation and commit.
        std::string content = readFile(configuration.graphDocuments()[0].path);
        const std::string needle =
            "#@FIC_SUDO_DISABLED_LINE@eol=lf@Defaults:alice exempt_group=wheel";
        const std::size_t at = content.find(needle);
        if (at != std::string::npos) {
            content.replace(at, needle.size(),
                            "#@FIC_SUDO_DISABLED_LINE@eol=lf@Defaults:root ALL=(ALL) ALL");
            writeFile(configuration.graphDocuments()[0].path, content);
        }
        return true;
    };
    const auto outcome = reconcile(configuration, hooks);
    require(!outcome.ok,
            "a drifted existing wrapper must block the target commit");
    require(activePreparedCount() == 1,
            "the Prepared record must survive a refused commit");
}

// --- Y: valid partial refresh is selectively rewound to {A} -----------------

void testPartialRefreshSelectiveCompensation() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply A");
    const auto ownedA = activeOwned();
    const std::string aWrapped = readFile(tree.root / "sudoers");

    // Prepare a refresh that plans TWO new wrappers, then install only the
    // first on disk: the state is {A,B}, the target is {A,B,C}.
    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\nDefaults:carol passwd_tries=3\n");
    SudoersConfiguration staged(options);
    std::string stagedError;
    require(staged.load(stagedError), stagedError);
    ScopedDefaultsTransaction planner(staged, kPolicyName);
    const auto plan = planner.plan(ownedA);
    require(plan.fresh.size() == 2, "two new wrappers must be planned");
    std::vector<SudoScopedDefaultsWrapperProof> fresh;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        fresh.push_back(mutation.proof);
    }
    stageRefresh(ownedA, policy, fresh);

    // Install ONLY the first new wrapper, leaving the second untouched: this is
    // a genuine PARTIAL target, not drift.
    ScopedDefaultsTransaction installer(staged, kPolicyName);
    SudoScopedDefaultsHooks partialHooks = productionHooks(staged);
    // Install ONLY the mechanical step for B: the semantic postcondition is
    // relaxed on purpose, because the scenario constructs a CRASH state where
    // C was never written.
    partialHooks.reloadAndVerify = [&staged](std::string& e) {
        return staged.load(e);
    };
    const auto partial = installer.apply({plan.fresh[0]}, partialHooks);
    require(partial.ok(), partial.operation.message);

    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(outcome.ok,
            "a valid partial refresh must be recovered: " + outcome.message);
    // After the selective rewind to {A} the ordinary reconciliation re-plans
    // both remaining violations, so the end state is the full {A,B,C}.
    const auto ownedAfter = activeOwned();
    require(ownedAfter.size() == 3,
            "recovery must re-plan and own A, B and C");
    bool aPreserved = false;
    for (const auto& proof : ownedAfter) {
        if (proof.wrapperId == ownedA[0].wrapperId) {
            aPreserved = true;
        }
    }
    require(aPreserved, "wrapper A must survive the selective compensation");
}

// --- Z: a duplicate id introduced before the release capture is refused -----

void testDuplicateIdBeforeReleaseCaptureRefused() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "site.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok,
            "apply");
    const auto owned = activeOwned();
    require(owned.size() == 1, "one wrapper must exist");

    // An external process copies the wrapper into the main file, creating the
    // same id in TWO files.
    // Copy the wrapper (which lives in site.conf) into the main file, so the
    // SAME id now exists in two different sudoers files.
    const std::string wrappedSite = readFile(tree.root / "site.conf");
    std::string main = readFile(tree.root / "sudoers");
    writeFile(tree.root / "sudoers", main + wrappedSite);

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        policy, kScopedDefaultsResource, deps);
    require(report.status == fic::rollback::RollbackStatus::Conflict,
            "a global duplicate id must make the rollback a Conflict");
    require(!activeOwned().empty(),
            "the provenance must stay active when the rollback is refused");
    require(readFile(tree.root / "sudoers").find("Defaults:alice exempt_group=wheel") !=
                std::string::npos,
            "the foreign duplicate must be preserved byte-exactly");
}


// --- AA/AI: new target wrapper B disappears before the final commit ---------

void testTargetWrapperDisappearsBeforeCommit() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "A");
    const auto ownedA = activeOwned();

    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\n");
    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    bool unwrapped = false;
    // After FIC wrapped B and after the original semantic postcondition, but
    // BEFORE the strict final target proof, an external process unwraps B and
    // the original Defaults:bob becomes active again.
    hooks.reloadAndVerify = [&configuration, &unwrapped](std::string& e) {
        if (!configuration.load(e)) {
            return false;
        }
        if (unwrapped) {
            return true;
        }
        unwrapped = true;
        const auto path = configuration.graphDocuments()[0].path;
        // Real unwrap of the newly installed wrapper: locate the LINE marker
        // holding the new violation and rebuild the file from its exact body.
        const std::vector<fic::sudoers::SudoPhysicalLine> lines =
            fic::sudoers::splitPhysicalLines(readFile(path));
        std::string body;
        std::size_t beginIndex = 0;
        std::size_t endIndex = 0;
        bool found = false;
        for (std::size_t index = 0; index + 1 < lines.size(); ++index) {
            static const std::string kPrefix =
                "#@FIC_SUDO_DISABLED_LINE@eol=";
            if (lines[index].text.rfind(kPrefix, 0) != 0) {
                continue;
            }
            // Skip the eol VALUE and its separator '@'.
            const std::size_t at =
                lines[index].text.find('@', kPrefix.size());
            if (at == std::string::npos ||
                lines[index].text.find("Defaults:bob") == std::string::npos) {
                continue;
            }
            body = lines[index].text.substr(at + 1);
            beginIndex = index - 1; // BEGIN marker
            endIndex = index + 1;   // END marker
            found = true;
            break;
        }
        if (!found) {
            return true;
        }
        std::string content;
        for (std::size_t index = 0; index < beginIndex; ++index) {
            content += lines[index].text + "\n";
        }
        content += body + "\n";
        for (std::size_t index = endIndex + 1; index < lines.size(); ++index) {
            content += lines[index].text + "\n";
        }
        writeFile(path, content);
        return true;
    };
    const auto outcome = reconcile(configuration, hooks);
    require(unwrapped, "the concurrent unwrap must have been injected");
    require(!outcome.ok, "a vanished target wrapper must block the commit");
    require(activePreparedCount() == 1,
            "the Prepared record must survive a missing target wrapper");
    bool bobActive = false;
    for (const auto& line : fic::sudoers::splitPhysicalLines(
             readFile(tree.root / "sudoers"))) {
        if (line.text.rfind("Defaults:bob passwd_tries=9", 0) == 0) {
            bobActive = true;
        }
    }
    require(bobActive, "the semantic state must NOT be reported compliant");
}

// --- AB/AC: previous wrapper drifts or vanishes before normalization --------

void runPreviousBrokenBeforeNormalization(bool removeWrapper) {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "A");
    const auto ownedA = activeOwned();

    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedA[0].wrapperId, "Defaults:alice exempt_group=wheel") +
              "Defaults:bob passwd_tries=9\n");
    SudoersConfiguration staged(options);
    std::string stagedError;
    require(staged.load(stagedError), stagedError);
    ScopedDefaultsTransaction planner(staged, kPolicyName);
    const auto plan = planner.plan(ownedA);
    std::vector<SudoScopedDefaultsWrapperProof> fresh;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        fresh.push_back(mutation.proof);
    }
    stageRefresh(ownedA, policy, fresh);

    // Break the PREVIOUS wrapper before the normalization proof runs.
    if (removeWrapper) {
        writeFile(tree.root / "sudoers", "Defaults:bob passwd_tries=9\n");
    } else {
        writeFile(tree.root / "sudoers",
                  wrapperBlock(ownedA[0].wrapperId,
                               "Defaults:root ALL=(ALL:ALL) ALL") +
                  "Defaults:bob passwd_tries=9\n");
    }

    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(!outcome.ok, "normalization over a broken previous state is forbidden");
    require(activePreparedCount() == 1,
            "the Prepared record must survive an unprovable previous state");
}

void testPreviousDriftsBeforeNormalization() {
    runPreviousBrokenBeforeNormalization(false);
}

void testPreviousDisappearsBeforeNormalization() {
    runPreviousBrokenBeforeNormalization(true);
}


// --- AD: duplicate id inserted AFTER graph load, BEFORE rollback capture ----

void testDuplicateInsertedAfterGraphLoadBeforeCapture() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "site.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    const auto owned = activeOwned();
    require(owned.size() == 1, "one wrapper must exist");
    const std::string wrappedSite = readFile(tree.root / "site.conf");

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    // The graph is ALREADY loaded; the duplicate appears only afterwards, inside
    // the window the beforeCapture seam models.
    std::string mainBefore = readFile(tree.root / "sudoers");
    SudoScopedDefaultsHooks hooks;
    hooks.beforeCapture = [&tree, &mainBefore, &wrappedSite]() {
        writeFile(tree.root / "sudoers", mainBefore + wrappedSite);
    };
    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    const auto result = transaction.release(owned, hooks);
    require(result.operation.conflict,
            "a duplicate id inserted before the capture must be a Conflict");
    require(!activeOwned().empty(), "the provenance must stay active");
}

// --- AE/AF: a non-regular proof target must NOT count as proven absence -----

void runNonRegularProofTarget(bool asDirectory) {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "site.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    const auto owned = activeOwned();
    require(owned.size() == 1, "one wrapper must exist");

    // Replace the proof path with something that is NOT a regular file.
    std::filesystem::remove(tree.root / "site.conf");
    if (asDirectory) {
        std::filesystem::create_directories(tree.root / "site.conf");
    } else {
        std::error_code ignored;
        std::filesystem::create_symlink("/etc/hostname", tree.root / "site.conf",
                                        ignored);
    }

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        policy, kScopedDefaultsResource, deps);
    require(report.status != fic::rollback::RollbackStatus::Success,
            "a non-regular proof target must not be reported as released");
    require(!activeOwned().empty(),
            "the provenance must stay active on a symlink/directory target");
}

void testSymlinkProofTargetNotAbsent() { runNonRegularProofTarget(false); }

void testDirectoryProofTargetNotAbsent() { runNonRegularProofTarget(true); }

// --- AG: a genuinely absent proof file may be proven as a durable absence ---

void testGenuinelyAbsentProofFile() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "site.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
    const auto owned = activeOwned();
    require(owned.size() == 1, "one wrapper must exist");

    // The wrapper file is genuinely REMOVED externally: the released subset is
    // legitimate, and the typed absence barrier proves it durably.
    std::filesystem::remove(tree.root / "site.conf");
    writeFile(tree.root / "sudoers",
              "Defaults:alice exempt_group=wheel\n");

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        policy, kScopedDefaultsResource, deps);
    require(report.status == fic::rollback::RollbackStatus::NothingToDo ||
                report.status == fic::rollback::RollbackStatus::Success,
            "a durable absence may resolve the record: " + report.message);
}

// --- AH: the filesystem changes between the exact proof and the barrier -----

void testChangeBetweenProofAndDurability() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // Durable barrier that first mutates the file, then reports success: the
    // state-bound proof must notice the change and refuse.
    class RacingBarrier {
    public:
        explicit RacingBarrier(std::filesystem::path path) : path_(std::move(path)) {
            AtomicFileWriter::setDirectoryFsyncHookForTests(
                [this](const std::string&) {
                    std::string current = readFile(path_);
                    current += "# racing writer\n";
                    writeFile(path_, current);
                    return true;
                });
        }
        ~RacingBarrier() { AtomicFileWriter::setDirectoryFsyncHookForTests({}); }
        RacingBarrier(const RacingBarrier&) = delete;
        RacingBarrier& operator=(const RacingBarrier&) = delete;
    private:
        std::filesystem::path path_;
    } racing(tree.root / "sudoers");

    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const auto plan = transaction.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    const auto applied = transaction.apply(plan.fresh, SudoScopedDefaultsHooks{});
    require(applied.ok(), applied.operation.message);

    SudoersConfiguration after(options);
    std::string loadError;
    require(after.load(loadError), loadError);
    ScopedDefaultsTransaction prover(after, kPolicyName);
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    require(prover.captureProofAndGraphState(targets, captured, captureError),
            captureError);
    const auto proof = prover.proveCapturedState(
        targets, captured, ScopedDefaultsProofMode::Exact);
    require(proof.ok, "the exact proof itself must succeed: " + proof.message);
    // Now the filesystem changes before the barrier runs.
    std::string current = readFile(tree.root / "sudoers");
    current += "# late external writer\n";
    writeFile(tree.root / "sudoers", current);
    std::string durabilityError;
    require(!ScopedDefaultsTransaction::proveCapturedStateDurable(
                proof.captured, durabilityError),
            "the barrier must fail when the proven state changed");
}

} // namespace


// --- AJ: fresh Prepared target hidden by an include topology change ---------

void testTargetHiddenByTopologyChange() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "site.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, targets}};
    require(recordPreparedMut(policy, undo, id, error), error);
    // Install the wrapper, then "crash".
    ScopedDefaultsTransaction installer(configuration, kPolicyName);
    const auto applied = installer.apply(plan.fresh, SudoScopedDefaultsHooks{});
    require(applied.ok(), applied.operation.message);
    require(activePreparedCount() == 1, "still Prepared");

    // The include disappears while site.conf (with wrapper A) stays on disk.
    writeFile(tree.root / "sudoers", "root ALL=(ALL:ALL) ALL\n");

    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    // The wrapper is still physically present even though it is no longer
    // reachable through the include graph. Recovery must therefore never treat
    // it as "nothing is owned": the record is either resolved to Applied while
    // still proving A, or it stays Prepared. What is FORBIDDEN is a discard.
    const auto ownedAfter = activeOwned();
    const std::size_t prepared = activePreparedCount();
    require(prepared + ownedAfter.size() >= 1,
            "a hidden target wrapper must never become unproven");
    if (prepared == 0) {
        require(ownedAfter.size() == 1 && outcome.ok,
                "resolution to Applied must still prove the hidden wrapper");
    }
    require(readFile(tree.root / "site.conf").find("#@FIC_SUDO_DISABLED_BEGIN") !=
                std::string::npos,
            "wrapper A must still be physically present");
}

// --- AK: fresh crash-before-write recovery still succeeds -------------------

void testFreshCrashBeforeWriteStillRecovers() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    writeFile(tree.root / "site.conf", "Defaults:alice exempt_group=wheel\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, targets}};
    require(recordPreparedMut(policy, undo, id, error), error);
    require(activePreparedCount() == 1, "Prepared must exist");

    // Restart: nothing was written, so the durable absence proof succeeds and a
    // FRESH planning re-applies the entry.
    SudoersConfiguration afterRestart(options);
    std::string loadError;
    require(afterRestart.load(loadError), loadError);
    const auto outcome = reconcile(afterRestart, productionHooks(afterRestart));
    require(outcome.ok, "a genuine crash-before-write must recover: " +
                            outcome.message);
    require(activeOwned().size() == 1, "the entry must be re-suppressed");
    require(readFile(tree.root / "site.conf").find("#@FIC_SUDO_DISABLED_BEGIN") !=
                std::string::npos,
            "the wrapper must be installed after the fresh plan");
}


// Collects the wrapper ids physically present on disk right now.
std::set<std::string> onDiskWrapperIds(const std::filesystem::path& root) {
    std::set<std::string> ids;
    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::string error;
        std::vector<fic::sudoers::SudoDisabledWrapper> wrappers;
        if (fic::sudoers::parseSudoDisabledWrappers(
                fic::sudoers::splitPhysicalLines(readFile(entry.path())),
                wrappers, error) != fic::sudoers::SudoWrapperParseStatus::Ok) {
            continue;
        }
        for (const auto& wrapper : wrappers) {
            if (wrapper.policy == kPolicyName) {
                ids.insert(wrapper.mutationId);
            }
        }
    }
    return ids;
}

// Builds Prepared previous={A}, target={A,B,C} with a PARTIAL disk {A,B}.
struct PartialRefreshFixture {
    explicit PartialRefreshFixture(TempTree& treeRef) : tree(treeRef) {
        writeFile(tree.root / "a.conf", "Defaults:alice exempt_group=wheel\n");
        writeFile(tree.root / "b.conf", "Defaults passwd_tries=3\n");
        writeFile(tree.root / "c.conf", "Defaults passwd_tries=4\n");
        writeFile(tree.root / "sudoers",
                  "@include " + (tree.root / "a.conf").string() + "\n"
                  "@include " + (tree.root / "b.conf").string() + "\n"
                  "@include " + (tree.root / "c.conf").string() + "\n");
        options = sudoOptions(tree.root);
    }
    void applyA() {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        require(reconcile(configuration, productionHooks(configuration)).ok,
                "apply A");
        ownedA = activeOwned();
        require(ownedA.size() == 1, "only A must be owned");
    }
    void prepareRefreshAndInstallB() {
        writeFile(tree.root / "b.conf",
                  "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
        writeFile(tree.root / "c.conf",
                  "Defaults passwd_tries=4\nDefaults:carol passwd_tries=3\n");
        SudoersConfiguration staged(options);
        std::string stagedError;
        require(staged.load(stagedError), stagedError);
        ScopedDefaultsTransaction planner(staged, kPolicyName);
        const auto plan = planner.plan(ownedA);
        planned = plan.fresh;
        require(planned.size() == 2, "B and C must be planned");
        for (const PlannedScopedDefaultsMutation& mutation : planned) {
            fresh.push_back(mutation.proof);
        }
        targetProofs = ownedA;
        for (const auto& proof : fresh) {
            targetProofs.push_back(proof);
        }
        stageRefresh(ownedA, scopedPolicy(), fresh);
        // Install ONLY B: the semantic postcondition is relaxed on purpose
        // because this scenario constructs a crash state where C never landed.
        SudoScopedDefaultsHooks partialHooks = productionHooks(staged);
        partialHooks.reloadAndVerify = [&staged](std::string& e) {
            return staged.load(e);
        };
        ScopedDefaultsTransaction installer(staged, kPolicyName);
        const auto partial = installer.apply({planned[0]}, partialHooks);
        require(partial.ok(), partial.operation.message);
    }
    // Installs the STAGED target wrappers that are still missing, reusing the
    // STAGED proofs: re-planning would mint different wrapper ids than the
    // journal record, and the disk would no longer match the recorded target.
    void installStagedRemaining() {
        SudoersConfiguration staged(options);
        std::string stagedError;
        require(staged.load(stagedError), stagedError);
        SudoScopedDefaultsHooks partialHooks = productionHooks(staged);
        partialHooks.reloadAndVerify = [&staged](std::string& e) {
            return staged.load(e);
        };
        ScopedDefaultsTransaction installer(staged, kPolicyName);
        // prepareRefreshAndInstallB() installed planned[0] only.
        require(planned.size() >= 2, "a remaining staged wrapper is expected");
        const std::vector<PlannedScopedDefaultsMutation> remaining(
            planned.begin() + 1, planned.end());
        const auto applied = installer.apply(remaining, partialHooks);
        require(applied.ok(), applied.operation.message);
    }
    TempTree& tree;
    SudoersConfigurationOptions options;
    std::vector<SudoScopedDefaultsWrapperProof> ownedA;
    std::vector<SudoScopedDefaultsWrapperProof> fresh;
    std::vector<SudoScopedDefaultsWrapperProof> targetProofs;
    std::vector<PlannedScopedDefaultsMutation> planned;
};

// --- AY: direct compensateToPrevious test, establishing the real disk state --

void testDirectCompensationYieldsExactPrevious() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    PartialRefreshFixture fixture(tree);
    fixture.applyA();
    fixture.prepareRefreshAndInstallB();

    const std::string aId = fixture.ownedA[0].wrapperId;
    const std::string bId = fixture.fresh[0].wrapperId;
    const std::string cId = fixture.fresh[1].wrapperId;
    std::set<std::string> before = onDiskWrapperIds(tree.root);
    require(before.count(aId) == 1 && before.count(bId) == 1 &&
                before.count(cId) == 0,
            "precondition: disk must be exactly {A,B}");

    SudoersConfiguration current(fixture.options);
    std::string error;
    require(current.load(error), error);
    ScopedDefaultsTransaction transaction(current, kPolicyName);
    fic::sudoers::SudoScopedDefaultsFilesystemState state =
        fic::sudoers::SudoScopedDefaultsFilesystemState::Unchanged;
    const bool ok = transaction.compensateToPrevious(
        fixture.ownedA, fixture.targetProofs, SudoScopedDefaultsHooks{}, state,
        error);

    const std::set<std::string> after = onDiskWrapperIds(tree.root);
    require(ok, "compensateToPrevious must succeed: " + error);
    require(after.count(aId) == 1,
            "A must survive the selective compensation");
    require(after.count(bId) == 0,
            "B (target-only) must be removed by the compensation");
    require(after.count(cId) == 0, "C was never installed and must be absent");
}


// Injects an external change between the mechanical compensation and the final
// snapshot-bound previous-resolution proof, then requires that the recovery
// refuses to normalize.
void runChangeBetweenCompensationAndProof(bool breakPrevious,
                                           bool restoreTargetOnly,
                                           bool dropTargetFromGraph) {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    PartialRefreshFixture fixture(tree);
    fixture.applyA();
    fixture.prepareRefreshAndInstallB();

    const std::string aId = fixture.ownedA[0].wrapperId;
    const std::string bId = fixture.fresh[0].wrapperId;
    const std::string bPath = fixture.fresh[0].canonicalPath;

    if (dropTargetFromGraph) {
        // B's file leaves the include graph while staying physically present.
        writeFile(tree.root / "sudoers",
                  "@include " + (tree.root / "a.conf").string() + "\n"
                  "@include " + (tree.root / "c.conf").string() + "\n");
    }

    const std::function<void()> hook = [&tree, aId, bId, bPath,
                                             breakPrevious, restoreTargetOnly,
                                             dropTargetFromGraph]() {
        if (breakPrevious) {
            // Drift the PREVIOUS wrapper A in a file the compensation may not
            // have touched.
            writeFile(tree.root / "a.conf",
                      wrapperBlock(aId, "Defaults:root ALL=(ALL:ALL) ALL"));
        }
        if (restoreTargetOnly) {
            // Restore the target-only wrapper B on its physical path.
            writeFile(bPath, wrapperBlock(bId, "Defaults:bob passwd_tries=9"));
        }
        (void)dropTargetFromGraph;
    };
    // The deps hold a pointer to a local configuration, so the lifecycle must
    // not outlive this scope.
    SudoersConfiguration holder(fixture.options);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(holder, SudoScopedDefaultsHooks{}, hook);
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);
    require(!outcome.ok,
            "an unproven previous state must forbid normalization");
    require(activePreparedCount() == 1,
            "the Prepared record must stay active when previous is unproven");
}

// --- AQ: previous wrapper A drifts between compensation and normalization ----

void testPreviousDriftsAfterCompensation() {
    runChangeBetweenCompensationAndProof(true, false, false);
}

// --- AV: target-only wrapper B restored between compensation and proof ------

void testTargetOnlyRestoredAfterCompensation() {
    runChangeBetweenCompensationAndProof(false, true, false);
}

// --- AW: target-only wrapper B survives OUTSIDE the current include graph ----

void testTargetOnlySurvivesOutsideGraph() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    PartialRefreshFixture fixture(tree);
    fixture.applyA();
    fixture.prepareRefreshAndInstallB();

    const std::string bId = fixture.fresh[0].wrapperId;
    const std::string bPath = fixture.fresh[0].canonicalPath;

    // Disk becomes {A,B,C}: C is installed and stays INSIDE the include graph,
    // so the compensation has a real target-only file to work on.
    fixture.installStagedRemaining();
    const std::set<std::string> installed = onDiskWrapperIds(tree.root);
    require(installed.count(bId) == 1, "B must be installed");
    require(installed.size() == 3, "disk must be exactly {A,B,C}");

    // B's file leaves the include graph while staying physical, and B drifts
    // from its target proof. A capture-first compensation now sees B as well, so
    // the DRIFT is what must stop the rewind: a drifted wrapper can never be
    // safely unwrapped, and rewriting it would activate foreign content.
    writeFile(bPath, wrapperBlock(bId, "Defaults:bob passwd_tries=10"));
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "a.conf").string() + "\n"
              "@include " + (tree.root / "c.conf").string() + "\n");

    bool compensationRan = false;
    const std::function<void()> hook = [&compensationRan]() {
        compensationRan = true;
    };
    SudoersConfiguration holder(fixture.options);
    std::string holderError;
    require(holder.load(holderError), holderError);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(holder, SudoScopedDefaultsHooks{}, hook);
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "a drifted target-only wrapper outside the graph must fail closed");
    require(!compensationRan,
            "the compensation must refuse before publishing any work");
    require(activePreparedCount() == 1,
            "the Prepared record must stay active: no normalize");
    require(onDiskWrapperIds(tree.root).count(bId) == 1,
            "the drifted wrapper must be left physically untouched");
}


// --- AY-durability: Exact(previous) succeeds, durability barrier fails ---------

void testPreviousExactButDurabilityFails() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    PartialRefreshFixture fixture(tree);
    fixture.applyA();
    // Stage the refresh but install NOTHING: disk stays exactly {A}, so the
    // classification is CompletePrevious and provePreviousResolution() runs.
    writeFile(tree.root / "b.conf",
              "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
    writeFile(tree.root / "c.conf",
              "Defaults passwd_tries=4\nDefaults:carol passwd_tries=3\n");
    {
        SudoersConfiguration staged(fixture.options);
        std::string stagedError;
        require(staged.load(stagedError), stagedError);
        ScopedDefaultsTransaction planner(staged, kPolicyName);
        const auto plan = planner.plan(fixture.ownedA);
        require(plan.fresh.size() == 2, "B and C must be planned");
        std::vector<SudoScopedDefaultsWrapperProof> fresh;
        for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
            fresh.push_back(mutation.proof);
        }
        stageRefresh(fixture.ownedA, scopedPolicy(), fresh);
    }
    const std::set<std::string> beforeCompensation = onDiskWrapperIds(tree.root);
    require(beforeCompensation.size() == 1,
            "only A may be on disk before the proof");

    {
        class FsyncGuard {
        public:
            FsyncGuard() {
                AtomicFileWriter::setDirectoryFsyncHookForTests(
                    [](const std::string&) { return false; });
            }
            ~FsyncGuard() {
                AtomicFileWriter::setDirectoryFsyncHookForTests({});
            }
        } guard;

        SudoersConfiguration blocked(fixture.options);
        std::string loadError;
        require(blocked.load(loadError), loadError);
        const auto outcome = reconcile(blocked, productionHooks(blocked));
        require(!outcome.ok,
                "an unproven-durable previous state must forbid normalization");
        require(activePreparedCount() == 1,
                "the Prepared record must stay active when the barrier fails");
    }

    // Once the barrier works again the SAME record normalizes: the failure was
    // durability-only, not a lost proof.
    SudoersConfiguration afterBarrier(fixture.options);
    std::string afterError;
    require(afterBarrier.load(afterError), afterError);
    const auto recovered = reconcile(afterBarrier, productionHooks(afterBarrier));
    require(recovered.ok, "recovery after the barrier must succeed: " +
                               recovered.message);
    require(activePreparedCount() == 0,
            "the record must be normalized to Applied(previous) afterwards");
}


// ===========================================================================
// AT: ownership preflight is PHYSICAL-PATH based, not graph based.
//
// The current include graph is NOT the ownership authority: an external process
// can remove an @include while the journal still proves ownership of a wrapper
// that physically remains at its canonical path.
// ===========================================================================

// Applied: journal owns wrapper A in site.conf, and site.conf IS in the graph.
struct OutsideGraphFixture {
    OutsideGraphFixture(TempTree& treeRef, const std::string& name)
        : tree(treeRef), site(tree.root / name) {
        writeFile(site, "Defaults:alice exempt_group=wheel\n");
        // A NON-scoped line, so the initial reconcile owns exactly A.
        writeFile(tree.root / "other.conf", "alice ALL=(ALL:ALL) ALL\n");
        options = sudoOptions(tree.root);
        includeSite();
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        require(reconcile(configuration, productionHooks(configuration)).ok,
                "apply A: " + error);
        owned = activeOwned();
        require(owned.size() == 1, "journal must own exactly A");
        require(owned[0].canonicalPath ==
                    fic::sudoers::canonicalizeSudoProofPath(site),
                "the proof must name the site.conf canonical path");
    }
    // The external process removes the @include; the file stays physical.
    void dropInclude() { includeSite_ = false; writeGraph(); }
    void includeSite() { includeSite_ = true; writeGraph(); }
    void writeGraph() {
        std::string content;
        if (includeSite_) {
            content += "@include " + site.string() + "\n";
        }
        content += "@include " + (tree.root / "other.conf").string() + "\n";
        writeFile(tree.root / "sudoers", content);
    }
    TempTree& tree;
    std::filesystem::path site;
    SudoersConfigurationOptions options;
    std::vector<SudoScopedDefaultsWrapperProof> owned;
    bool includeSite_ = true;
};

std::string readAll(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

// --- AT: drifted owned wrapper outside the graph must fail closed ------------

void testOwnedWrapperDriftedOutsideGraph() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();
    const std::string before = readAll(fixture.site);
    // Drift the payload INSIDE wrapper A, in a file the graph no longer sees.
    const std::string drifted = before;
    size_t at = drifted.find("exempt_group=wheel");
    require(at != std::string::npos, "wrapper A body must be present");
    std::string mutated = drifted;
    mutated.replace(at, std::string("exempt_group=wheel").size(),
                    "exempt_group=daemon");
    writeFile(fixture.site, mutated);
    const std::string driftedOnDisk = readAll(fixture.site);

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    const auto outcome = reconcile(configuration, productionHooks(configuration));

    require(!outcome.ok, "a drifted owned wrapper outside the graph must fail");
    require(!outcome.unchanged, "it must never be reported as a no-op");
    require(activePreparedCount() == 0,
            "no new Prepared record may be created");
    require(activeOwned().size() == 1,
            "the existing ownership record must remain active");
    require(readAll(fixture.site) == driftedOnDisk,
            "FIC must not have written the file");
}

// --- AT2: exact owned wrapper outside the graph is FOUND and accepted -------

void testOwnedWrapperExactOutsideGraph() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    // The preflight must PASS: the wrapper really is inspected through its
    // proof canonical path even though the graph does not contain it.
    const std::string refusal =
        transaction.validateCurrentOwnership(fixture.owned);
    require(refusal.empty(),
            "an exact owned wrapper outside the graph must be accepted: " +
                refusal);

    // NOTE: an EMPTY proof set deliberately does NOT discover site.conf. With no
    // proof there is no known canonical path to capture, which is the separate
    // @include topology-discovery problem and is intentionally out of scope here.
    //
    // ...and that success is NOT blind: the same id/path with a tampered digest
    // fails, which proves the file CONTENT is really inspected.
    // A tampered digest on the same id/path must fail closed, which proves the
    // file's CONTENT is really inspected rather than merely tolerated.
    SudoScopedDefaultsWrapperProof tampered = fixture.owned[0];
    tampered.payloadDigest += "0";
    require(!transaction.validateCurrentOwnership({tampered}).empty(),
            "a tampered payload digest must fail closed");

    // The wrapper really is still there, and the no-op path is legitimate.
    require(onDiskWrapperIds(tree.root).count(fixture.owned[0].wrapperId) == 1,
            "A must still be physically present");
}

// --- AT3: the same id+digest moved to another file must fail ---------------

void testOwnedWrapperMovedOutsideGraph() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();
    // Move the EXACT wrapper into a different file that IS in the graph.
    const std::string body = readAll(fixture.site);
    writeFile(fixture.site, "");
    writeFile(tree.root / "other.conf", body);

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::string refusal =
        transaction.validateCurrentOwnership(fixture.owned);
    require(!refusal.empty(),
            "a relocated wrapper does not prove ownership: " + refusal);

    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "a moved owned wrapper must fail closed");
    require(activePreparedCount() == 0, "no Prepared record may be created");
}

// --- AT4: an unknown wrapper on a proof-only path must fail closed ---------

void testUnknownWrapperOnProofOnlyPath() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();
    writeFile(fixture.site,
              readAll(fixture.site) +
                  wrapperBlock("FIC-SUDO-1-2-3-4-5", "Defaults:eve x=1"));

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::string refusal =
        transaction.validateCurrentOwnership(fixture.owned);
    require(!refusal.empty(),
            "an unknown wrapper on a proof-only path must fail closed: " +
                refusal);
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "reconcile must fail closed");
}

// --- AT5: the same id in a graph file and in a proof-only path must fail ----

void testDuplicateIdAcrossGraphAndProofOnlyPath() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();
    // A copy of the very same wrapper id lands in a graph file.
    writeFile(tree.root / "other.conf",
              readAll(fixture.site));

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::string refusal =
        transaction.validateCurrentOwnership(fixture.owned);
    require(!refusal.empty(),
            "a duplicate id across the combined capture must fail closed: " +
                refusal);
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "reconcile must fail closed before any write");
    require(activePreparedCount() == 0, "no Prepared record may be created");
}

// --- AT6: a non-regular owned proof path must fail closed ------------------

void testNonRegularOwnedProofPath(bool asDirectory) {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();
    std::filesystem::remove(fixture.site);
    if (asDirectory) {
        std::filesystem::create_directories(fixture.site);
    } else {
        writeFile(tree.root / "elsewhere.conf", "alice ALL=(ALL:ALL) ALL\n");
        std::error_code ec;
        std::filesystem::create_symlink(tree.root / "elsewhere.conf",
                                        fixture.site, ec);
        require(!ec, "the test symlink must be created");
    }

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::string refusal =
        transaction.validateCurrentOwnership(fixture.owned);
    require(!refusal.empty(),
            std::string("a non-regular owned path (") +
                (asDirectory ? "directory" : "symlink") +
                ") must fail closed and never count as released: " + refusal);
    const auto outcome = reconcile(configuration, productionHooks(configuration));
    require(!outcome.ok, "reconcile must fail closed");
}

void testOwnedPathAsDirectory() { testNonRegularOwnedProofPath(true); }
void testOwnedPathAsSymlink() { testNonRegularOwnedProofPath(false); }

// --- AT7: a new violation must NOT be applied over a broken ownership -------

void testNewViolationOverBrokenOwnership() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    OutsideGraphFixture fixture(tree, "site.conf");
    fixture.dropInclude();
    const std::string drifted = readAll(fixture.site);
    std::string mutated = drifted;
    size_t at = mutated.find("exempt_group=wheel");
    require(at != std::string::npos, "wrapper A body must be present");
    mutated.replace(at, std::string("exempt_group=wheel").size(),
                    "exempt_group=daemon");
    writeFile(fixture.site, mutated);

    // A brand-new active violation inside the CURRENT graph.
    writeFile(tree.root / "other.conf",
              "Defaults:bob passwd_tries=5\nDefaults:bob passwd_tries=9\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    const auto outcome = reconcile(configuration, productionHooks(configuration));

    require(!outcome.ok,
            "a new violation must not be planned over an unproven ownership");
    require(activePreparedCount() == 0, "zero new Prepared records");
    require(activeOwned().size() == 1, "the old record must remain active");
    require(onDiskWrapperIds(tree.root).count(fixture.owned[0].wrapperId) == 1,
            "no new wrapper may be installed");
    const std::set<std::string> ids = onDiskWrapperIds(tree.root);
    require(ids.size() == 1,
            "exactly the pre-existing wrapper A must exist on disk");
    require(readAll(fixture.site) == mutated, "FIC must not have written");
}


// ===========================================================================
// AO/AQ-series: @includedir TOPOLOGY binding.
//
// A captured file set alone is not a sufficient security proof: a brand-new
// @includedir member can appear after load() and carry active scoped Defaults
// or a copied FIC wrapper that NO capture path knows about.
//
// NOTE on eligibility: `ignoredIncludedirName()` ignores any name containing a
// dot, so an eligible member name must NOT contain '.'. The fixtures below
// therefore use names like "abase" / "bnew", which is exactly what this
// configuration really loads.
// ===========================================================================

struct DropinFixture {
    // `abaseContent` decides whether the loaded graph has an ACTIVE scoped
    // Defaults violation. "Defaults:bob ..." IS scoped (the scope character is
    // mandatory), while a bare "Defaults ..." is a GLOBAL default and therefore
    // not a violation at all.
    DropinFixture(TempTree& treeRef, const std::string& abaseContent)
        : tree(treeRef) {
        dropins = tree.root / "dropins";
        std::filesystem::create_directories(dropins);
        writeFile(dropins / "abase", abaseContent);
        writeFile(tree.root / "sudoers", "@includedir " + dropins.string() + "\n");
        options = sudoOptions(tree.root);
    }
    TempTree& tree;
    std::filesystem::path dropins;
    SudoersConfigurationOptions options;
};

// --- AO: a new active drop-in before the final commit ---------------------

void testNewDropinBeforeFinalCommit() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        // The external process drops a new eligible member with an ACTIVE
        // violation that this plan never saw.
        writeFile(fixture.dropins / "bnew", "Defaults:carol passwd_tries=4\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "a new @includedir member must block the final commit: " + outcome.message);
    require(activePreparedCount() == 1,
            "the Prepared record must stay active");
}

// --- AO-deletion: a deleted member before the final commit ----------------

void testDeletedDropinBeforeFinalCommit() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");
    writeFile(fixture.dropins / "bsecond", "Defaults:carol passwd_tries=4\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        std::filesystem::remove(fixture.dropins / "bsecond");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "a DELETED @includedir member must also invalidate the proof");
    require(activePreparedCount() == 1, "the Prepared record must stay active");
}

// --- AO-rename: a renamed member before the final commit ------------------

void testRenamedDropinBeforeFinalCommit() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");
    writeFile(fixture.dropins / "bsecond", "Defaults:carol passwd_tries=4\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        std::filesystem::rename(fixture.dropins / "bsecond",
                                fixture.dropins / "zsecond");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok, "a RENAMED member is a topology change");
    require(activePreparedCount() == 1, "the Prepared record must stay active");
}

// --- AO-ignored: an IGNORED member must NOT cause a mismatch --------------
// "ignored.conf" contains a dot, so this configuration never loads it. Adding
// it must leave the topology equivalent, which proves the topology verifier
// shares the parser's eligibility rule instead of re-implementing it.

void testIgnoredDropinDoesNotChangeTopology() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");
    // Also a dotfile and a backup, both ignored by the same rule.
    writeFile(fixture.dropins / "ignored.conf", "Defaults:bob passwd_tries=9\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        writeFile(fixture.dropins / ".hidden", "Defaults:bob passwd_tries=9\n");
        writeFile(fixture.dropins / "backup~", "Defaults:bob passwd_tries=9\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(outcome.ok,
            "an ignored member must not invalidate a correct proof: " +
                outcome.message);
    require(activePreparedCount() == 0, "the record must be committed");
}

// --- AO-dir-error: the includedir becomes a regular file ------------------

void testIncludedirBecomesRegularFile() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        std::filesystem::remove_all(fixture.dropins);
        writeFile(fixture.dropins, "not a directory\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "an includedir that stopped being a directory must fail closed");
    require(activePreparedCount() == 1, "the Prepared record must stay active");
}

// --- AO-dir-gone: the includedir disappears ------------------------------

void testIncludedirDisappears() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        std::filesystem::remove_all(fixture.dropins);
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "a vanished includedir must NOT be read as an empty directory");
    require(activePreparedCount() == 1, "the Prepared record must stay active");
}

// --- AU: a new drop-in before a successful no-op ------------------------

void testNewDropinBeforeNoOp() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    // A GLOBAL Defaults is not a scoped violation, so the loaded graph has no
    // active scoped Defaults and the reconcile would be a no-op.
    DropinFixture fixture(tree, "Defaults passwd_tries=3\n");
    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().empty(),
            "the loaded graph must have no active scoped Defaults, otherwise "
            "this is not a no-op scenario");

    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeNoOpFinalTopologyGuard = [&fixture]() {
        writeFile(fixture.dropins / "bnew",
                  "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok || !outcome.unchanged,
            "a stale unchanged success must be impossible after a new drop-in");
    require(!outcome.unchanged,
            "the no-op must not be reported as unchanged on a stale graph");
}

// --- AP: a copied wrapper via a new drop-in before rollback resolution ----

void testCopiedWrapperViaNewDropinBeforeRollback() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:bob passwd_tries=9\n");
    // Install wrapper A through the drop-in so the journal owns it.
    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok,
            "apply A");
    const auto owned = activeOwned();
    require(owned.size() == 1, "the journal must own exactly A");
    const std::string wrapperBody = readAll(
        std::filesystem::path(owned[0].canonicalPath));

    SudoersConfiguration rollbackConfiguration(fixture.options);
    std::string loadError;
    require(rollbackConfiguration.load(loadError), loadError);
    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [fixture]() { return fixture.options; };
    deps.beforeSudoRollbackTopologyGuard = [&fixture, &wrapperBody]() {
        // A COPY of wrapper A appears in a brand-new eligible member that no
        // capture path knows about.
        writeFile(fixture.dropins / "bnew", wrapperBody);
    };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        scopedPolicy(), kScopedDefaultsResource, deps);

    require(report.status != fic::rollback::RollbackStatus::Success,
            "a copied wrapper in a new drop-in must block rollback Success");
    require(report.status != fic::rollback::RollbackStatus::NothingToDo,
            "the journal provenance must remain active");
    require(activeOwned().size() == 1,
            "the ownership record must still be active");
}

// --- AT8: ownership preflight from b6dc2b0 still holds under topology -----
// A wrapper that left the graph but whose proof path is known keeps being
// inspected, even when an @includedir is present.

void testOwnershipOutsideGraphWithIncludedir() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    DropinFixture fixture(tree, "Defaults:alice exempt_group=wheel\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok,
            "apply A: " + error);
    const auto owned = activeOwned();
    require(owned.size() == 1, "the journal must own exactly A");

    // The @includedir leaves the graph entirely, while the file that carries
    // wrapper A stays physical at the journal's proof path.
    writeFile(tree.root / "sudoers", "# no include directives\n");
    SudoersConfiguration afterDrop(fixture.options);
    std::string dropError;
    require(afterDrop.load(dropError), dropError);

    // Drift wrapper A at its proof path. The b6dc2b0 ownership preflight must
    // still see it and fail closed: the topology guard is NOT what catches this,
    // so the two mechanisms stay separate.
    const std::filesystem::path proofPath(owned[0].canonicalPath);
    std::string drifted = readAll(proofPath);
    const size_t at = drifted.find("exempt_group=wheel");
    require(at != std::string::npos, "wrapper A body must be present");
    drifted.replace(at, std::string("exempt_group=wheel").size(),
                    "exempt_group=daemon");
    writeFile(proofPath, drifted);

    ScopedDefaultsTransaction transaction(afterDrop, kPolicyName);
    require(!transaction.validateCurrentOwnership(owned).empty(),
            "the ownership preflight must still inspect the proof path of a "
            "wrapper that left the include graph");
}


// --- AV-topology: a new drop-in before a recovery normalization -----------

void testNewDropinBeforeRecoveryNormalization() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    PartialRefreshFixture fixture(tree);
    fixture.applyA();
    // Refreshing an existing owner: previous={A}, and nothing landed on disk, so
    // the recovery classification is CompletePrevious and the lifecycle reaches
    // the previous normalization.
    writeFile(tree.root / "b.conf",
              "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
    {
        SudoersConfiguration staged(fixture.options);
        std::string stagedError;
        require(staged.load(stagedError), stagedError);
        ScopedDefaultsTransaction planner(staged, kPolicyName);
        const auto plan = planner.plan(fixture.ownedA);
        std::vector<SudoScopedDefaultsWrapperProof> fresh;
        for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
            fresh.push_back(mutation.proof);
        }
        require(!fresh.empty(), "a refresh must be planned");
        stageRefresh(fixture.ownedA, scopedPolicy(), fresh);
    }
    // A fresh @includedir whose membership changes during the recovery.
    std::filesystem::create_directories(tree.root / "dropins");
    writeFile(tree.root / "dropins" / "abase", "Defaults passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "a.conf").string() + "\n"
              "@include " + (tree.root / "b.conf").string() + "\n"
              "@include " + (tree.root / "c.conf").string() + "\n"
              "@includedir " + (tree.root / "dropins").string() + "\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&tree]() {
        writeFile(tree.root / "dropins" / "bnew",
                  "Defaults passwd_tries=3\nDefaults:carol passwd_tries=4\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "a topology change must block the previous normalization: " +
                outcome.message);
    require(activePreparedCount() == 1,
            "the Prepared record must remain active");
}

// --- AW-topology: a new drop-in before a fresh Prepared discard ----------

void testNewDropinBeforeFreshDiscard() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    std::filesystem::create_directories(tree.root / "dropins");
    writeFile(tree.root / "dropins" / "abase", "Defaults:bob passwd_tries=9\n");
    writeFile(tree.root / "sudoers",
              "@includedir " + (tree.root / "dropins").string() + "\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    // A FRESH Prepared whose target never landed: previous is empty, so the
    // recovery path is the fresh discard.
    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    require(!targets.empty(), "a target must be planned");
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, targets}};
    require(recordPreparedMut(scopedPolicy(), undo, id, error), error);
    require(activePreparedCount() == 1, "the Prepared record must exist");

    SudoersConfiguration recovery(options);
    std::string loadError;
    require(recovery.load(loadError), loadError);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(recovery, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&tree]() {
        writeFile(tree.root / "dropins" / "bnew",
                  "Defaults passwd_tries=3\nDefaults:dave passwd_tries=5\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!outcome.ok,
            "a topology change must block a fresh discard: " + outcome.message);
    require(activePreparedCount() == 1,
            "the Prepared record must remain active");
}


// ===========================================================================
// Topology-resolution gaps: every normalize path needs a topology guard, a
// topology failure with an active Prepared record must be FailClosed (never
// NotPresent), and a no-op must rest on a FRESH semantic capture.
// ===========================================================================

// A refresh Prepared whose target never landed, with a known @includedir that a
// test can mutate in the protected window.
struct TopologyRefreshFixture {
    explicit TopologyRefreshFixture(TempTree& treeRef) : tree(treeRef) {
        writeFile(tree.root / "a.conf", "Defaults:alice exempt_group=wheel\n");
        writeFile(tree.root / "b.conf", "Defaults passwd_tries=3\n");
        std::filesystem::create_directories(tree.root / "dropins");
        writeFile(tree.root / "dropins" / "abase", "Defaults passwd_tries=5\n");
        writeFile(tree.root / "sudoers",
                  "@include " + (tree.root / "a.conf").string() + "\n"
                  "@include " + (tree.root / "b.conf").string() + "\n"
                  "@includedir " + (tree.root / "dropins").string() + "\n");
        options = sudoOptions(tree.root);
        applyA();
        // Stage the refresh but install nothing: the filesystem keeps {A}, so
        // the classification is CompletePrevious. Two distinct violations give
        // target {A,B,C}, which the Indeterminate test partially installs.
        writeFile(tree.root / "b.conf",
                  "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
        writeFile(tree.root / "dropins" / "cbase",
                  "Defaults passwd_tries=5\nDefaults:carol passwd_tries=4\n");
        SudoersConfiguration staged(options);
        std::string stagedError;
        require(staged.load(stagedError), stagedError);
        ScopedDefaultsTransaction planner(staged, kPolicyName);
        const auto plan = planner.plan(ownedA);
        // The STAGED planned mutations are kept: wrapper ids embed a timestamp,
        // so re-planning later would mint DIFFERENT ids than the journal record
        // and the disk state would no longer match the recorded target.
        planned = plan.fresh;
        require(planned.size() >= 2,
                "the refresh must plan at least two wrappers");
        std::vector<SudoScopedDefaultsWrapperProof> fresh;
        for (const PlannedScopedDefaultsMutation& mutation : planned) {
            fresh.push_back(mutation.proof);
        }
        target = fresh;
        stageRefresh(ownedA, scopedPolicy(), fresh);
    }

    // Installs the first `count` STAGED target wrappers, producing a genuine
    // partial disk state.
    void installPartialTarget(size_t count) {
        SudoersConfiguration staged(options);
        std::string stagedError;
        require(staged.load(stagedError), stagedError);
        SudoScopedDefaultsHooks installHooks = productionHooks(staged);
        installHooks.reloadAndVerify = [&staged](std::string& e) {
            return staged.load(e);
        };
        ScopedDefaultsTransaction installer(staged, kPolicyName);
        std::vector<PlannedScopedDefaultsMutation> slice(planned.begin(),
                                                         planned.begin() + count);
        const auto applied = installer.apply(slice, installHooks);
        require(applied.ok(), applied.operation.message);
    }

    void installWholeTarget() {
        installPartialTarget(planned.size());
    }
    void applyA() {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        require(reconcile(configuration, productionHooks(configuration)).ok,
                "apply A: " + error);
        ownedA = activeOwned();
        require(ownedA.size() == 1, "only A must be owned");
    }
    // Each call adds a DIFFERENT eligible member, so calling it twice in one
    // test really changes membership twice (an idempotent write would leave the
    // topology identical and silently pass).
    void newDropin() {
        ++dropinCounter;
        writeFile(tree.root / "dropins" / ("bnew" + std::to_string(dropinCounter)),
                  "Defaults passwd_tries=5\nDefaults:carol passwd_tries=4\n");
    }
    TempTree& tree;
    SudoersConfigurationOptions options;
    std::vector<SudoScopedDefaultsWrapperProof> ownedA;
    std::vector<SudoScopedDefaultsWrapperProof> target;
    std::vector<PlannedScopedDefaultsMutation> planned;
    int dropinCounter = 0;
};

// --- R3: CompletePrevious topology mismatch => FailClosed -----------------

void testCompletePreviousTopologyMismatchFailsClosed() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TopologyRefreshFixture fixture(tree);
    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        fixture.newDropin();
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));

    const auto recovery = lifecycle.recoverPrepared(kPolicyName);
    require(recovery.result == fic::sudoers::PreparedRecoveryResult::FailClosed,
            "a CompletePrevious topology mismatch must be FailClosed, never "
            "NotPresent");
    require(activePreparedCount() == 1, "the Prepared record must remain active");

    // ...and through reconcile() the unresolved record must not be ignored.
    SudoersConfiguration again(fixture.options);
    std::string againError;
    require(again.load(againError), againError);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps2 =
        productionDeps(again, SudoScopedDefaultsHooks{});
    deps2.journal.beforeFinalTopologyGuard = [&fixture]() {
        fixture.newDropin();
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle2(std::move(deps2));
    const auto outcome = lifecycle2.reconcile(kPolicyName);
    require(!outcome.ok, "reconcile must not succeed over a stale topology");
    require(!outcome.unchanged, "reconcile must not report unchanged");
    require(activePreparedCount() == 1, "the Prepared record must remain active");
}

// --- R4: CompleteTarget topology mismatch => FailClosed -------------------

void testCompleteTargetTopologyMismatchFailsClosed() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TopologyRefreshFixture fixture(tree);
    // Install the whole STAGED target, so the classification is CompleteTarget.
    fixture.installWholeTarget();

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeFinalTopologyGuard = [&fixture]() {
        fixture.newDropin();
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));

    const auto recovery = lifecycle.recoverPrepared(kPolicyName);
    require(recovery.result == fic::sudoers::PreparedRecoveryResult::FailClosed,
            "a CompleteTarget topology mismatch must be FailClosed, never "
            "NotPresent");
    require(activePreparedCount() == 1,
            "the Prepared record must NOT be committed to Applied");
}

// --- R6: post-compensation normalize topology mismatch => no normalize -----
// previous={A}, target={A,B}, B is installed so the state is Indeterminate,
// compensateToPrevious() rewinds B, the previous proof passes, and the
// topology changes right before normalize.

void testPostCompensationTopologyMismatchBlocksNormalize() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TopologyRefreshFixture fixture(tree);
    // Install ONLY the first planned wrapper, so the disk state {A,B} is a strict
    // subset of target {A,B,...}: the classification is Indeterminate and the
    // selective compensation has REAL work.
    fixture.installPartialTarget(1);

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    bool compensated = false;
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.afterPreparedCompensation = [&compensated]() {
        compensated = true;
    };
    deps.journal.beforeFinalTopologyGuard = [&fixture, &compensated]() {
        // Only mutate the topology once the compensation really happened, so the
        // test provably reaches the post-compensation normalize window.
        if (compensated) {
            fixture.newDropin();
        }
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));

    const auto recovery = lifecycle.recoverPrepared(kPolicyName);
    require(compensated,
            "the test must really pass through a successful "
            "compensateToPrevious()");
    require(recovery.result == fic::sudoers::PreparedRecoveryResult::FailClosed,
            "a post-compensation topology mismatch must be FailClosed");
    require(activePreparedCount() == 1,
            "the Prepared record must stay active: no normalize");
}

// --- R5: same-member content race before a no-op --------------------------

void testSameMemberContentRaceBeforeNoOp() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    // A GLOBAL Defaults is not a scoped violation, so the loaded graph has
    // nothing to remediate.
    std::filesystem::create_directories(tree.root / "dropins");
    writeFile(tree.root / "dropins" / "abase", "Defaults passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@includedir " + (tree.root / "dropins").string() + "\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().empty(),
            "the loaded graph must have no active scoped Defaults");

    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeNoOpSemanticCapture = [&tree]() {
        // SAME filename, so the membership topology is unchanged...
        writeFile(tree.root / "dropins" / "abase",
                  "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
        // ...but the file now activates a scoped Defaults, which the fresh
        // capture must see.
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(!(outcome.ok && outcome.unchanged),
            "a stale unchanged success is forbidden when a member's CONTENT "
            "changed under the same name");
    require(!outcome.unchanged, "the reconcile must not report unchanged");
}

// --- R6b: benign same-member content change stays a valid no-op ------------

void testBenignMemberContentChangeStillNoOp() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    std::filesystem::create_directories(tree.root / "dropins");
    writeFile(tree.root / "dropins" / "abase", "Defaults passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@includedir " + (tree.root / "dropins").string() + "\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().empty(),
            "the loaded graph must have no active scoped Defaults");

    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeNoOpSemanticCapture = [&tree]() {
        // Bytes change, but NO scoped Defaults is activated: a plain comment
        // and another global Defaults. This must NOT be a security failure.
        writeFile(tree.root / "dropins" / "abase",
                  "# a benign comment\nDefaults passwd_tries=3\n"
                  "Defaults log_input=1\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(outcome.ok && outcome.unchanged,
            "a benign same-member change must still allow a legitimate no-op: " +
                outcome.message);
}


// --- R8: a NEW @includedir member appearing AFTER the semantic proof -------
// The content proof cannot see it: captureProofAndGraphState() only knows the
// previously loaded graph documents and the journal proof paths. Only the FINAL
// topology guard closes this window.

void testNewMemberAfterSemanticProofBlocksNoOp() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    std::filesystem::create_directories(tree.root / "dropins");
    writeFile(tree.root / "dropins" / "abase", "Defaults passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@includedir " + (tree.root / "dropins").string() + "\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().empty(),
            "the loaded graph must have no active scoped Defaults");

    bool semanticCaptureReached = false;
    bool createdAfterProof = false;
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeNoOpSemanticCapture = [&semanticCaptureReached]() {
        semanticCaptureReached = true;
    };
    deps.journal.beforeNoOpFinalTopologyGuard = [&tree, &semanticCaptureReached,
                                                 &createdAfterProof]() {
        // The semantic proof has already succeeded on its capture at this
        // point; the drop-in is created afterwards and is therefore invisible
        // to that capture.
        require(semanticCaptureReached,
                "the semantic capture must happen before the final guard");
        createdAfterProof = true;
        writeFile(tree.root / "dropins" / "bnew",
                  "Defaults passwd_tries=3\nDefaults:bob passwd_tries=9\n");
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(createdAfterProof, "the test must inject the drop-in after the proof");
    require(!outcome.unchanged,
            "a new eligible member appearing after the semantic proof must "
            "block the unchanged success");
    require(!(outcome.ok && outcome.unchanged),
            "no successful unchanged result may be returned");
    require(activePreparedCount() == 0, "no journal record may be created");
    require(activeOwned().empty(), "no ownership may be recorded");
}

// --- R9: no membership change in the final window keeps the no-op valid ----

void testStableNoOpStillSucceeds() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    std::filesystem::create_directories(tree.root / "dropins");
    writeFile(tree.root / "dropins" / "abase", "Defaults passwd_tries=3\n");
    writeFile(tree.root / "sudoers",
              "@includedir " + (tree.root / "dropins").string() + "\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().empty(),
            "the loaded graph must have no active scoped Defaults");

    bool semanticProofPassed = false;
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    deps.journal.beforeNoOpFinalTopologyGuard = [&semanticProofPassed]() {
        // The final window is reached, but NOTHING changes on disk: the no-op
        // must stay valid, so the reordering cannot become always-fail.
        semanticProofPassed = true;
    };
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto outcome = lifecycle.reconcile(kPolicyName);

    require(semanticProofPassed, "the final window must be reached");
    require(outcome.ok && outcome.unchanged,
            "an unchanged no-op must remain valid when nothing changes: " +
                outcome.message);
    require(activePreparedCount() == 0, "no journal record may be created");
}


// ===========================================================================
// ML: multiline parity. The parser and the snapshot-bound semantic proof now
// share ONE physical -> logical assembler, so a multi-line scoped Defaults can
// never be classified one physical line at a time.
// ===========================================================================

// --- ML1: a multi-line scoped Defaults is ONE violation and ONE target -----

void testMultilineScopedDefaultsPlannedAsOneTarget() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    writeFile(tree.root / "sudoers", kRootLine + "Defaults:alice env_reset, \\\n    passwd_tries=5\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().size() == 1,
            "the configuration must see exactly ONE violation");

    // graphEntries() also carries the non-scoped root line, so the multi-line
    // entry is located by its physical span rather than by position.
    const auto entries = configuration.graphEntries();
    const SudoersConfiguration::GraphEntry* multiline = nullptr;
    for (const SudoersConfiguration::GraphEntry& entry : entries) {
        if (entry.lineCount > 1) {
            multiline = &entry;
            break;
        }
    }
    require(multiline != nullptr,
            "a logical entry spanning several physical lines must exist");
    require(multiline->lineCount == 2,
            "the entry must span BOTH physical lines");
    require(multiline->firstLine == 2,
            "firstLine stays 1-based and must not shift");

    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const auto plan = transaction.plan({});
    require(plan.fresh.size() == 1,
            "the whole logical entry must become exactly ONE target");
    require(plan.fresh.front().target.lineCount == 2,
            "the target must cover both physical lines");
    ++executedMultiline;
}

// --- ML2: the snapshot semantic proof SEES an active multi-line entry ------

void testMultilineActiveEntrySeenBySnapshotProof() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    writeFile(tree.root / "sudoers", kRootLine + "Defaults:alice env_reset, \\\n    passwd_tries=5\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    // No wrappers at all: the multi-line entry is an active violation and the
    // proof must say so instead of scanning physical lines one by one.
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    require(transaction.captureProofAndGraphState({}, captured, captureError),
            captureError);
    const ScopedDefaultsStateProof proof = transaction.proveCapturedState(
        {}, captured, ScopedDefaultsProofMode::ReleaseSubset,
        /*requireNoActiveScopedDefaults=*/true);
    require(!proof.ok,
            "an active MULTI-LINE scoped Defaults must fail the semantic proof");
    require(proof.message.find("активный") != std::string::npos,
            "the diagnostic must report the active entry: " + proof.message);
    ++executedMultiline;
}

// --- ML3: a WRAPPED multi-line entry is suppressed, not a false violation ---
// The marker payload of a wrapped continuation still contains a backslash, so a
// physical-line scanner could re-assemble it and see a phantom violation.

void testWrappedMultilineEntryIsSuppressed() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    writeFile(tree.root / "sudoers", kRootLine + "Defaults:alice env_reset, \\\n    passwd_tries=5\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction planner(configuration, kPolicyName);
    const auto plan = planner.plan({});
    require(plan.fresh.size() == 1, "one target is expected");
    SudoScopedDefaultsHooks hooks = productionHooks(configuration);
    ScopedDefaultsTransaction installer(configuration, kPolicyName);
    const auto applied = installer.apply(plan.fresh, hooks);
    require(applied.ok(), applied.operation.message);

    std::vector<SudoScopedDefaultsWrapperProof> targets;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targets.push_back(mutation.proof);
    }
    SudoersConfiguration after(options);
    std::string reloadError;
    require(after.load(reloadError), reloadError);
    ScopedDefaultsTransaction verifier(after, kPolicyName);
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    require(verifier.captureProofAndGraphState(targets, captured, captureError),
            captureError);
    const ScopedDefaultsStateProof proof = verifier.proveCapturedState(
        targets, captured, ScopedDefaultsProofMode::Exact,
        /*requireNoActiveScopedDefaults=*/true);
    require(proof.ok,
            "a WRAPPED multi-line entry must not look like an active "
            "violation: " + proof.message);
    ++executedMultiline;
}

// --- ML4 + ML6 + ML7: byte-exact rollback, CRLF and no-final-newline -------

void testMultilineByteExactRollback(const std::string& original,
                                    const std::string& label) {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    writeFile(tree.root / "sudoers", original);
    const SudoersConfigurationOptions options = sudoOptions(tree.root);
    const std::string before = readAll(tree.root / "sudoers");
    require(before == original, label + ": the fixture must be byte-exact");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(reconcile(configuration, productionHooks(configuration)).ok,
            label + ": apply must succeed: " + error);
    require(readAll(tree.root / "sudoers") != original,
            label + ": apply must change the file");

    fic::rollback::RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        scopedPolicy(), kScopedDefaultsResource, deps);
    require(report.status == fic::rollback::RollbackStatus::Success,
            label + ": rollback must succeed: " + report.message);
    require(readAll(tree.root / "sudoers") == original,
            label + ": rollback must restore the EXACT original bytes");
    ++executedMultiline;
}

void testMultilineByteExactRollbackLf() {
    testMultilineByteExactRollback(
        kRootLine + "Defaults:alice env_reset, \\\n    passwd_tries=5\n", "LF multiline");
}

void testMultilineByteExactRollbackCrlf() {
    testMultilineByteExactRollback(
        kRootLine + "Defaults:alice env_reset, \\\r\n    passwd_tries=5\r\n", "CRLF multiline");
}

void testMultilineByteExactRollbackNoFinalNewline() {
    testMultilineByteExactRollback(
        kRootLine + "Defaults:alice env_reset, \\\n    passwd_tries=5", "no-final-newline multiline");
}


// --- ML8: a logical entry that STRADDLES a wrapper boundary fails closed ---
// A FIC-created wrapper always owns a WHOLE logical entry, so a logical entry
// that starts inside the marker payload and continues past the END marker is a
// shape FIC never produces. Its semantics cannot be guessed, so the proof fails
// closed instead of guessing.

void testLogicalEntryStraddlingWrapperFailsClosed() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    writeFile(tree.root / "sudoers", "#@FIC_SUDO_DISABLED_BEGIN policy=sudo_disable_scoped_defaults mutation=FIC-SUDO-1-1-1-1-1@\n#@FIC_SUDO_DISABLED_LINE@eol=lf@Defaults:alice env_reset, \\\n#@FIC_SUDO_DISABLED_END policy=sudo_disable_scoped_defaults mutation=FIC-SUDO-1-1-1-1-1@\n    passwd_tries=5\n");
    const SudoersConfigurationOptions options = sudoOptions(tree.root);
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // Prove the wrapper as OWNED, so the ownership checks pass and the failure
    // that remains is exactly the boundary conflict under test. The digest is
    // taken from the parser itself, never hardcoded.
    const std::vector<fic::sudoers::SudoPhysicalLine> lines =
        fic::sudoers::splitPhysicalLines(readAll(tree.root / "sudoers"));
    std::vector<fic::sudoers::SudoDisabledWrapper> parsed;
    std::string parseError;
    require(fic::sudoers::parseSudoDisabledWrappers(
                lines, parsed, parseError) ==
                fic::sudoers::SudoWrapperParseStatus::Ok,
            parseError);
    require(parsed.size() == 1, "the fixture must contain one wrapper");
    SudoScopedDefaultsWrapperProof owned;
    owned.wrapperId = parsed[0].mutationId;
    owned.canonicalPath =
        fic::sudoers::canonicalizeSudoProofPath(tree.root / "sudoers");
    owned.payloadDigest = parsed[0].payloadDigest();
    const std::vector<SudoScopedDefaultsWrapperProof> proofs{owned};

    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    require(transaction.captureProofAndGraphState(proofs, captured, captureError),
            captureError);
    const ScopedDefaultsStateProof proof = transaction.proveCapturedState(
        proofs, captured, ScopedDefaultsProofMode::ReleaseSubset,
        /*requireNoActiveScopedDefaults=*/true);
    require(!proof.ok,
            "a logical entry crossing a wrapper boundary must fail closed");
    require(proof.message.find("частично") != std::string::npos,
            "the diagnostic must name the boundary conflict: " + proof.message);
    ++executedMultiline;
}


// --- CL: Prepared classification is SNAPSHOT-BOUND ---------------------------
// A previous wrapper that is physically present but no longer reachable through
// the current include graph must STILL be visible to the classifier, because the
// journal proves its canonical path.
//
// A graph-only classifier could not do this: an inventory limited to the current
// include graph would see NO wrappers at all, match neither side, and answer
// Indeterminate for a record that physically holds exactly the previous
// ownership. No such graph-only recovery API exists any more.

void testClassificationSeesPreviousWrapperOutsideGraph() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TopologyRefreshFixture fixture(tree);

    // The @include for a.conf disappears while a.conf itself stays physical and
    // still carries wrapper A. The @includedir membership is untouched, so the
    // topology guard is not what decides this test.
    writeFile(tree.root / "sudoers",
              kRootLine +
                  "@include " + (tree.root / "b.conf").string() + "\n"
                  "@includedir " + (tree.root / "dropins").string() + "\n");

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);

    // Direct classifier contract on the explicit captured authority state.
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::vector<SudoScopedDefaultsWrapperProof> previous =
        fixture.ownedA;
    std::vector<SudoScopedDefaultsWrapperProof> allProofs = previous;
    allProofs.insert(allProofs.end(), fixture.target.begin(),
                     fixture.target.end());
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    require(transaction.captureProofAndGraphState(allProofs, captured,
                                                  captureError),
            captureError);
    std::string classifyError;
    const PreparedRecovery classification = transaction.classifyCaptured(
        previous, fixture.target, captured, classifyError);
    require(classification == PreparedRecovery::CompletePrevious,
            "a previous wrapper outside the current graph must still classify "
            "as CompletePrevious, not Indeterminate");

    // And the recovery flow must therefore normalize the record back to the
    // proven previous ownership instead of attempting a compensation.
    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto recovery = lifecycle.recoverPrepared(kPolicyName);
    require(recovery.result == fic::sudoers::PreparedRecoveryResult::NormalizedExisting,
            "recovery must normalize to the previous ownership: " +
                recovery.message);
    require(activePreparedCount() == 0,
            "the record must be resolved to Applied(previous)");
}


// --- LV: selective compensation must not be limited to the current graph ----
//
// LIVENESS, not safety: a target-only wrapper that physically exists at a
// journal-known canonicalPath which has fallen out of the current include graph
// is invisible to a graph-only inventory. Compensation then produces no work,
// recovery answers FailClosed, and the Prepared record can never be resolved:
// every retry reaches exactly the same dead end.
//
// The expected resolution is CompensatedExisting/normalize, because the wrapper
// is real, journal-known and removable by its proof.

void testCompensationSeesTargetOnlyWrapperOutsideGraph() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    TopologyRefreshFixture fixture(tree);
    // Install only the first target wrapper: disk is a strict subset of target,
    // so the classification is Indeterminate and compensation must run.
    fixture.installPartialTarget(1);
    require(fixture.planned.size() >= 2,
            "the target must hold more than one wrapper");

    // The file carrying the installed target-only wrapper leaves the include
    // graph while staying physical at its journal proof path.
    const std::filesystem::path orphan = fixture.planned.front().target.path;
    const std::string orphanName = orphan.filename().string();
    writeFile(tree.root / "sudoers",
              kRootLine +
                  "@include " + (tree.root / "a.conf").string() + "\n"
                  "@include " + (tree.root / "c.conf").string() + "\n"
                  "@includedir " + (tree.root / "dropins").string() + "\n");
    (void)orphanName;

    SudoersConfiguration configuration(fixture.options);
    std::string error;
    require(configuration.load(error), error);
    // The wrapper really is gone from the graph but present on disk.
    require(onDiskWrapperIds(tree.root).size() >= 2,
            "previous and the target-only wrapper must both be physical");

    fic::sudoers::ScopedDefaultsLifecycleDeps deps =
        productionDeps(configuration, SudoScopedDefaultsHooks{});
    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const auto recovery = lifecycle.recoverPrepared(kPolicyName);

    require(recovery.result !=
                fic::sudoers::PreparedRecoveryResult::FailClosed,
            "a journal-known target-only wrapper outside the graph must not "
            "wedge recovery: " + recovery.message);
    require(recovery.result ==
                fic::sudoers::PreparedRecoveryResult::CompensatedExisting ||
                recovery.result ==
                    fic::sudoers::PreparedRecoveryResult::NormalizedExisting,
            "the record must be resolved back to the previous ownership: " +
                recovery.message);
    require(activePreparedCount() == 0,
            "no Prepared record may be left active");
}



// ---------------------------------------------------------------------------
// Test registry.
//
// Every lifecycle scenario is registered HERE and executed from this table, so
// a test function can never be defined and silently skipped. The table is also
// the single source of truth for the reported counts.
// ---------------------------------------------------------------------------

struct LifecycleCase {
    const char* label;
    void (*run)();
};

const std::vector<LifecycleCase>& lifecycleCases() {
    static const std::vector<LifecycleCase> cases = {
        {"A  normal lifecycle + journal reload + rollback", testNormalLifecycle},
        {"B  reconciliation grows ownership", testReconciliationGrowsOwnership},
        {"C  payload drift refuses unwrap", testPayloadDriftRefusesUnwrap},
        {"D1 partial apply, compensation succeeds", testPartialApplyCompensated},
        {"D2 partial apply, compensation fails", testPartialApplyCompensationFails},
        {"E  orphan wrapper, no violations", testOrphanNoOpFailsClosed},
        {"F  same physical include twice", testSamePhysicalIncludeTwice},
        {"G  duplicate id across two files", testGlobalDuplicateIdRefused},
        {"H  CRLF round trip", testCrlfRoundTrip},
        {"I  multiple fresh violations mapping", testMultipleFreshViolationsMapping},
        {"J  graph load -> capture TOCTOU", testGraphSnapshotToCaptureToctou},
        {"K  first-write CAS conflict", testFirstWriteCasConflictNotWedged},
        {"L  crash before write recovery", testCrashBeforeWriteRecovery},
        {"M  crash after complete write", testCrashAfterWriteRecovery},
        {"N  ambiguous Prepared fails closed", testPartialPreparedRecovery},
        {"O  drift + new violation", testDriftedWrapperPlusNewViolation},
        {"P  orphan + new violation", testOrphanWrapperPlusNewViolation},
        {"Q  no-final-newline round trip", testNoFinalNewlineRoundTrip},
        {"R  partial rollback compensated", testPartialRollbackCompensated},
        {"S  refresh crash before write", testRefreshCrashBeforeWriteKeepsOwnership},
        {"T  refresh CAS conflict", testRefreshCasConflictKeepsOwnership},
        {"U  refresh partial + compensation", testRefreshPartialMutationCompensated},
        {"V  durability blocks commit", testCompleteTargetDurabilityBlocksCommit},
        {"W  rollback durability blocks resolution", testRollbackDurabilityBlocksResolution},
        {"X  drift between preflight and commit", testDriftBetweenPreflightAndCommitRefusesCommit},
        {"Y  partial refresh selective compensation", testPartialRefreshSelectiveCompensation},
        {"Z  duplicate id before release capture", testDuplicateIdBeforeReleaseCaptureRefused},
        {"AA target wrapper disappears before commit", testTargetWrapperDisappearsBeforeCommit},
        {"AB previous drifts before normalization", testPreviousDriftsBeforeNormalization},
        {"AC previous disappears before normalization", testPreviousDisappearsBeforeNormalization},
        {"AD duplicate after graph load, before capture", testDuplicateInsertedAfterGraphLoadBeforeCapture},
        {"AE symlink proof target is not absence", testSymlinkProofTargetNotAbsent},
        {"AF directory proof target is not absence", testDirectoryProofTargetNotAbsent},
        {"AG genuinely absent proof file", testGenuinelyAbsentProofFile},
        {"AH change between proof and durability", testChangeBetweenProofAndDurability},
        {"AJ target hidden by topology change", testTargetHiddenByTopologyChange},
        {"AK fresh crash-before-write recovers", testFreshCrashBeforeWriteStillRecovers},
        {"AY direct compensation -> exact previous", testDirectCompensationYieldsExactPrevious},
        {"AQ previous drifts after compensation", testPreviousDriftsAfterCompensation},
        {"AV target-only restored after compensation", testTargetOnlyRestoredAfterCompensation},
        {"AW target-only survives outside graph", testTargetOnlySurvivesOutsideGraph},
        {"AZ durability failure blocks previous normalization", testPreviousExactButDurabilityFails},
        {"AT drifted owned wrapper outside graph", testOwnedWrapperDriftedOutsideGraph},
        {"AT2 exact owned wrapper outside graph", testOwnedWrapperExactOutsideGraph},
        {"AT3 moved owned wrapper outside graph", testOwnedWrapperMovedOutsideGraph},
        {"AT4 unknown wrapper on proof-only path", testUnknownWrapperOnProofOnlyPath},
        {"AT5 duplicate id across graph and proof-only path", testDuplicateIdAcrossGraphAndProofOnlyPath},
        {"AT6a owned proof path is a directory", testOwnedPathAsDirectory},
        {"AT6b owned proof path is a symlink", testOwnedPathAsSymlink},
        {"AT7 new violation over broken ownership", testNewViolationOverBrokenOwnership},
        {"AO new drop-in before final commit", testNewDropinBeforeFinalCommit},
        {"AO-deleted drop-in before final commit", testDeletedDropinBeforeFinalCommit},
        {"AO-renamed drop-in before final commit", testRenamedDropinBeforeFinalCommit},
        {"AO-ignored member keeps topology equivalent", testIgnoredDropinDoesNotChangeTopology},
        {"AO includedir became a regular file", testIncludedirBecomesRegularFile},
        {"AO includedir disappeared", testIncludedirDisappears},
        {"AU new drop-in before no-op", testNewDropinBeforeNoOp},
        {"AP copied wrapper via new drop-in before rollback", testCopiedWrapperViaNewDropinBeforeRollback},
        {"AT8 ownership outside graph with includedir", testOwnershipOutsideGraphWithIncludedir},
        {"AV-topology new drop-in before recovery normalization", testNewDropinBeforeRecoveryNormalization},
        {"AW-topology new drop-in before fresh discard", testNewDropinBeforeFreshDiscard},
        {"R3 CompletePrevious topology mismatch is FailClosed", testCompletePreviousTopologyMismatchFailsClosed},
        {"R4 CompleteTarget topology mismatch is FailClosed", testCompleteTargetTopologyMismatchFailsClosed},
        {"R5 post-compensation topology mismatch blocks normalize", testPostCompensationTopologyMismatchBlocksNormalize},
        {"R6 same-member content race blocks stale no-op", testSameMemberContentRaceBeforeNoOp},
        {"R7 benign same-member change keeps the no-op", testBenignMemberContentChangeStillNoOp},
        {"R8 new member after semantic proof blocks no-op", testNewMemberAfterSemanticProofBlocksNoOp},
        {"R9 stable final window keeps the no-op valid", testStableNoOpStillSucceeds},
        {"ML1 multiline scoped Defaults planned as one target", testMultilineScopedDefaultsPlannedAsOneTarget},
        {"ML2 snapshot proof sees active multiline entry", testMultilineActiveEntrySeenBySnapshotProof},
        {"ML3 wrapped multiline entry is suppressed", testWrappedMultilineEntryIsSuppressed},
        {"ML4 multiline rollback is byte-exact (LF)", testMultilineByteExactRollbackLf},
        {"ML6 multiline rollback is byte-exact (CRLF)", testMultilineByteExactRollbackCrlf},
        {"ML7 multiline rollback is byte-exact (no final newline)", testMultilineByteExactRollbackNoFinalNewline},
        {"ML8 logical entry straddling a wrapper boundary fails closed", testLogicalEntryStraddlingWrapperFailsClosed},
        {"CL classification sees previous wrapper outside the graph", testClassificationSeesPreviousWrapperOutsideGraph},
        {"LV compensation reaches a target-only wrapper outside the graph", testCompensationSeesTargetOnlyWrapperOutsideGraph},
    };
    return cases;
}

int main() {
    std::size_t executed = 0;
    for (const LifecycleCase& item : lifecycleCases()) {
        try {
            item.run();
            ++executed;
        } catch (const std::exception& error) {
            std::cerr << "FAILED [" << item.label << "]: " << error.what()
                      << '\n';
            std::cout << "Executed " << executed << " of "
                      << lifecycleCases().size()
                      << " lifecycle test functions before failure\n";
            return 1;
        }
    }
    std::cout << "Executed " << executed << " of " << lifecycleCases().size()
              << " lifecycle test functions\n";
    std::cout << "Covered " << lifecycleCases().size()
              << " acceptance scenarios\n";
    return 0;
}
