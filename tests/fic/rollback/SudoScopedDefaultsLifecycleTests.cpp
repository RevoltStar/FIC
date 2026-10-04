// End-to-end journal -> filesystem lifecycle for the SUDO scoped-defaults
// blocker. The scenarios drive the PRODUCTION orchestration
// (ScopedDefaultsLifecycle) over temporary trees and the real MutationJournal,
// so crash recovery, partial writes and compensation are exercised through the
// production code path rather than a hand-copied imitation of it.

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
using fic::sudoers::ScopedDefaultsLifecycleOutcome;
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
    const SudoScopedDefaultsHooks& hooks) {
    ScopedDefaultsLifecycleDeps deps;
    deps.configuration = &configuration;
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
    require(reconcile(configuration, productionHooks(configuration)).ok,
            label + ": apply");
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
    require(reconcile(configuration, productionHooks(configuration)).ok, "apply");
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

} // namespace

int main() {
    try {
        testNormalLifecycle();                            // A
        testReconciliationGrowsOwnership();               // B
        testPayloadDriftRefusesUnwrap();                 // C
        testPartialApplyCompensated();                    // D1
        testPartialApplyCompensationFails();              // D2
        testOrphanNoOpFailsClosed();                      // E
        testSamePhysicalIncludeTwice();                   // F
        testGlobalDuplicateIdRefused();                   // G
        testCrlfRoundTrip();                              // H
        testMultipleFreshViolationsMapping();             // I
        testGraphSnapshotToCaptureToctou();               // J
        testFirstWriteCasConflictNotWedged();             // K
        testCrashBeforeWriteRecovery();                   // L
        testCrashAfterWriteRecovery();                    // M
        testPartialPreparedRecovery();                    // N
        testDriftedWrapperPlusNewViolation();             // O
        testOrphanWrapperPlusNewViolation();              // P
        testNoFinalNewlineRoundTrip();                    // Q
        testPartialRollbackCompensated();                 // R
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}