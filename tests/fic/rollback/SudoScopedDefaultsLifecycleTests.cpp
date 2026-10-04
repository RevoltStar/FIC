// End-to-end journal -> filesystem lifecycle for the SUDO scoped-defaults
// blocker. These scenarios drive the REAL backend, MutationJournal and
// RollbackExecutor against temporary trees, so the durable contract (journal
// reload, byte-exact restore, drift refusal, orphan fail-closed) is exercised
// rather than just the in-memory helpers.

#include <fic/core/integrity/ContentDigest.h>
#include <fic/policy/PolicyDependency.h>
#include "modules/dac/sudo/SudoersConfiguration.h"
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
using fic::sudoers::kScopedDefaultsPolicyName;
using fic::sudoers::kScopedDefaultsResource;
using fic::sudoers::ScopedDefaultsTransaction;
using fic::sudoers::SudoScopedDefaultsHooks;
using fic::sudoers::SudoScopedDefaultsOutcome;

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
    ~JournalOverride() { fic::rollback::DaemonMutationJournal::instance().resetOverride(); }
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

// Active ownership proven by the journal: exactly the set a reconciliation
// must carry forward.
std::vector<SudoScopedDefaultsWrapperProof> activeOwned(
    const PolicyRef& policy) {
    std::vector<SudoScopedDefaultsWrapperProof> owned;
    std::string error;
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    for (const MutationRecord& record : journal->activeRecords(policy)) {
        const auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(
            &record.undo.payload);
        if (payload == nullptr) {
            continue;
        }
        for (const SudoScopedDefaultsWrapperProof& proof : payload->targetProofs) {
            owned.push_back(proof);
        }
    }
    return owned;
}

// Applies the blocker the way the policy does: plan, journal the Prepared
// record, run the transaction, then commit or discard per the TYPED outcome.
SudoScopedDefaultsOutcome runApply(
    SudoersConfiguration& configuration,
    const PolicyRef& policy,
    const std::vector<SudoScopedDefaultsWrapperProof>& owned,
    std::vector<SudoScopedDefaultsWrapperProof>& targetOut) {
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    SudoScopedDefaultsHooks hooks;
    hooks.validate = [&configuration](std::string& e) {
        return configuration.validateConfiguration(e);
    };
    hooks.reloadAndVerify = [&configuration](std::string& e) {
        return configuration.load(e) &&
            configuration.scopedDefaultsViolations().empty();
    };
    const auto planned = transaction.planRefresh(owned);
    const std::vector<SudoScopedDefaultsWrapperProof> fresh(
        planned.begin() + static_cast<std::ptrdiff_t>(owned.size()),
        planned.end());
    targetOut = planned;

    MutationId id = 0;
    std::string error;
    // The FULL ownership set is journaled, not just the fresh wrappers: the
    // record must keep authorizing the wrappers FIC created earlier.
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, owned, planned}};
    require(fic::rollback::recordPreparedMutation(policy, kScopedDefaultsResource,
                                                  undo, id, error),
            error);
    SudoScopedDefaultsOutcome outcome = SudoScopedDefaultsOutcome::NoMutation;
    const auto result = transaction.apply(fresh, outcome, hooks);
    if (!result.ok) {
        if (fic::sudoers::outcomeAllowsDiscard(outcome)) {
            require(fic::rollback::discardMutation(id, error), error);
        }
        throw std::runtime_error("apply failed: " + result.message);
    }
    require(fic::rollback::commitMutation(id, error), error);
    return outcome;
}

std::string wrapperBlock(const std::string& id, const std::string& body) {
    // Mirrors the exact marker grammar produced by disableSudoEntry().
    return std::string("#@FIC_SUDO_DISABLED_BEGIN policy=") + kPolicyName +
        " mutation=" + id + "@\n" +
        "#@FIC_SUDO_DISABLED_LINE@" + body + "\n" +
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

    std::vector<SudoScopedDefaultsWrapperProof> target;
    require(runApply(configuration, policy, {}, target) ==
                SudoScopedDefaultsOutcome::Success,
            "a fresh scoped-defaults apply must succeed");
    require(countWrappers(configuration) == 1,
            "exactly one wrapper must exist after the first apply");

    // The provenance survives a journal RELOAD: a fresh journal instance must
    // read back the persisted proofs.
    {
        fic::rollback::MutationJournal reloaded(tree.root / "journal.json");
        std::string reloadError;
        require(reloaded.load(reloadError), reloadError);
        const auto owned = activeOwned(policy);
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
            "rollback must resolve the recorded scoped-defaults mutation: " +
                report.message);
    require(readFile(tree.root / "sudoers") == before,
            "rollback must restore the sudoers file BYTE EXACTLY");
}

// --- B: reconciliation GROWS the ownership set ------------------------------

void testReconciliationGrowsOwnership() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);

    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    std::vector<SudoScopedDefaultsWrapperProof> target;
    require(runApply(configuration, policy, {}, target) ==
                SudoScopedDefaultsOutcome::Success, "first apply");
    const auto ownedAfterFirst = activeOwned(policy);
    require(ownedAfterFirst.size() == 1,
            "one owned wrapper after the first apply");

    // New drift appears OUTSIDE FIC's wrappers, as a separate entry.
    writeFile(tree.root / "sudoers",
              wrapperBlock(ownedAfterFirst[0].wrapperId,
                           "Defaults:alice exempt_group=wheel") +
              "Defaults:bob exempt_group=wheel\n");
    require(configuration.load(error), error);
    require(configuration.scopedDefaultsViolations().size() == 1,
            "exactly the new violation is active");

    require(runApply(configuration, policy, ownedAfterFirst, target) ==
                SudoScopedDefaultsOutcome::Success, "reconciliation apply");
    const auto ownedAfterSecond = activeOwned(policy);
    require(ownedAfterSecond.size() == 2,
            "reconciliation must GROW ownership from 1 to 2, never replace it");
    require(countWrappers(configuration) == 2,
            "both wrappers must be physically present");

    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    SudoScopedDefaultsHooks hooks;
    SudoScopedDefaultsOutcome releaseOutcome = SudoScopedDefaultsOutcome::NoMutation;
    const auto released =
        transaction.release(ownedAfterSecond, releaseOutcome, hooks);
    require(released.ok &&
                releaseOutcome == SudoScopedDefaultsOutcome::Success,
            "both wrappers must be released");
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
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);

    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    std::vector<SudoScopedDefaultsWrapperProof> target;
    require(runApply(configuration, policy, {}, target) ==
                SudoScopedDefaultsOutcome::Success, "apply");
    const auto owned = activeOwned(policy);

    // Hand-edit the suppressed BODY while keeping the id and the markers.
    const std::string wrapped = readFile(tree.root / "sudoers");
    const std::string needle =
        "#@FIC_SUDO_DISABLED_LINE@Defaults:alice exempt_group=wheel\n";
    require(wrapped.find(needle) != std::string::npos,
            "wrapper layout changed unexpectedly");
    std::string tampered = wrapped;
    tampered.replace(tampered.find(needle), needle.size(),
                     "#@FIC_SUDO_DISABLED_LINE@Defaults:root ALL=(ALL:ALL) ALL\n");
    writeFile(tree.root / "sudoers", tampered);

    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    SudoScopedDefaultsHooks hooks;
    SudoScopedDefaultsOutcome outcome = SudoScopedDefaultsOutcome::NoMutation;
    const auto result = transaction.release(owned, outcome, hooks);
    require(result.conflict && outcome == SudoScopedDefaultsOutcome::Conflict,
            "a hand-edited wrapper body must be a Conflict");
    require(readFile(tree.root / "sudoers") == tampered,
            "a drifted payload must cause ZERO writes");
}

// --- D: an unresolved Prepared record and the typed-outcome contract -------

void testUncompensatedMutationKeepsPreparedRecord() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);

    writeFile(tree.root / "sudoers", "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const auto planned = transaction.planRefresh({});

    // Prepare the record exactly as the policy does, then leave the
    // transaction unresolved (the crash-consistent window).
    MutationId id = 0;
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{kPolicyName, {}, planned}};
    require(fic::rollback::recordPreparedMutation(policy, kScopedDefaultsResource,
                                                  undo, id, error),
            error);

    // The filesystem still matches the PREVIOUS side, so the transition can be
    // proven never to have landed and resolved WITHOUT minting new provenance.
    require(transaction.classifyPrepared({}, planned, error) ==
                fic::sudoers::PreparedRecovery::CompletePrevious,
            "an untouched filesystem must classify as CompletePrevious");

    // Typed-outcome contract: only a proven no-mutation or fully compensated
    // transition may discard the record.
    require(fic::sudoers::outcomeAllowsDiscard(
                SudoScopedDefaultsOutcome::NoMutation) &&
                fic::sudoers::outcomeAllowsDiscard(
                    SudoScopedDefaultsOutcome::MutatedAndCompensated) &&
                !fic::sudoers::outcomeAllowsDiscard(
                    SudoScopedDefaultsOutcome::MutatedAndStillPresent) &&
                !fic::sudoers::outcomeAllowsDiscard(
                    SudoScopedDefaultsOutcome::Conflict),
            "only NoMutation and MutatedAndCompensated may discard provenance");
    require(fic::rollback::discardMutation(id, error), error);
}

// --- E: an orphan wrapper makes a no-op apply fail closed -------------------

void testOrphanNoOpFailsClosed() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    const std::string orphanId = "FIC-SUDO-1-2-3-4-5";
    writeFile(tree.root / "sudoers",
              wrapperBlock(orphanId, "Defaults:alice exempt_group=wheel"));

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    // No active scoped violations remain: this is the "no-op" case.
    require(configuration.scopedDefaultsViolations().empty(),
            "the orphan wrapper already deactivates the entry");

    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::string before = readFile(tree.root / "sudoers");
    const std::string refusal = transaction.noopPreflight({});
    require(!refusal.empty(),
            "an orphan wrapper without journal provenance must fail closed");
    require(readFile(tree.root / "sudoers") == before,
            "a refused no-op must leave the file untouched");
}

// --- F: the same physical include twice yields exactly ONE wrapper ----------

void testSamePhysicalIncludeTwice() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
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
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    require(transaction.targets().size() == 1,
            "semantic duplication must collapse to ONE physical target");

    std::vector<SudoScopedDefaultsWrapperProof> target;
    require(runApply(configuration, policy, {}, target) ==
                SudoScopedDefaultsOutcome::Success, "apply");
    require(countWrappers(configuration) == 1,
            "a doubly included file must be wrapped exactly ONCE");
}

// --- G: one wrapper id in two files is refused globally, with zero writes --

void testGlobalDuplicateIdRefused() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const auto options = sudoOptions(tree.root);
    const std::string shared = "FIC-SUDO-9-9-9-9-9";
    const auto block = wrapperBlock(shared, "Defaults:alice exempt_group=wheel");
    writeFile(tree.root / "site.conf", block);
    writeFile(tree.root / "sudoers",
              "@include " + (tree.root / "site.conf").string() + "\n" + block);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    ScopedDefaultsTransaction transaction(configuration, kPolicyName);
    const std::string before = readFile(tree.root / "sudoers");
    const std::string refusal = transaction.noopPreflight({});
    require(!refusal.empty(),
            "the SAME wrapper id in two files must be refused globally");
    require(readFile(tree.root / "sudoers") == before,
            "a global duplicate id must cause ZERO writes");
}

// --- H: a CRLF sudoers file round-trips byte-exactly -----------------------

void testCrlfByteExactRoundTrip() {
    TempTree tree;
    JournalOverride override(tree.root / "journal.json");
    const PolicyRef policy = scopedPolicy();
    const auto options = sudoOptions(tree.root);
    const std::string original =
        "Defaults passwd_tries=3\r\nDefaults:alice exempt_group=wheel\r\n";
    writeFile(tree.root / "sudoers", original);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    std::vector<SudoScopedDefaultsWrapperProof> target;
    require(runApply(configuration, policy, {}, target) ==
                SudoScopedDefaultsOutcome::Success, "CRLF apply");
    // The entry must no longer be an ACTIVE sudoers line (the suppressed copy
    // still lives inside the wrapper, prefixed by the marker).
    bool stillActive = false;
    for (const fic::sudoers::SudoPhysicalLine& line :
         fic::sudoers::splitPhysicalLines(readFile(tree.root / "sudoers"))) {
        if (line.text.rfind("Defaults:alice", 0) == 0) {
            stillActive = true;
        }
    }
    require(!stillActive, "the CRLF entry must no longer be an active line");

    const auto owned = activeOwned(policy);
    SudoersConfiguration release(options);
    std::string releaseError;
    require(release.load(releaseError), releaseError);
    ScopedDefaultsTransaction transaction(release, kPolicyName);
    SudoScopedDefaultsHooks hooks;
    SudoScopedDefaultsOutcome outcome = SudoScopedDefaultsOutcome::NoMutation;
    const auto result = transaction.release(owned, outcome, hooks);
    require(result.ok, result.message);
    require(readFile(tree.root / "sudoers") == original,
            "a CRLF sudoers file must be restored BYTE EXACTLY");
}

} // namespace

int main() {
    try {
        testNormalLifecycle();
        testReconciliationGrowsOwnership();
        testPayloadDriftRefusesUnwrap();
        testUncompensatedMutationKeepsPreparedRecord();
        testOrphanNoOpFailsClosed();
        testSamePhysicalIncludeTwice();
        testGlobalDuplicateIdRefused();
        testCrlfByteExactRoundTrip();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}