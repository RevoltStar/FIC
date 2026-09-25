// C2 runtime transition executor tests: deterministic fake native
// pam-auth-update mutator + fake /var/lib/pam + /etc/pam.d tree.
// Coverage: E1-E12 success transitions, F1-F11 failure matrix.
#include "modules/identity_access/pam/PamPasswordTopologyTransitionExecutor.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"

#include <rollback/MutationJournal.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

using fic::identity::pam::kFicPasswordHistoryHookProfileId;
using fic::identity::pam::kFicPasswordHistoryInitialHookProfileId;
using fic::identity::pam::kFicPasswordQualityHookProfileId;
using fic::identity::pam::kStockPwqualityProfileId;
using fic::identity::pam::ManagedPasswordSlotState;
using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamPasswordStateInspectionOptions;
using fic::identity::pam::PamPasswordTopologyClass;
using fic::identity::pam::PamPasswordTopologyExecutorOptions;
using fic::identity::pam::PamPasswordTopologySnapshot;
using fic::identity::pam::PamPasswordTopologyTransitionExecutor;
using fic::identity::pam::PamPasswordTransitionResult;
using fic::identity::pam::PamManagedPasswordSlots;
using fic::rollback::MutationJournal;
using fic::rollback::MutationStatus;

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
        root_ = base / ("fic-c2-executor-test-" +
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
    std::filesystem::path pamd() const { return root_ / "pam.d"; }
    std::filesystem::path state() const { return root_ / "state"; }

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

// The fake native mutator emulates the pam-auth-update semantics the C2
// grammar relies on: the "Module:" records in the password state file and
// the generated include lines (with the REAL trailing-whitespace
// generation quirk) in common-password, ONE profile per invocation.
struct FakeNativeMutator {
    struct Invocation {
        std::string flag;
        std::string profileId;
    };

    TemporaryDirectory& tree;
    std::vector<Invocation> invocations;
    // Scripted behavior by invocation number (1-based): return the exit
    // code. 0 = apply the mutation. Non-zero = no applied mutation.
    std::function<int(std::size_t, const Invocation&)> behavior;

    explicit FakeNativeMutator(TemporaryDirectory& tree) : tree(tree) {}

    ProcessResult run(const std::string& /*executable*/,
                      const std::vector<std::string>& arguments,
                      const ProcessOptions& /*options*/) {
        require(arguments.size() == 2,
                "fake mutator: exactly ONE profile per pam-auth-update "
                "invocation is required, got " +
                    std::to_string(arguments.size()));
        require(arguments[0] == "--enable" || arguments[0] == "--disable",
                "fake mutator: unexpected pam-auth-update flag " +
                    arguments[0]);
        const Invocation invocation{arguments[0], arguments[1]};
        invocations.push_back(invocation);
        int exitCode = 0;
        if (behavior) {
            exitCode = behavior(invocations.size(), invocation);
        }
        if (exitCode == 0) {
            apply(invocation);
            if (afterApplyHook) {
                afterApplyHook();
            }
        }
        ProcessResult result;
        result.started = true;
        result.exitCode = exitCode;
        return result;
    }

    bool isSelected(const std::string& profileId) const {
        std::istringstream stream(readFile(stateFile()));
        std::string line;
        while (std::getline(stream, line)) {
            const std::string prefix = "Module: ";
            if (line.compare(0, prefix.size(), prefix) == 0 &&
                line.substr(prefix.size()) == profileId) {
                return true;
            }
        }
        return false;
    }

    bool hasInclude(const std::string& slotName) const {
        std::istringstream stream(readFile(tree.pamd() / "common-password"));
        std::string line;
        while (std::getline(stream, line)) {
            std::istringstream tokens(line);
            std::string token;
            std::vector<std::string> words;
            while (tokens >> token) {
                words.push_back(token);
            }
            if (words.size() < 3 || words.front() != "password") {
                continue;
            }
            for (std::size_t index = 1; index + 1 < words.size(); ++index) {
                if (words[index] == "include" &&
                    words[index + 1] == slotName) {
                    return true;
                }
            }
        }
        return false;
    }

    std::filesystem::path stateFile() const {
        return tree.state() / "password";
    }

    // Test-scenario helpers operating OUTSIDE the normal rc semantics.
    // Foreign / drift injection: select a profile regardless of any
    // invocation (foreign state appears between actions).
    void forceSelect(const std::string& profileId) {
        std::vector<std::string> selected = readSelected();
        bool found = false;
        for (const std::string& profile : selected) {
            if (profile == profileId) {
                found = true;
                break;
            }
        }
        if (!found) {
            selected.push_back(profileId);
        }
        writeSelected(selected);
    }

    // Partial native mutation: the state record lands but the generated
    // stack regeneration does not happen.
    void forceStateOnlySelect(const std::string& profileId) {
        std::vector<std::string> selected = readSelected();
        selected.push_back(profileId);
        std::string stateContent;
        for (const std::string& profile : selected) {
            stateContent += "Module: " + profile + "\n";
        }
        writeFile(stateFile(), stateContent);
    }

    // Hook that runs after a successfully applied invocation (models an
    // external tamper / malformed regeneration result).
    std::function<void()> afterApplyHook;

private:
    std::vector<std::string> readSelected() const {
        std::vector<std::string> selected;
        std::istringstream stream(readFile(stateFile()));
        std::string line;
        const std::string prefix = "Module: ";
        while (std::getline(stream, line)) {
            if (line.compare(0, prefix.size(), prefix) == 0) {
                selected.push_back(line.substr(prefix.size()));
            }
        }
        return selected;
    }

    void writeSelected(const std::vector<std::string>& selected) {
        std::string stateContent;
        for (const std::string& profile : selected) {
            stateContent += "Module: " + profile + "\n";
        }
        writeFile(stateFile(), stateContent);
        regenerateStack(selected);
    }

private:
    void apply(const Invocation& invocation) {
        std::vector<std::string> selected;
        {
            std::istringstream stream(readFile(stateFile()));
            std::string line;
            const std::string prefix = "Module: ";
            while (std::getline(stream, line)) {
                if (line.compare(0, prefix.size(), prefix) == 0) {
                    selected.push_back(line.substr(prefix.size()));
                }
            }
        }
        bool changed = false;
        if (invocation.flag == "--disable") {
            for (std::size_t index = 0; index < selected.size();) {
                if (selected[index] == invocation.profileId) {
                    selected.erase(selected.begin() + index);
                    changed = true;
                } else {
                    ++index;
                }
            }
        } else {
            bool found = false;
            for (const std::string& profile : selected) {
                if (profile == invocation.profileId) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                selected.push_back(invocation.profileId);
                changed = true;
            }
        }
        if (changed) {
            std::string stateContent;
            for (const std::string& profile : selected) {
                stateContent += "Module: " + profile + "\n";
            }
            writeFile(stateFile(), stateContent);
            regenerateStack(selected);
        }
    }

    void regenerateStack(const std::vector<std::string>& selected) const {
        // Deterministic generation order: foreign pwquality rule, FIC
        // quality (1024), FIC history consumer (1023), FIC history
        // initial (1022), stock pam_unix. Include lines carry the real
        // trailing space.
        bool quality = false;
        bool consumer = false;
        bool initial = false;
        for (const std::string& profile : selected) {
            if (profile == kFicPasswordQualityHookProfileId) {
                quality = true;
            } else if (profile == kFicPasswordHistoryHookProfileId) {
                consumer = true;
            } else if (profile == kFicPasswordHistoryInitialHookProfileId) {
                initial = true;
            }
        }
        std::string stack;
        if (isSelected(kStockPwqualityProfileId)) {
            stack += "password requisite pam_pwquality.so retry=3 \n";
        }
        if (quality) {
            stack += "password include fic-password-quality \n";
        }
        if (consumer) {
            stack += "password include fic-password-history \n";
        }
        if (initial) {
            stack += "password include fic-password-history-initial \n";
        }
        stack +=
            "password required pam_unix.so obscure use_authtok "
            "try_first_pass yescrypt \n";
        writeFile(tree.pamd() / "common-password", stack);
    }
};

// Full fake environment: pam.d tree, state directory, operational journal
// and a C2 transition executor over the fake native mutator.
struct TestEnvironment {
    TemporaryDirectory tree;
    MutationJournal journal{tree.path() / "journal.json"};
    FakeNativeMutator mutator{tree};
    fic::platform::PlatformExecutableResolver resolver{
        fic::platform::PlatformExecutables{}};
    std::unique_ptr<PamPasswordTopologyTransitionExecutor> executor;

    TestEnvironment() {
        std::filesystem::create_directories(tree.pamd());
        std::filesystem::create_directories(tree.state());
        // Package bootstrap: canonical neutral slot files.
        for (const auto& spec : PamManagedPasswordSlots::slots()) {
            writeFile(tree.pamd() / spec.fileName,
                PamManagedPasswordSlots::renderNeutral(spec));
        }
        // Stock state database and generated stack.
        writeFile(mutator.stateFile(), "Module: unix\n");
        writeFile(tree.pamd() / "common-password",
            "password required pam_unix.so obscure use_authtok "
            "try_first_pass yescrypt \n");
        std::string journalError;
        require(journal.initializeOrLoad(journalError),
            "journal initialization failed: " + journalError);
        PamPasswordTopologyExecutorOptions options;
        options.historyOptions =
            ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
        options.runner =
            [this](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                return mutator.run(executable, arguments, processOptions);
            };
        executor =
            std::make_unique<PamPasswordTopologyTransitionExecutor>(
                journal, resolver, options, tree.pamd(), tree.state());
    }

    PamPasswordTransitionResult run(bool quality, bool history,
                                    std::string& error) {
        PamPasswordTransitionResult result;
        require(!executor->transition(quality, history, result, error),
            "transition unexpectedly succeeded: " + error);
        return result;
    }

    PamPasswordTransitionResult runOk(bool quality, bool history) {
        PamPasswordTransitionResult result;
        std::string error;
        require(executor->transition(quality, history, result, error),
            "transition failed: " + error);
        return result;
    }

    PamPasswordTopologySnapshot inspect() {
        PamPasswordStateInspectionOptions options;
        options.configDirectory = tree.pamd();
        options.stateDirectory = tree.state();
        PamPasswordTopologySnapshot snapshot;
        std::string error;
        require(inspectPamPasswordTopology(options, journal, snapshot, error),
            "test inspection failed");
        return snapshot;
    }

    std::size_t appliedCount() const {
        std::size_t count = 0;
        for (const auto& record : journal.records()) {
            if (record.status == MutationStatus::Applied) {
                ++count;
            }
        }
        return count;
    }
};

// ---- E1-E12: success transitions ----

void testE1_noneToQuality() {
    TestEnvironment env;
    const auto result = env.runOk(true, false);
    require(result.success, "E1: success expected");
    require(result.changedSystemState, "E1: changed expected");
    require(result.topologyAfter == PamPasswordTopologyClass::FicQuality,
        "E1: FicQuality class expected");
    require(env.mutator.invocations.size() == 1 &&
            env.mutator.invocations[0].flag == "--enable" &&
            env.mutator.invocations[0].profileId ==
                kFicPasswordQualityHookProfileId,
        "E1: exactly one native enable of the quality profile expected");
    require(env.mutator.isSelected(kFicPasswordQualityHookProfileId),
        "E1: quality profile selected");
    require(env.mutator.hasInclude("fic-password-quality"),
        "E1: quality include generated");
    const auto snapshot = env.inspect();
    require(snapshot.ownership.ficQualityOwned,
        "E1: quality ownership proven");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Active,
        "E1: quality slot Active");
    require(env.appliedCount() == 1, "E1: one Applied journal record");
    // Idempotent re-apply: no new mutation, ownership stays.
    const auto again = env.runOk(true, false);
    require(again.success && !again.changedSystemState,
        "E1: idempotent re-apply is a proven no-op");
    require(env.mutator.invocations.size() == 1,
        "E1: idempotent re-apply performs no native call");
}

void testE2_noneToHistory() {
    TestEnvironment env;
    const auto result = env.runOk(false, true);
    require(result.success, "E2: success expected");
    require(result.topologyAfter ==
            PamPasswordTopologyClass::FicHistoryInitial,
        "E2: FicHistoryInitial class expected");
    require(env.mutator.invocations.size() == 1 &&
            env.mutator.invocations[0].profileId ==
                kFicPasswordHistoryInitialHookProfileId,
        "E2: history WITHOUT a producer attaches the INITIAL profile");
    const auto snapshot = env.inspect();
    require(snapshot.ownership.ficHistoryInitialOwned,
        "E2: history-initial ownership proven");
    require(!snapshot.selections.ficHistorySelected,
        "E2: consumer profile not selected");
    require(env.mutator.hasInclude("fic-password-history-initial"),
        "E2: initial include generated");
    require(!env.mutator.hasInclude("fic-password-history"),
        "E2: consumer include absent");
}

void testE3_noneToQualityPlusHistory() {
    TestEnvironment env;
    const auto result = env.runOk(true, true);
    require(result.success, "E3: success expected");
    require(result.topologyAfter ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "E3: FicQualityPlusFicHistory class expected");
    require(env.mutator.invocations.size() == 2 &&
            env.mutator.invocations[0].profileId ==
                kFicPasswordQualityHookProfileId &&
            env.mutator.invocations[1].profileId ==
                kFicPasswordHistoryHookProfileId,
        "E3: producer attach precedes the consumer attach");
    const auto snapshot = env.inspect();
    require(snapshot.ownership.ficQualityOwned &&
            snapshot.ownership.ficHistoryOwned,
        "E3: both ownerships proven");
    require(!snapshot.ownership.ficHistoryInitialOwned,
        "E3: history-initial not owned");
    require(env.appliedCount() == 2, "E3: two Applied records");
}

void testE4_qualityToNone() {
    TestEnvironment env;
    env.runOk(true, false);
    const auto result = env.runOk(false, false);
    require(result.success, "E4: success expected");
    require(result.topologyAfter == PamPasswordTopologyClass::None,
        "E4: None class expected");
    require(env.mutator.invocations.size() == 2 &&
            env.mutator.invocations[1].flag == "--disable" &&
            env.mutator.invocations[1].profileId ==
                kFicPasswordQualityHookProfileId,
        "E4: detach removes the selection before neutralizing the slot");
    require(!env.mutator.isSelected(kFicPasswordQualityHookProfileId),
        "E4: quality deselected");
    require(!env.mutator.hasInclude("fic-password-quality"),
        "E4: quality include absent");
    const auto snapshot = env.inspect();
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "E4: quality slot Neutral");
    require(!snapshot.ownership.ficQualityOwned, "E4: no ownership");
    require(env.appliedCount() == 0,
        "E4: the activation record was RolledBack");
}

void testE5_historyToNone() {
    TestEnvironment env;
    env.runOk(false, true);
    const auto result = env.runOk(false, false);
    require(result.success, "E5: success expected");
    require(result.topologyAfter == PamPasswordTopologyClass::None,
        "E5: None class expected");
    const auto snapshot = env.inspect();
    require(snapshot.historyInitialSlotState ==
            ManagedPasswordSlotState::Neutral,
        "E5: history-initial slot Neutral");
    require(env.appliedCount() == 0, "E5: record RolledBack");
}

void testE6_qualityPlusHistoryToQuality() {
    TestEnvironment env;
    env.runOk(true, true);
    const auto result = env.runOk(true, false);
    require(result.success, "E6: success expected");
    require(result.topologyAfter == PamPasswordTopologyClass::FicQuality,
        "E6: FicQuality class expected");
    require(env.mutator.invocations.size() == 3 &&
            env.mutator.invocations[2].flag == "--disable" &&
            env.mutator.invocations[2].profileId ==
                kFicPasswordHistoryHookProfileId,
        "E6: only the consumer profile is detached");
    const auto snapshot = env.inspect();
    require(snapshot.ownership.ficQualityOwned &&
            !snapshot.ownership.ficHistoryOwned,
        "E6: quality ownership kept, history released");
    require(snapshot.historySlotState == ManagedPasswordSlotState::Neutral,
        "E6: history slot Neutral");
    require(!env.mutator.hasInclude("fic-password-history"),
        "E6: history include absent");
}

void testE7_qualityPlusHistoryToHistory() {
    // §15 variant switch: consumer detach, quality detach, initial attach.
    TestEnvironment env;
    env.runOk(true, true);
    const auto result = env.runOk(false, true);
    require(result.success, "E7: success expected");
    require(result.topologyAfter ==
            PamPasswordTopologyClass::FicHistoryInitial,
        "E7: FicHistoryInitial class expected");
    require(env.mutator.invocations.size() == 5 &&
            env.mutator.invocations[2].profileId ==
                kFicPasswordHistoryHookProfileId &&
            env.mutator.invocations[3].profileId ==
                kFicPasswordQualityHookProfileId &&
            env.mutator.invocations[4].profileId ==
                kFicPasswordHistoryInitialHookProfileId,
        "E7: consumer detach -> quality detach -> initial attach");
    const auto snapshot = env.inspect();
    require(snapshot.ownership.ficHistoryInitialOwned &&
            !snapshot.ownership.ficQualityOwned &&
            !snapshot.ownership.ficHistoryOwned,
        "E7: initial ownership only");
    require(env.appliedCount() == 1, "E7: one Applied record");
}

void testE8_historyToQualityPlusHistory() {
    // §15 variant switch: initial detach, quality attach, consumer attach.
    TestEnvironment env;
    env.runOk(false, true);
    const auto result = env.runOk(true, true);
    require(result.success, "E8: success expected");
    require(result.topologyAfter ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "E8: FicQualityPlusFicHistory class expected");
    require(env.mutator.invocations.size() == 4 &&
            env.mutator.invocations[1].profileId ==
                kFicPasswordHistoryInitialHookProfileId &&
            env.mutator.invocations[2].profileId ==
                kFicPasswordQualityHookProfileId &&
            env.mutator.invocations[3].profileId ==
                kFicPasswordHistoryHookProfileId,
        "E8: initial detach -> quality attach -> consumer attach");
    const auto snapshot = env.inspect();
    require(!snapshot.ownership.ficHistoryInitialOwned,
        "E8: history-initial released");
    require(env.mutator.invocations[2].flag == "--enable" &&
            env.mutator.invocations[2].profileId ==
                kFicPasswordQualityHookProfileId,
        "E8: producer attach precedes the consumer attach");
}

void testE9_qualityToQualityPlusHistory() {
    TestEnvironment env;
    env.runOk(true, false);
    const auto result = env.runOk(true, true);
    require(result.success, "E9: success expected");
    require(result.topologyAfter ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "E9: FicQualityPlusFicHistory class expected");
    require(env.mutator.invocations.size() == 2 &&
            env.mutator.invocations[1].profileId ==
                kFicPasswordHistoryHookProfileId,
        "E9: only the consumer attaches");
}

void testE10_foreignQualityRequestedQualityIsNoOp() {
    // §30: pre-existing foreign quality satisfies the request without any
    // FIC mutation and without claiming ownership.
    TestEnvironment env;
    env.mutator.forceSelect(kStockPwqualityProfileId);
    const auto result = env.runOk(true, false);
    require(result.success, "E10: success expected");
    require(!result.changedSystemState, "E10: no mutation expected");
    require(env.mutator.invocations.empty(),
        "E10: no native call expected");
    const auto snapshot = env.inspect();
    require(snapshot.foreignQualityProducer, "E10: foreign producer proven");
    require(!snapshot.selections.ficQualitySelected,
        "E10: FIC quality not selected");
    require(!snapshot.ownership.ficQualityOwned,
        "E10: no FIC quality ownership claimed");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "E10: quality slot stays Neutral");
    require(result.topologyAfter == PamPasswordTopologyClass::ForeignQuality,
        "E10: ForeignQuality class expected");
}

void testE11_foreignQualityPlusHistory() {
    // §31: only the history consumer becomes FIC-owned; the foreign
    // quality producer stays untouched.
    TestEnvironment env;
    env.mutator.forceSelect(kStockPwqualityProfileId);
    const auto result = env.runOk(true, true);
    require(result.success, "E11: success expected");
    require(env.mutator.invocations.size() == 1 &&
            env.mutator.invocations[0].profileId ==
                kFicPasswordHistoryHookProfileId,
        "E11: only the history consumer attaches");
    const auto snapshot = env.inspect();
    require(snapshot.foreignQualityProducer,
        "E11: foreign producer preserved");
    require(!snapshot.selections.ficQualitySelected,
        "E11: FIC quality not selected");
    require(snapshot.ownership.ficHistoryOwned,
        "E11: history ownership proven");
    require(result.topologyAfter ==
            PamPasswordTopologyClass::ForeignQualityPlusFicHistory,
        "E11: ForeignQualityPlusFicHistory class expected");
    // Disable keeps the stock producer (§31).
    const auto disable = env.runOk(true, false);
    require(disable.success, "E11: disable success expected");
    require(env.mutator.isSelected(kStockPwqualityProfileId) &&
            env.mutator.hasInclude("fic-password-history") == false,
        "E11: stock pwquality stays, FIC history gone");
}

void testE12_foreignAddedDuringFicQualityDisable() {
    // §32: a foreign stock pwquality profile appears while FIC quality is
    // owned. The disable removes ONLY the FIC-owned selection; the
    // foreign producer is preserved.
    TestEnvironment env;
    env.runOk(true, false);
    env.mutator.forceSelect(kStockPwqualityProfileId);
    const auto result = env.runOk(false, false);
    require(result.success, "E12: success expected");
    require(result.topologyAfter == PamPasswordTopologyClass::ForeignQuality,
        "E12: ForeignQuality class expected");
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "E12: foreign pwquality preserved");
    const auto snapshot = env.inspect();
    require(snapshot.foreignQualityProducer,
        "E12: foreign producer proven");
    require(!snapshot.selections.ficQualitySelected,
        "E12: FIC quality detached");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "E12: quality slot Neutral");
}

// ---- F1-F10: failure matrix ----

void testF1_slotWriteFailsBeforeNativeMutation() {
    TestEnvironment env;
    env.executor->setQualitySlotFaultHooksForTests(
        [](std::size_t) { return false; }, nullptr);
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F1: failure expected");
    require(env.mutator.invocations.empty(),
        "F1: no native pam-auth-update call may happen");
    require(!result.changedSystemState,
        "F1: the failed write is fully compensated (no change)");
    require(env.appliedCount() == 0, "F1: journal not Applied");
    const auto snapshot = env.inspect();
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "F1: quality slot back to Neutral");
}

void testF2_attachNativeFailsNoMutation() {
    TestEnvironment env;
    env.mutator.behavior = [](std::size_t, const auto&) { return 3; };
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F2: failure expected");
    require(result.compensated && result.compensatedStateProven,
        "F2: compensation proves the pre-transition state: " + error);
    require(env.appliedCount() == 0, "F2: no Applied record remains");
    const auto snapshot = env.inspect();
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "F2: quality slot Neutral");
    require(!env.mutator.isSelected(kFicPasswordQualityHookProfileId),
        "F2: quality not selected");
}

void testF3_attachNativeFailsPartialMutation() {
    TestEnvironment env;
    // rc != 0 with a PARTIAL mutation: the state record lands, the
    // generated stack regeneration does not.
    env.mutator.behavior = [&](std::size_t number, const auto& invocation) {
        if (number == 1 &&
            invocation.profileId == kFicPasswordQualityHookProfileId) {
            env.mutator.forceStateOnlySelect(
                kFicPasswordQualityHookProfileId);
            return 3;
        }
        return 0;
    };
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F3: failure expected");
    require(result.compensated && result.compensatedStateProven,
        "F3: compensation removes the partial selection");
    require(!env.mutator.isSelected(kFicPasswordQualityHookProfileId),
        "F3: partial selection removed");
    const auto snapshot = env.inspect();
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "F3: quality slot Neutral");
    require(env.appliedCount() == 0, "F3: no Applied record remains");
}

void testF4_attachRcZeroMalformedResult() {
    TestEnvironment env;
    // rc = 0 with a malformed resulting state: the include disappears
    // while the selection stays (incoherent regeneration result).
    env.mutator.afterApplyHook = [&env]() {
        std::string stack = readFile(
            env.tree.pamd() / "common-password");
        std::string filtered;
        std::istringstream stream(stack);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("include fic-password-quality") ==
                std::string::npos) {
                filtered += line + "\n";
            }
        }
        writeFile(env.tree.pamd() / "common-password", filtered);
    };
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F4: failure expected (rc=0 is not trusted)");
    require(result.compensated && result.compensatedStateProven,
        "F4: compensation proves the pre-transition state");
    require(!env.mutator.isSelected(kFicPasswordQualityHookProfileId),
        "F4: selection removed by compensation");
    require(env.appliedCount() == 0, "F4: no Applied record remains");
}

void testF5_secondActionFailsAfterFirstApplied() {
    TestEnvironment env;
    env.mutator.behavior = [](std::size_t number, const auto&) {
        return number == 2 ? 5 : 0;
    };
    std::string error;
    const auto result = env.run(true, true, error);
    require(!result.success, "F5: failure expected");
    require(result.compensated && result.compensatedStateProven,
        "F5: the full pre-transition topology is restored");
    require(!env.mutator.isSelected(kFicPasswordQualityHookProfileId) &&
            !env.mutator.isSelected(kFicPasswordHistoryHookProfileId),
        "F5: both selections removed by compensation");
    const auto snapshot = env.inspect();
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral &&
            snapshot.historySlotState == ManagedPasswordSlotState::Neutral,
        "F5: both slots Neutral");
    require(env.appliedCount() == 0, "F5: no Applied records remain");
}

void testF6_compensationNativeFailsStops() {
    TestEnvironment env;
    env.mutator.behavior = [](std::size_t number, const auto& invocation) {
        if (number == 2) {
            // Second attach fails without mutation.
            return 5;
        }
        if (invocation.flag == "--disable") {
            // Compensation disable fails: fail-fast STOP.
            return 7;
        }
        return 0;
    };
    std::string error;
    const auto result = env.run(true, true, error);
    require(!result.success, "F6: failure expected");
    require(result.compensated && !result.compensatedStateProven,
        "F6: compensation did NOT prove the restoration");
    require(error.find("NOT proven restored") != std::string::npos,
        "F6: diagnostic must name the unproven restoration");
    // The quality identity was still selected when compensation stopped.
    require(env.mutator.isSelected(kFicPasswordQualityHookProfileId),
        "F6: quality selection preserved after the fail-fast stop");
}

void testF7_compensationRcZeroMalformedStops() {
    TestEnvironment env;
    bool tamperNext = false;
    env.mutator.behavior = [&](std::size_t number, const auto& invocation) {
        if (number == 2) {
            return 5;  // second attach fails without mutation
        }
        if (invocation.flag == "--disable") {
            tamperNext = true;  // compensation will run next
        }
        return 0;
    };
    env.mutator.afterApplyHook = [&env, &tamperNext]() {
        if (tamperNext) {
            // rc = 0 but malformed: the disable "succeeded" while the
            // Module record stays in the state database.
            env.mutator.forceStateOnlySelect(
                kFicPasswordQualityHookProfileId);
            tamperNext = false;
        }
    };
    std::string error;
    const auto result = env.run(true, true, error);
    require(!result.success, "F7: failure expected");
    require(result.compensated && !result.compensatedStateProven,
        "F7: compensation did NOT prove the restoration");
    require(error.find("NOT proven restored") != std::string::npos,
        "F7: diagnostic must name the unproven restoration");
}

void testF8_foreignDriftMidTransitionAbortsAndPreserves() {
    TestEnvironment env;
    env.mutator.behavior = [&env](std::size_t number, const auto&) {
        if (number == 2) {
            // Foreign stock pwquality appears while the transition runs.
            env.mutator.forceSelect(kStockPwqualityProfileId);
        }
        return 0;
    };
    std::string error;
    const auto result = env.run(true, true, error);
    require(!result.success, "F8: the stale plan must abort");
    require(result.compensated && result.compensatedStateProven,
        "F8: FIC-owned changes are compensated");
    // Foreign state preserved, never claimed or removed.
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "F8: foreign pwquality selection preserved");
    const auto snapshot = env.inspect();
    require(snapshot.foreignQualityProducer,
        "F8: foreign producer proven");
    require(!snapshot.selections.ficQualitySelected &&
            !snapshot.selections.ficHistorySelected &&
            !snapshot.selections.ficHistoryInitialSelected,
        "F8: FIC selections fully compensated");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral &&
            snapshot.historySlotState == ManagedPasswordSlotState::Neutral,
        "F8: FIC slots fully compensated");
}

void testF9_selectedButUnownedIdentityIsNeverTouched() {
    TestEnvironment env;
    // Physically selected FIC quality with a canonical Active slot but NO
    // journal provenance (an administrator-selected or orphaned profile).
    std::string body;
    std::string renderError;
    require(PamManagedPasswordSlots::renderActiveQuality(
                777, body, renderError),
        "F9: render failed");
    writeFile(env.tree.pamd() / "fic-password-quality", body);
    env.mutator.forceSelect(kFicPasswordQualityHookProfileId);
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F9: fail closed expected");
    require(env.mutator.invocations.empty(),
        "F9: no destructive mutation may happen");
    require(!result.changedSystemState, "F9: no system change");
    require(error.find("ownership") != std::string::npos,
        "F9: diagnostic names the ownership violation");
}

void testF10_noOpDesiredButPhysicalProofFails() {
    TestEnvironment env;
    env.mutator.forceSelect(kStockPwqualityProfileId);
    // Break the physical proof: remove the stock pam_unix rule.
    std::string stack = readFile(env.tree.pamd() / "common-password");
    std::string filtered;
    std::istringstream stream(stack);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.find("pam_unix.so") == std::string::npos) {
            filtered += line + "\n";
        }
    }
    writeFile(env.tree.pamd() / "common-password", filtered);
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F10: fail closed expected");
    require(env.mutator.invocations.empty(), "F10: no mutation");
    require(!result.changedSystemState, "F10: no system change");
}

void testF11_journalCompletionFailsAfterSlotWrite() {
    // Partial-state propagation regression: the journal Prepared ->
    // Applied commit fails AFTER the physical slot write persisted and
    // was freshly proven. Before the fix the executor never learned the
    // exact outstanding mutation id, skipped compensateC2ActiveSlot() and
    // left "Active slot + Prepared record" behind. The compensation must
    // neutralize the exact slot, discard the exact Prepared record and
    // prove the pre-transition state again.
    TestEnvironment env;
    env.executor->setQualityJournalCompletionFaultHookForTests(
        [] { return false; });
    std::string error;
    const auto result = env.run(true, false, error);
    require(!result.success, "F11: failure expected");
    // Invariant: no native call before journal ownership proof — the
    // slot activation never reached a caller-visible valid state.
    require(env.mutator.invocations.empty(),
        "F11: no native pam-auth-update call may happen");
    require(result.compensated && result.compensatedStateProven,
        "F11: compensation proves the pre-transition state: " + error);
    require(error.find("C2 PAM topology NOT proven restored") ==
            std::string::npos,
        "F11: diagnostic must be a normal compensated failure");
    // The exact Prepared activation must be resolved: no Applied
    // ownership, no outstanding record, no outstanding marker id.
    require(env.appliedCount() == 0, "F11: no Applied record remains");
    const auto snapshot = env.inspect();
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "F11: quality slot neutralized by the exact-id compensation");
    require(snapshot.qualitySlotMutationId == 0,
        "F11: no outstanding quality mutation id");
    require(!snapshot.selections.ficQualitySelected,
        "F11: quality profile unselected");
    require(!snapshot.ownership.ficQualityOwned,
        "F11: no Applied ownership remains");
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::None,
        "F11: final topology restored to the original None class");
}

} // namespace

int main() {
    struct NamedTest {
        const char* name;
        void (*fn)();
    };
    const NamedTest tests[] = {
        {"E1_noneToQuality", testE1_noneToQuality},
        {"E2_noneToHistory", testE2_noneToHistory},
        {"E3_noneToQualityPlusHistory", testE3_noneToQualityPlusHistory},
        {"E4_qualityToNone", testE4_qualityToNone},
        {"E5_historyToNone", testE5_historyToNone},
        {"E6_qualityPlusHistoryToQuality",
            testE6_qualityPlusHistoryToQuality},
        {"E7_qualityPlusHistoryToHistory",
            testE7_qualityPlusHistoryToHistory},
        {"E8_historyToQualityPlusHistory",
            testE8_historyToQualityPlusHistory},
        {"E9_qualityToQualityPlusHistory",
            testE9_qualityToQualityPlusHistory},
        {"E10_foreignQualityRequestedQualityIsNoOp",
            testE10_foreignQualityRequestedQualityIsNoOp},
        {"E11_foreignQualityPlusHistory", testE11_foreignQualityPlusHistory},
        {"E12_foreignAddedDuringFicQualityDisable",
            testE12_foreignAddedDuringFicQualityDisable},
        {"F1_slotWriteFailsBeforeNativeMutation",
            testF1_slotWriteFailsBeforeNativeMutation},
        {"F2_attachNativeFailsNoMutation",
            testF2_attachNativeFailsNoMutation},
        {"F3_attachNativeFailsPartialMutation",
            testF3_attachNativeFailsPartialMutation},
        {"F4_attachRcZeroMalformedResult",
            testF4_attachRcZeroMalformedResult},
        {"F5_secondActionFailsAfterFirstApplied",
            testF5_secondActionFailsAfterFirstApplied},
        {"F6_compensationNativeFailsStops",
            testF6_compensationNativeFailsStops},
        {"F7_compensationRcZeroMalformedStops",
            testF7_compensationRcZeroMalformedStops},
        {"F8_foreignDriftMidTransitionAbortsAndPreserves",
            testF8_foreignDriftMidTransitionAbortsAndPreserves},
        {"F9_selectedButUnownedIdentityIsNeverTouched",
            testF9_selectedButUnownedIdentityIsNeverTouched},
        {"F10_noOpDesiredButPhysicalProofFails",
            testF10_noOpDesiredButPhysicalProofFails},
        {"F11_journalCompletionFailsAfterSlotWrite",
            testF11_journalCompletionFailsAfterSlotWrite},
    };
    for (const NamedTest& test : tests) {
        try {
            test.fn();
        } catch (const std::exception& exception) {
            std::cerr << "FAIL " << test.name << ": " << exception.what()
                      << std::endl;
            return 1;
        }
        std::cout << "PASS " << test.name << std::endl;
    }
    std::cout << "All C2 password topology transition executor tests passed"
              << std::endl;
    return 0;
}

