#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"
#include "modules/oss/desktop_environment/KdeSessionTopology.h"
#include "modules/oss/desktop_environment/policies/OSS_absence_of_uncontrolled_desktop_environments.h"
#include "policy/registry/PolicyRegistry.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <unistd.h>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct Scope : ControlledDesktopEnvironmentScope {
    DesktopEnvironmentSet value;
    bool controlledDesktopEnvironments(DesktopEnvironmentSet& out,
                                       std::string& error) override {
        out = value; error.clear(); return true;
    }
};

struct Inventory : GraphicalSessionInventory {
    std::vector<ClassifiedGraphicalSession> value;
    bool currentSessions(std::vector<ClassifiedGraphicalSession>& out,
                         std::string& error) override {
        out = value; error.clear(); return true;
    }
};

class CapabilityPolicy final : public Policy {
public:
    CapabilityPolicy() {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = "capability";
    }
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::SessionAware};
    }
};

class TestPolicy final : public SessionAwareDesktopEnvironmentPolicy {
public:
    TestPolicy(Scope& scope, std::shared_ptr<Inventory> inventory)
        : SessionAwareDesktopEnvironmentPolicy(scope, inventory) {
        policyName = "test_session_policy";
    }
    EnforcementMode mode = EnforcementMode::SessionOnly;
    bool reconcileOk = true;
    bool prepareOk = true;
    int reconciled = 0;
    std::vector<std::string> operations;
    std::vector<KdeSessionTopology> kdeTopologies;
    std::vector<std::string> targetIds;
    std::vector<std::size_t> snapshotSizes;
    std::vector<bool> inventoryCompleteFlags;
protected:
    bool prepare(std::string& error) override {
        error = prepareOk ? "" : "session preparation failure";
        return prepareOk;
    }
    bool relevantTo(DesktopEnvironmentKind) const override { return true; }
    EnforcementMode modeFor(DesktopEnvironmentKind) const override { return mode; }
    bool reconcileControlledSession(const SessionReconcileContext& context,
                                    std::string& error) override {
        ++reconciled; operations.push_back("runtime");
        kdeTopologies.push_back(determineKdeSessionTopology(
            context.target, context.sessions,
            context.inventoryComplete).state);
        targetIds.push_back(context.target.session.id);
        snapshotSizes.push_back(context.sessions.size());
        inventoryCompleteFlags.push_back(context.inventoryComplete);
        if (!reconcileOk) error = "session failure"; return reconcileOk;
    }
};

ClassifiedGraphicalSession session(DesktopEnvironmentKind desktop) {
    ClassifiedGraphicalSession value;
    value.session.id = "7";
    value.session.uid = 1000;
    value.desktop = desktop;
    return value;
}

PolicyGlobalEnforcementResult globalResult(bool verified) {
    return {true, verified, {"backend"},
            verified ? "" : "backend failure"};
}

SessionReconcileContext contextFor(
    const ClassifiedGraphicalSession& target,
    const std::vector<ClassifiedGraphicalSession>& snapshot,
    bool inventoryComplete) {
    return {target, snapshot, inventoryComplete};
}

void initializeRuntime() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-session-policy-test-" + std::to_string(::getpid()));
    fs::create_directories(root / "config");
    fs::create_directories(root / "log");
    std::ofstream(root / "config/OSS.conf") << "_schema_version=1\n";
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    paths.runtimeDir = root / "run";
    paths.dataDir = root / "data";
    paths.defaultConfigDir = root / "defaults";
    paths.commandHashFile = root / "data/hash";
    paths.deviceDatabaseFile = root / "data/db";
    paths.deviceDatabaseLockFile = root / "log/db.lock";
    paths.lockDebugLogFile = root / "log/lock.log";
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error.c_str());
}
}

int main() {
    initializeRuntime();
    Scope scope;
    auto inventory = std::make_shared<Inventory>();

    TestPolicy unconfigured(scope, inventory);
    require(!unconfigured.apply(), "empty controlled scope succeeded");

    scope.value = {DesktopEnvironmentKind::Gnome};
    inventory->value = {session(DesktopEnvironmentKind::Lxqt)};
    TestPolicy ignored(scope, inventory);
    require(ignored.apply() && ignored.reconciled == 0,
            "uncontrolled desktop was not ignored");

    auto unclassified = session(DesktopEnvironmentKind::Unknown);
    unclassified.classificationError = "unknown desktop";
    inventory->value = {unclassified};
    TestPolicy ignoredUnknown(scope, inventory);
    require(ignoredUnknown.apply() && ignoredUnknown.reconciled == 0,
            "unclassifiable session failed an ordinary policy apply");
    const SessionReconcileResult unknownResult =
        ignoredUnknown.reconcileSession(
            contextFor(unclassified, inventory->value, true),
            globalResult(true));
    require(unknownResult.status == SessionReconcileStatus::NotApplicable &&
            ignoredUnknown.reconciled == 0,
            "unclassifiable session failed targeted ordinary reconciliation");

    inventory->value.clear();
    scope.value = {DesktopEnvironmentKind::Lxqt};
    TestPolicy unsupported(scope, inventory);
    unsupported.mode = EnforcementMode::Unsupported;
    require(!unsupported.apply(), "controlled unsupported backend succeeded");

    scope.value = {DesktopEnvironmentKind::Gnome};
    TestPolicy deferred(scope, inventory);
    require(deferred.apply() && deferred.reconciled == 0,
            "zero-session SessionOnly apply was not deferred success");
    inventory->value = {session(DesktopEnvironmentKind::Gnome)};
    TestPolicy failedSession(scope, inventory);
    failedSession.reconcileOk = false;
    require(!failedSession.apply(), "SessionOnly session failure was ignored");

    TestPolicy global(scope, inventory);
    global.mode = EnforcementMode::MandatoryGlobal;
    global.reconcileOk = false;
    global.setGlobalEnforcementResults(
        {{DesktopEnvironmentKind::Gnome, globalResult(true)}});
    require(global.apply(), "verified global enforcement was defeated by runtime warning");
    require(global.operations == std::vector<std::string>{"runtime"},
            "normal apply performed policy-level global enforcement");

    TestPolicy normalPrepareWarning(scope, inventory);
    normalPrepareWarning.mode = EnforcementMode::MandatoryGlobal;
    normalPrepareWarning.prepareOk = false;
    normalPrepareWarning.setGlobalEnforcementResults(
        {{DesktopEnvironmentKind::Gnome, globalResult(true)}});
    require(normalPrepareWarning.apply() && normalPrepareWarning.reconciled == 0,
            "session preparation invalidated verified global state on normal apply");

    TestPolicy normalGlobalFailure(scope, inventory);
    normalGlobalFailure.mode = EnforcementMode::MandatoryGlobal;
    normalGlobalFailure.setGlobalEnforcementResults(
        {{DesktopEnvironmentKind::Gnome, globalResult(false)}});
    require(!normalGlobalFailure.apply() && normalGlobalFailure.reconciled == 0,
            "normal apply ignored relevant global failure");

    TestPolicy normalMissingCoverage(scope, inventory);
    normalMissingCoverage.mode = EnforcementMode::MandatoryGlobal;
    require(!normalMissingCoverage.apply() && normalMissingCoverage.reconciled == 0,
            "normal apply accepted missing global coverage");

    TestPolicy normalSessionOnly(scope, inventory);
    normalSessionOnly.setGlobalEnforcementResults(
        {{DesktopEnvironmentKind::Gnome, globalResult(false)}});
    require(normalSessionOnly.apply() && normalSessionOnly.reconciled == 1,
            "SessionOnly normal apply depended on global failure");

    scope.value = {DesktopEnvironmentKind::Kde};
    inventory->value = {session(DesktopEnvironmentKind::Kde),
                        session(DesktopEnvironmentKind::Kde)};
    inventory->value[1].session.id = "8";
    TestPolicy ambiguousKde(scope, inventory);
    require(ambiguousKde.apply() &&
                ambiguousKde.kdeTopologies ==
                    std::vector<KdeSessionTopology>{
                        KdeSessionTopology::Ambiguous,
                        KdeSessionTopology::Ambiguous},
            "same-UID KDE session ambiguity was not propagated");

    // Regression: KDE + unclassified same-UID сессия — topology Unknown,
    // а не доказанная unique topology.
    {
        auto unclassifiedNeighbour = session(DesktopEnvironmentKind::Unknown);
        unclassifiedNeighbour.classificationError = "agent query failed";
        unclassifiedNeighbour.session.id = "8";
        inventory->value = {session(DesktopEnvironmentKind::Kde),
                            unclassifiedNeighbour};
        TestPolicy unknownTopology(scope, inventory);
        require(unknownTopology.apply() &&
                    unknownTopology.kdeTopologies ==
                        std::vector<KdeSessionTopology>{
                            KdeSessionTopology::Unknown},
                "KDE + unclassified same-UID session did not yield "
                "Unknown topology");
    }
    // Чужая unknown сессия другого UID не влияет на topology target UID.
    {
        auto foreign = session(DesktopEnvironmentKind::Unknown);
        foreign.classificationError = "agent query failed";
        foreign.session.uid = 1001;
        foreign.session.id = "8";
        inventory->value = {session(DesktopEnvironmentKind::Kde), foreign};
        TestPolicy foreignUnknown(scope, inventory);
        require(foreignUnknown.apply() &&
                    foreignUnknown.kdeTopologies ==
                        std::vector<KdeSessionTopology>{
                            KdeSessionTopology::Unique},
                "foreign-UID unknown session changed KDE topology");
    }
    // Достоверно известный non-KDE same-UID сосед — не ambiguity.
    {
        inventory->value = {session(DesktopEnvironmentKind::Kde),
                            session(DesktopEnvironmentKind::Gnome)};
        TestPolicy gnomeNeighbour(scope, inventory);
        require(gnomeNeighbour.apply() &&
                    gnomeNeighbour.kdeTopologies ==
                        std::vector<KdeSessionTopology>{
                            KdeSessionTopology::Unique},
                "known non-KDE same-UID session was treated as ambiguity");
    }
    // KDE + KDE + GNOME одного UID — Ambiguous; non-KDE сосед не маскирует.
    {
        auto secondKde = session(DesktopEnvironmentKind::Kde);
        secondKde.session.id = "8";
        inventory->value = {session(DesktopEnvironmentKind::Kde), secondKde,
                            session(DesktopEnvironmentKind::Gnome)};
        TestPolicy kdeKdeGnome(scope, inventory);
        require(kdeKdeGnome.apply() &&
                    kdeKdeGnome.kdeTopologies ==
                        std::vector<KdeSessionTopology>{
                            KdeSessionTopology::Ambiguous,
                            KdeSessionTopology::Ambiguous},
                "known non-KDE session masked multiple KDE sessions");
    }

    // Targeted session_ready path: тот же reconciliation контракт —
    // context.target + snapshot + inventoryComplete, без mutation target.
    {
        scope.value = {DesktopEnvironmentKind::Kde};
        auto queued = session(DesktopEnvironmentKind::Kde);
        std::vector<ClassifiedGraphicalSession> current = {queued};

        TestPolicy targetedUnique(scope, inventory);
        require(targetedUnique.reconcileSession(
                        contextFor(queued, current, true),
                        globalResult(true)).status ==
                    SessionReconcileStatus::SessionOnlyConverged &&
                targetedUnique.kdeTopologies ==
                    std::vector<KdeSessionTopology>{
                        KdeSessionTopology::Unique} &&
                targetedUnique.targetIds == std::vector<std::string>{"7"} &&
                targetedUnique.snapshotSizes == std::vector<std::size_t>{1} &&
                targetedUnique.inventoryCompleteFlags ==
                    std::vector<bool>{true},
            "targeted reconciliation did not receive the real snapshot");

        // inventoryComplete=false доходит как есть и fail closed в Unknown,
        // а не в default/fake topology.
        TestPolicy targetedIncomplete(scope, inventory);
        require(targetedIncomplete.reconcileSession(
                        contextFor(queued, current, false),
                        globalResult(true)).status ==
                    SessionReconcileStatus::SessionOnlyConverged &&
                targetedIncomplete.kdeTopologies ==
                    std::vector<KdeSessionTopology>{
                        KdeSessionTopology::Unknown},
            "inventoryComplete=false did not fail closed on targeted path");

        // Replacement same-UID KDE session не маскирует exact target.
        auto replacement = session(DesktopEnvironmentKind::Kde);
        replacement.session.id = "8";
        std::vector<ClassifiedGraphicalSession> replaced{replacement};
        TestPolicy targetedReplacement(scope, inventory);
        require(targetedReplacement.reconcileSession(
                        contextFor(queued, replaced, true),
                        globalResult(true)).status ==
                    SessionReconcileStatus::SessionOnlyConverged &&
                targetedReplacement.kdeTopologies ==
                    std::vector<KdeSessionTopology>{
                        KdeSessionTopology::Unknown},
            "replacement same-UID KDE session masqueraded as the target");
    }

    scope.value = {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Kde};
    inventory->value = {session(DesktopEnvironmentKind::Gnome),
                        session(DesktopEnvironmentKind::Kde)};
    TestPolicy mixedGlobal(scope, inventory);
    mixedGlobal.mode = EnforcementMode::MandatoryGlobal;
    mixedGlobal.setGlobalEnforcementResults({
        {DesktopEnvironmentKind::Gnome, globalResult(true)},
        {DesktopEnvironmentKind::Kde, globalResult(false)}});
    require(!mixedGlobal.apply() && mixedGlobal.reconciled == 1,
            "mixed-DE global results were collapsed into one status");
    scope.value = {DesktopEnvironmentKind::Gnome};
    inventory->value = {session(DesktopEnvironmentKind::Gnome)};

    const auto graphical = session(DesktopEnvironmentKind::Gnome);
    TestPolicy targetedGlobal(scope, inventory);
    targetedGlobal.mode = EnforcementMode::MandatoryGlobal;
    const SessionReconcileResult targetedGlobalResult =
        targetedGlobal.reconcileSession(
            contextFor(graphical, inventory->value, true),
            globalResult(true));
    require(targetedGlobalResult.status ==
                SessionReconcileStatus::MandatoryGlobalConverged,
            "targeted MandatoryGlobal reconciliation failed");
    require(targetedGlobal.operations == std::vector<std::string>{"runtime"},
            "targeted path performed policy-level global enforcement");

    TestPolicy failedGlobal(scope, inventory);
    failedGlobal.mode = EnforcementMode::MandatoryGlobal;
    const SessionReconcileResult failedGlobalResult =
        failedGlobal.reconcileSession(
            contextFor(graphical, inventory->value, true),
            globalResult(false));
    require(failedGlobalResult.status ==
                SessionReconcileStatus::GlobalEnforcementFailed &&
                failedGlobalResult.diagnostic == "backend failure" &&
                failedGlobal.reconciled == 0,
            "backend global failure did not stop targeted runtime convergence");

    TestPolicy targetedGlobalWarning(scope, inventory);
    targetedGlobalWarning.mode = EnforcementMode::MandatoryGlobal;
    targetedGlobalWarning.reconcileOk = false;
    require(targetedGlobalWarning.reconcileSession(
                contextFor(graphical, inventory->value, true),
                globalResult(true)).status ==
                SessionReconcileStatus::MandatoryGlobalRuntimeWarning,
            "verified global state did not preserve authoritative success");

    TestPolicy targetedPrepareWarning(scope, inventory);
    targetedPrepareWarning.mode = EnforcementMode::MandatoryGlobal;
    targetedPrepareWarning.prepareOk = false;
    require(targetedPrepareWarning.reconcileSession(
                contextFor(graphical, inventory->value, true),
                globalResult(true)).status ==
                SessionReconcileStatus::MandatoryGlobalRuntimeWarning,
            "session preparation failure invalidated verified global state");

    TestPolicy targetedSessionFailure(scope, inventory);
    targetedSessionFailure.reconcileOk = false;
    require(targetedSessionFailure.reconcileSession(
                contextFor(graphical, inventory->value, true),
                globalResult(false)).status ==
                SessionReconcileStatus::SessionOnlyFailed,
            "targeted SessionOnly failure was accepted");

    TestPolicy targetedUnsupported(scope, inventory);
    targetedUnsupported.mode = EnforcementMode::Unsupported;
    require(targetedUnsupported.reconcileSession(
                contextFor(graphical, inventory->value, true),
                globalResult(false)).status ==
                SessionReconcileStatus::Unsupported,
            "targeted unsupported desktop was accepted");

    scope.value = {DesktopEnvironmentKind::Kde};
    TestPolicy targetedNotApplicable(scope, inventory);
    require(targetedNotApplicable.reconcileSession(
                contextFor(graphical, inventory->value, true),
                globalResult(false)).status ==
                SessionReconcileStatus::NotApplicable &&
                targetedNotApplicable.operations.empty(),
            "targeted NotApplicable policy changed state");
    scope.value = {DesktopEnvironmentKind::Gnome};

    std::string error;
    OSS_absence_of_uncontrolled_desktop_environments absence(scope, inventory);
    require(absence.evaluateSessionInventory(
                {session(DesktopEnvironmentKind::Gnome)}, error),
            "controlled inventory failed compliance");
    require(!absence.evaluateSessionInventory(
                {session(DesktopEnvironmentKind::Gnome),
                 session(DesktopEnvironmentKind::Lxqt)}, error),
            "full inventory ignored an uncontrolled session");
    require(!absence.evaluateSessionInventory({unclassified}, error),
            "unclassifiable graphical session passed compliance");
    scope.value.clear();
    require(!absence.evaluateSessionInventory({}, error),
            "absence policy accepted unconfigured scope");

    PolicyRegistry registry;
    require(registry.addModule("OSS", ModuleView::Standard, 0, error),
            "test module registration failed");
    auto capabilityPolicy = std::make_unique<CapabilityPolicy>();
    Policy* indexed = capabilityPolicy.get();
    require(registry.addPolicy(std::move(capabilityPolicy), error),
            "capability policy registration failed");
    const auto& capabilityIndex =
        registry.capabilityPolicies(PolicyCapability::SessionAware);
    require(capabilityIndex.size() == 1 && capabilityIndex.front() == indexed,
            "PolicyRegistry capability index is incomplete");
    return 0;
}
