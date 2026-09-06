#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"
#include "modules/oss/desktop_environment/policies/OSS_absence_of_uncontrolled_desktop_environments.h"
#include "policy/registry/PolicyRegistry.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
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
    bool valueOk = true, protectionOk = true, verifyOk = true;
    int reconciled = 0, values = 0, protections = 0, verifies = 0;
protected:
    bool prepare(std::string& error) override { error.clear(); return true; }
    bool relevantTo(DesktopEnvironmentKind) const override { return true; }
    EnforcementMode modeFor(DesktopEnvironmentKind) const override { return mode; }
    bool reconcileControlledSession(const ClassifiedGraphicalSession&,
                                    std::string& error) override {
        ++reconciled; if (!reconcileOk) error = "session failure"; return reconcileOk;
    }
    bool applyGlobalValue(DesktopEnvironmentKind, std::string& error) override {
        ++values; if (!valueOk) error = "value failure"; return valueOk;
    }
    bool applyGlobalProtection(DesktopEnvironmentKind, std::string& error) override {
        ++protections; if (!protectionOk) error = "protection failure"; return protectionOk;
    }
    bool verifyGlobalState(DesktopEnvironmentKind, std::string& error) override {
        ++verifies; if (!verifyOk) error = "verify failure"; return verifyOk;
    }
};

ClassifiedGraphicalSession session(DesktopEnvironmentKind desktop) {
    ClassifiedGraphicalSession value;
    value.session.id = "7";
    value.session.uid = 1000;
    value.desktop = desktop;
    return value;
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
    std::string targetedError;
    require(ignoredUnknown.reconcileSession(unclassified, targetedError) &&
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
    require(global.apply(), "verified global enforcement was defeated by runtime warning");
    require(global.values == 1 && global.protections == 1 && global.verifies == 1,
            "MandatoryGlobal phases were not all executed");

    for (int failedPhase = 0; failedPhase != 3; ++failedPhase) {
        TestPolicy failing(scope, inventory);
        failing.mode = EnforcementMode::MandatoryGlobal;
        failing.valueOk = failedPhase != 0;
        failing.protectionOk = failedPhase != 1;
        failing.verifyOk = failedPhase != 2;
        require(!failing.apply(), "MandatoryGlobal phase failure succeeded");
    }

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
