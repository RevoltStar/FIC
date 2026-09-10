#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/policies/OSS_screenlock_timeout.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

struct Scope : ControlledDesktopEnvironmentScope {
    DesktopEnvironmentSet desktops;
    bool controlledDesktopEnvironments(DesktopEnvironmentSet& result,
                                       std::string& error) override {
        result = desktops;
        error.clear();
        return true;
    }
};

struct EmptyInventory : GraphicalSessionInventory {
    bool currentSessions(std::vector<ClassifiedGraphicalSession>& result,
                         std::string& error) override {
        result.clear(); error.clear(); return true;
    }
};

struct Backend : DesktopSystemBackend {
    bool ensureOk = true;
    DesktopEnvironmentKind kind = DesktopEnvironmentKind::Gnome;
    std::string name = "gnome";
    DesktopManagedSettings received;
    DesktopEnvironmentKind desktop() const override { return kind; }
    std::string backendName() const override { return name; }
    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override {
        received = required;
        error = ensureOk ? "" : "ensure failed";
        return ensureOk;
    }
    bool verifyManagedSettings(const DesktopManagedSettings&,
                               std::string& error) override {
        error = ensureOk ? "" : "verify failed";
        return ensureOk;
    }
};

fs::path configPath;

void writeConfig(const std::string& value) {
    std::ofstream(configPath) <<
        "_schema_version=1\n"
        "screenlock_timeout.status=ENABLE\n"
        "screenlock_timeout.value=" << value << "\n";
}

void initializeRuntime() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-screenlock-global-test-" + std::to_string(::getpid()));
    fs::create_directories(root / "config");
    fs::create_directories(root / "log");
    configPath = root / "config/OSS.conf";
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.defaultConfigDir = root / "defaults";
    paths.logDir = root / "log";
    paths.runtimeDir = root / "run";
    paths.dataDir = root / "data";
    paths.commandHashFile = root / "data/hashes";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/locks.log";
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

std::unique_ptr<OSS_screenlock_timeout> makePolicy(
    Scope& scope, const std::shared_ptr<EmptyInventory>& inventory) {
    return std::make_unique<OSS_screenlock_timeout>(scope, inventory);
}

void testModesCapabilitiesAndContributions() {
    Scope scope;
    auto inventory = std::make_shared<EmptyInventory>();
    writeConfig("5");
    scope.desktops = {DesktopEnvironmentKind::Gnome};
    auto policy = makePolicy(scope, inventory);
    require(policy->enforcementMode(DesktopEnvironmentKind::Gnome) ==
                EnforcementMode::MandatoryGlobal,
            "GNOME is not MandatoryGlobal");
    require(policy->enforcementMode(DesktopEnvironmentKind::Kde) ==
                EnforcementMode::MandatoryGlobal,
            "KDE is not MandatoryGlobal");
    for (const auto desktop : {DesktopEnvironmentKind::Xfce,
                               DesktopEnvironmentKind::Fly})
        require(policy->enforcementMode(desktop) == EnforcementMode::SessionOnly,
                "XFCE/FLY mode changed from SessionOnly");
    require(policy->enforcementMode(DesktopEnvironmentKind::Lxqt) ==
                EnforcementMode::Unsupported,
            "LXQt unexpectedly became supported");
    const auto capabilities = policy->capabilities();
    require(capabilities.size() == 2 &&
            capabilities[0] == PolicyCapability::SessionAware &&
            capabilities[1] == PolicyCapability::GlobalDesktopConfiguration,
            "screenlock capabilities are incomplete");

    std::vector<GlobalDesktopPolicyContribution> contributions;
    std::string error;
    require(policy->globalDesktopPolicyContributions(contributions, error), error);
    require(contributions.size() == 4, "GNOME did not publish exactly four keys");
    std::map<std::string, std::string> values;
    for (const auto& contribution : contributions) {
        require(contribution.backend == "gnome" &&
                contribution.desktop == DesktopEnvironmentKind::Gnome &&
                contribution.owner == PolicyRef{"OSS", "DesktopEnvironment",
                                                "screenlock_timeout"},
                "contribution identity is not canonical");
        values[contribution.key.setting] = contribution.value;
    }
    require(values["/org/gnome/desktop/session/idle-delay"] == "uint32 300" &&
            values["/org/gnome/desktop/screensaver/lock-enabled"] == "true" &&
            values["/org/gnome/desktop/screensaver/lock-delay"] == "uint32 0" &&
            values["/org/gnome/desktop/lockdown/disable-lock-screen"] == "false",
            "five-minute GNOME conversion is wrong");

    scope.desktops = {DesktopEnvironmentKind::Kde};
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error) &&
            contributions.size() == 5,
            "KDE did not publish exactly five keys");
    values.clear();
    for (const auto& contribution : contributions) {
        require(contribution.backend == "kde" &&
                    contribution.desktop == DesktopEnvironmentKind::Kde &&
                    contribution.owner ==
                        PolicyRef{"OSS", "DesktopEnvironment",
                                  "screenlock_timeout"},
                "KDE contribution identity is not canonical");
        values[contribution.key.setting] = contribution.value;
    }
    require(values["kscreenlockerrc/Daemon/Autolock"] == "true" &&
                values["kscreenlockerrc/Daemon/Timeout"] == "5" &&
                values["kscreenlockerrc/Daemon/Lock"] == "true" &&
                values["kscreenlockerrc/Daemon/LockGrace"] == "0" &&
                values["kscreenlockerrc/Daemon/RequirePassword"] == "true",
            "five-minute KDE conversion is wrong");

    scope.desktops = {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Kde};
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error) &&
            contributions.size() == 9,
            "mixed GNOME/KDE scope did not publish nine keys");

    for (const auto desktop : {DesktopEnvironmentKind::Xfce,
                               DesktopEnvironmentKind::Fly}) {
        scope.desktops = {desktop};
        contributions.clear();
        require(policy->globalDesktopPolicyContributions(contributions, error) &&
                    contributions.empty(),
                "XFCE/FLY published global screen-lock state");
    }

    writeConfig("20");
    scope.desktops = {DesktopEnvironmentKind::Gnome,
                      DesktopEnvironmentKind::Kde};
    policy = makePolicy(scope, inventory);
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error), error);
    for (const auto& contribution : contributions)
        if (contribution.key.setting.find("idle-delay") != std::string::npos)
            require(contribution.value == "uint32 1200",
                    "twenty-minute conversion is wrong");
        else if (contribution.key.setting == "kscreenlockerrc/Daemon/Timeout")
            require(contribution.value == "20",
                    "twenty-minute KDE conversion is wrong");
}

void testInvalidValueAndReconcilerReport() {
    Scope scope;
    scope.desktops = {DesktopEnvironmentKind::Gnome,
                      DesktopEnvironmentKind::Kde};
    auto inventory = std::make_shared<EmptyInventory>();
    writeConfig("invalid");
    auto invalid = makePolicy(scope, inventory);
    std::vector<GlobalDesktopPolicyContribution> contributions;
    std::string error;
    require(!invalid->globalDesktopPolicyContributions(contributions, error),
            "invalid value generated requirements");

    writeConfig("5");
    PolicyRegistry registry;
    require(registry.addModule("OSS", ModuleView::Standard, 0, error), error);
    require(registry.addPolicy(makePolicy(scope, inventory), error), error);
    auto gnome = std::make_shared<Backend>();
    auto kde = std::make_shared<Backend>();
    kde->kind = DesktopEnvironmentKind::Kde;
    kde->name = "kde";
    DesktopGlobalConfigReconciler reconciler({gnome, kde});
    auto report = reconciler.reconcile(registry);
    const PolicyRef owner{"OSS", "DesktopEnvironment", "screenlock_timeout"};
    require(report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(owner, DesktopEnvironmentKind::Kde).verified &&
                gnome->received.size() == 4 && kde->received.size() == 5,
            "actual policy did not receive complete GNOME/KDE coverage");

    kde->ensureOk = false;
    report = reconciler.reconcile(registry);
    require(report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                !report.resultFor(owner, DesktopEnvironmentKind::Kde).verified,
            "KDE failure contaminated GNOME result");

    kde->ensureOk = true;
    gnome->ensureOk = false;
    report = reconciler.reconcile(registry);
    require(!report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(owner, DesktopEnvironmentKind::Kde).verified,
            "GNOME failure contaminated KDE result");
}

} // namespace

int main() {
    try {
        initializeRuntime();
        testModesCapabilitiesAndContributions();
        testInvalidValueAndReconcilerReport();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
