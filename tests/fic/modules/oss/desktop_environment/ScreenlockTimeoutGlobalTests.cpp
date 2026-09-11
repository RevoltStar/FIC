#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/policies/OSS_screenlock_timeout.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

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
    int ensures = 0;
    int verifies = 0;
    DesktopEnvironmentKind desktop() const override { return kind; }
    std::string backendName() const override { return name; }
    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override {
        ++ensures;
        received = required;
        error = ensureOk ? "" : "ensure failed";
        return ensureOk;
    }
    bool verifyManagedSettings(const DesktopManagedSettings&,
                               std::string& error) override {
        ++verifies;
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
                EnforcementMode::SessionOnly,
            "KDE is not SessionOnly");
    require(policy->enforcementMode(DesktopEnvironmentKind::Fly) ==
                EnforcementMode::MandatoryGlobal,
            "FLY is not MandatoryGlobal");
    for (const auto desktop : {DesktopEnvironmentKind::Kde,
                               DesktopEnvironmentKind::Xfce})
        require(policy->enforcementMode(desktop) == EnforcementMode::SessionOnly,
                "KDE/XFCE mode changed from SessionOnly");
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
            contributions.empty(),
            "SessionOnly KDE published global requirements");

    scope.desktops = {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Kde};
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error) &&
            contributions.size() == 4,
            "mixed GNOME/KDE scope did not publish only four GNOME keys");
    for (const auto& contribution : contributions)
        require(contribution.backend == "gnome" &&
                    contribution.desktop == DesktopEnvironmentKind::Gnome,
                "mixed scope published a non-GNOME global requirement");

    scope.desktops = {DesktopEnvironmentKind::Xfce};
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error) &&
                contributions.empty(),
            "XFCE published global screen-lock state");

    scope.desktops = {DesktopEnvironmentKind::Fly};
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error) &&
                contributions.size() == 1,
            "FLY did not publish exactly one global requirement");
    values.clear();
    for (const auto& contribution : contributions) {
        require(contribution.backend == "fly" &&
                contribution.desktop == DesktopEnvironmentKind::Fly,
                "FLY contribution identity is not canonical");
        values[contribution.key.setting] = contribution.value;
    }
    require(values.size() == 1 &&
            values["themerc/Variables/ScreenSaverDelay"] == "300",
            "five-minute FLY conversion is wrong");

    scope.desktops = {DesktopEnvironmentKind::Gnome,
                      DesktopEnvironmentKind::Fly};
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error) &&
                contributions.size() == 5,
            "GNOME/FLY scope did not publish five requirements");

    writeConfig("20");
    scope.desktops = {DesktopEnvironmentKind::Gnome,
                      DesktopEnvironmentKind::Fly};
    policy = makePolicy(scope, inventory);
    contributions.clear();
    require(policy->globalDesktopPolicyContributions(contributions, error), error);
    for (const auto& contribution : contributions)
        if (contribution.key.setting.find("idle-delay") != std::string::npos)
            require(contribution.value == "uint32 1200",
                    "twenty-minute conversion is wrong");
        else if (contribution.key.setting ==
                 "themerc/Variables/ScreenSaverDelay")
            require(contribution.value == "1200",
                    "twenty-minute FLY conversion is wrong");
}

void testInvalidValueAndReconcilerReport() {
    Scope scope;
    scope.desktops = {DesktopEnvironmentKind::Gnome,
                      DesktopEnvironmentKind::Fly};
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
    auto fly = std::make_shared<Backend>();
    fly->kind = DesktopEnvironmentKind::Fly;
    fly->name = "fly";
    DesktopGlobalConfigReconciler reconciler({gnome, kde, fly});
    auto report = reconciler.reconcile(registry);
    const PolicyRef owner{"OSS", "DesktopEnvironment", "screenlock_timeout"};
    require(report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(owner, DesktopEnvironmentKind::Fly).verified &&
                gnome->received.size() == 4 && gnome->ensures == 1 &&
                gnome->verifies == 1 && fly->received.size() == 1 &&
                fly->ensures == 1 && fly->verifies == 1 &&
                kde->ensures == 0 && kde->verifies == 0,
            "actual policy did not route GNOME and FLY global enforcement");

    kde->ensureOk = false;
    report = reconciler.reconcile(registry);
    require(report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(owner, DesktopEnvironmentKind::Fly).verified &&
                report.successful() && kde->ensures == 0 && kde->verifies == 0,
            "unused KDE backend was invoked or contaminated GNOME result");

    kde->ensureOk = true;
    gnome->ensureOk = false;
    report = reconciler.reconcile(registry);
    require(!report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                report.resultFor(owner, DesktopEnvironmentKind::Fly).verified &&
                !report.successful() && kde->ensures == 0 && kde->verifies == 0,
            "GNOME failure or unused KDE backend handling is wrong");

    gnome->ensureOk = true;
    fly->ensureOk = false;
    report = reconciler.reconcile(registry);
    require(report.resultFor(owner, DesktopEnvironmentKind::Gnome).verified &&
                !report.resultFor(owner, DesktopEnvironmentKind::Fly).verified &&
                !report.successful() && kde->ensures == 0 && kde->verifies == 0,
            "FLY failure or unused KDE backend handling is wrong");
}

ClassifiedGraphicalSession contradictorySession(
    DesktopEnvironmentKind desktop, const std::string& contextDesktopName) {
    ClassifiedGraphicalSession value;
    value.session.id = "7";
    value.session.uid = 1000;
    value.desktop = desktop;
    value.context.desktop = contextDesktopName;
    return value;
}

void testFactoryUsesCanonicalDesktopIdentity() {
    // Ключевой regression: canonical identity — session.desktop,
    // а не строка session.context.desktop.
    auto kde = ScreenLockTimeoutHandlerFactory::create(
        contradictorySession(DesktopEnvironmentKind::Kde, "GNOME"));
    require(kde != nullptr &&
                dynamic_cast<KdeScreenLockTimeoutHandler*>(kde.get()) !=
                    nullptr,
            "factory ignored canonical session.desktop classification");
    auto gnome = ScreenLockTimeoutHandlerFactory::create(
        contradictorySession(DesktopEnvironmentKind::Gnome, "KDE"));
    require(gnome != nullptr &&
                dynamic_cast<GnomeScreenLockTimeoutHandler*>(gnome.get()) !=
                    nullptr,
            "factory did not honor canonical GNOME classification");

    // Полная матрица DE: выбор зависит только от session.desktop.
    auto fly = ScreenLockTimeoutHandlerFactory::create(
        contradictorySession(DesktopEnvironmentKind::Fly, "KDE"));
    require(fly != nullptr &&
                dynamic_cast<FlyScreenLockTimeoutHandler*>(fly.get()) !=
                    nullptr,
            "FLY handler was not selected by session.desktop");
    auto xfce = ScreenLockTimeoutHandlerFactory::create(
        contradictorySession(DesktopEnvironmentKind::Xfce, "GNOME"));
    require(xfce != nullptr &&
                dynamic_cast<XfceScreenLockTimeoutHandler*>(xfce.get()) !=
                    nullptr,
            "XFCE handler was not selected by session.desktop");
    for (const auto desktop : {DesktopEnvironmentKind::Lxqt,
                               DesktopEnvironmentKind::Unknown}) {
        auto none = ScreenLockTimeoutHandlerFactory::create(
            contradictorySession(desktop, "GNOME"));
        require(none == nullptr,
                "unsupported desktop unexpectedly produced a handler");
    }

    // KDE topology не влияет на выбор handler и переносится как есть.
    ClassifiedGraphicalSession kdeTopology =
        contradictorySession(DesktopEnvironmentKind::Kde, "GNOME");
    kdeTopology.sameUidKdeTopology.state = KdeSessionTopology::Ambiguous;
    auto kdeAmbiguous = ScreenLockTimeoutHandlerFactory::create(kdeTopology);
    require(kdeAmbiguous != nullptr &&
                dynamic_cast<KdeScreenLockTimeoutHandler*>(
                    kdeAmbiguous.get()) != nullptr,
            "factory changed handler selection based on KDE topology");
}

} // namespace

int main() {
    try {
        initializeRuntime();
        testModesCapabilitiesAndContributions();
        testInvalidValueAndReconcilerReport();
        testFactoryUsesCanonicalDesktopIdentity();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
