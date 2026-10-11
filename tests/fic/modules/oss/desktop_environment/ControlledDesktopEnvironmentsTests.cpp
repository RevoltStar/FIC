#include "modules/oss/desktop_environment/ControlledDesktopEnvironmentsPolicyTypeValue.h"

#include "modules/oss/desktop_environment/policies/OSS_controlled_desktop_environments.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include "rollback/DaemonMutationJournal.h"
#include "rollback/ScopeTransition.h"
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    ControlledDesktopEnvironmentsPolicyTypeValue value;
    require(value.getDefaultValue().empty(), "default scope must be unconfigured");
    DesktopEnvironmentSet parsed;
    require(ControlledDesktopEnvironmentsPolicyTypeValue::parse("", parsed) &&
            parsed.empty(), "empty scope must parse as unconfigured");
    require(ControlledDesktopEnvironmentsPolicyTypeValue::parse(
                "GNOME, KDE, XFCE, LXQT, FLY", parsed),
            "supported canonical desktops were rejected");
    require(parsed.size() == 5, "typed desktop set has wrong size");
    require(!ControlledDesktopEnvironmentsPolicyTypeValue::parse("GNOME,", parsed),
            "trailing empty entry was accepted");
    require(!ControlledDesktopEnvironmentsPolicyTypeValue::parse("GNOME,GNOME", parsed),
            "duplicate desktop was accepted");
    require(!ControlledDesktopEnvironmentsPolicyTypeValue::parse("MATE", parsed),
            "unsupported arbitrary desktop was accepted");
    require(value.postProcessingValue("GNOME,KDE") == "[\"GNOME\",\"KDE\"]",
            "serialized scope is not canonical JSON");
    const auto root = std::filesystem::temp_directory_path() /
        ("fic-controlled-scope-test-" + std::to_string(getpid()));
    std::filesystem::create_directories(root / "config");
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.defaultConfigDir = root / "defaults";
    paths.logDir = root / "log";
    paths.runtimeDir = root / "run";
    paths.dataDir = root / "data";
    paths.commandHashFile = root / "data/hash";
    paths.deviceDatabaseFile = root / "data/db";
    paths.deviceDatabaseLockFile = root / "log/db.lock";
    paths.lockDebugLogFile = root / "log/lock.log";
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
    const auto configure = [&](const std::string& status, const std::string& scope) {
        std::ofstream(root / "config/OSS.conf") << "_schema_version=1\n"
            << "controlled_desktop_environments.status=" << status << '\n'
            << "controlled_desktop_environments.value=" << scope << '\n';
    };
    configure("ENABLE", "[]");
    require(!OSS_controlled_desktop_environments().apply(),
            "enabled empty scope must fail UNCONFIGURED");
    configure("DISABLE", "[\"KDE\"]");
    OSS_controlled_desktop_environments disabled;
    require(!disabled.controlledDesktopEnvironments(parsed, error),
            "alternate scope entrypoint accepted disabled Required");
    configure("ENABLE", "[\"KDE\"]");
    std::filesystem::create_directories(root / "data");
    auto& facade = fic::rollback::DaemonMutationJournal::instance();
    facade.setOverridePath(root / "data/mutations.json");
    require(!OSS_controlled_desktop_environments().apply(),
            "uncommitted nonempty scope was accepted");
    auto* journal = facade.tryGet(error);
    require(journal != nullptr, error);
    fic::rollback::ScopeTransition transition(*journal);
    const fic::rollback::ScopeTransition::Operation verified = [](std::string&) { return true; };
    require(transition.reconcile({"KDE"}, verified, verified, verified, verified, error), error);
    require(OSS_controlled_desktop_environments().apply(), "committed scope was rejected");
    const auto failure = [](std::string& e) { e = "injected release conflict"; return false; };
    require(!transition.reconcile({"KDE"}, verified, verified, failure, verified, error),
            "release failure was accepted");
    require(!OSS_controlled_desktop_environments().apply(),
            "partial transition was accepted by Required prerequisite");
    facade.resetOverride();
    std::filesystem::remove_all(root);
    return 0;
}
