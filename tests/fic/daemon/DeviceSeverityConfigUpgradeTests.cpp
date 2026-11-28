// Additive configuration upgrade for the device incident severity settings.
//
// An existing installation keeps every configured DC value; only entirely
// missing severity entries are appended with the packaged factory values. The
// test then resolves the production detector reaction from that upgraded
// configuration, proving that an upgraded host does not fall back to an
// unintended ISOLATE reaction (or to a silent NONE where a reaction is
// expected).
#include "daemon/DeviceIncidentEvent.h"

#include <fic/core/config/ConfigSchemaManager.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "modules/dc/DC.h"

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path);
    std::ostringstream content;
    content << input.rdbuf();
    return content.str();
}

void writeFile(const fs::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::trunc);
    output << content;
    output.close();
    require(::chmod(path.c_str(), 0640) == 0, "fixture chmod failed");
}

const std::string kLegacyConfig =
    "_schema_version=1\n"
    "block_usb_storage.status=DISABLE\n"
    "block_usb_storage.value=all\n"
    "block_printers_scanners.status=DISABLE\n"
    "block_printers_scanners.value=all\n"
    "block_optical_drives.status=DISABLE\n"
    "block_optical_drives.value=all\n";

} // namespace


int main() {
    char pattern[] = "/tmp/fic-dc-severity-upgrade-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    require(created != nullptr, "mkdtemp failed");
    const fs::path root = created;
    const fs::path configDir = root / "config";
    fs::create_directories(configDir);
    // proveConfigDirectory() proves the directory AND its parent, so the test
    // fixture must carry the canonical authority metadata.
    require(::chmod(root.c_str(), 02750) == 0, "root chmod failed");
    require(::chmod(configDir.c_str(), 02750) == 0, "config chmod failed");
    const fs::path dcConf = configDir / "DC.conf";
    const auto identity =
        fic::core::ConfigAuthorityIdentity{::geteuid(), ::getegid()};
    std::string error;

    // A configuration written before the new severity policies existed.
    writeFile(dcConf, kLegacyConfig);

    // Resolving before the upgrade: an entirely absent policy uses the
    // packaged factory value instead of failing closed.
    {
        fic::core::FicProductPaths paths = fic::core::FicProductPaths::production();
        paths.configDir = configDir;
        paths.languageDir = root / "lang";
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        DC_static_device_present_severity staticPolicy;
        DC_device_block_failed_severity blockPolicy;
        const auto staticReaction = fic::daemon::resolve_device_incident_severity(
            staticPolicy,
            fic::daemon::device_incident_severity_spec(
                fic::ipc::DeviceIncidentKind::StaticDevicePresent));
        require(staticReaction.kind == fic::daemon::DeviceMissingReactionKind::None,
                "an unupgraded configuration must use the factory NONE");
        const auto blockReaction = fic::daemon::resolve_device_incident_severity(
            blockPolicy,
            fic::daemon::device_incident_severity_spec(
                fic::ipc::DeviceIncidentKind::DeviceBlockFailed));
        require(blockReaction.kind ==
                    fic::daemon::DeviceMissingReactionKind::Severity,
                "an unupgraded configuration must use the factory STANDARD");
        require(blockReaction.severity == fic::core::IncidentSeverity::Standard,
                "the factory STANDARD severity must be STANDARD");
    }

    // The additive upgrade appends only the missing entries.
    require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                configDir, error, identity),
            "DC severity upgrade failed: " + error);
    const std::string upgraded = readFile(dcConf);
    require(upgraded.rfind(kLegacyConfig, 0) == 0,
            "the upgrade must preserve the existing configuration bytes");
    for (const char* expected : {
             "permanent_device_missing_severity.status=ENABLE\n",
             "permanent_device_missing_severity.value=STANDARD\n",
             "static_device_present_severity.status=ENABLE\n",
             "static_device_present_severity.value=NONE\n",
             "device_block_failed_severity.status=ENABLE\n",
             "device_block_failed_severity.value=STANDARD\n"}) {
        require(upgraded.find(expected) != std::string::npos,
                std::string("missing upgraded default: ") + expected);
    }
    require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                configDir, error, identity) &&
                readFile(dcConf) == upgraded,
            "the upgrade must be idempotent");

    // Explicit operator choices and unproven values are never rewritten.
    const std::string explicitConfig =
        kLegacyConfig +
        "permanent_device_missing_severity.status=DISABLE\n"
        "permanent_device_missing_severity.value=HARD\n"
        "static_device_present_severity.status=BROKEN\n"
        "static_device_present_severity.value=ISOLATE\n"
        "device_block_failed_severity.status=ENABLE\n"
        "device_block_failed_severity.value=SOFT\n";
    writeFile(dcConf, explicitConfig);
    require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                configDir, error, identity),
            "DC severity upgrade failed on explicit config: " + error);
    require(readFile(dcConf) == explicitConfig,
            "the upgrade must not overwrite configured severity settings");

    // With the packaged defaults present, the resolver reports the configured
    // factory values instead of an unproven ISOLATE.
    writeFile(dcConf, upgraded);
    {
        DC_static_device_present_severity staticPolicy;
        const auto staticReaction = fic::daemon::resolve_device_incident_severity(
            staticPolicy,
            fic::daemon::device_incident_severity_spec(
                fic::ipc::DeviceIncidentKind::StaticDevicePresent));
        require(staticReaction.kind == fic::daemon::DeviceMissingReactionKind::None,
                "an upgraded configuration resolves the packaged NONE: " +
                    staticReaction.diagnostic);
        DC_device_block_failed_severity blockPolicy;
        const auto blockReaction = fic::daemon::resolve_device_incident_severity(
            blockPolicy,
            fic::daemon::device_incident_severity_spec(
                fic::ipc::DeviceIncidentKind::DeviceBlockFailed));
        require(blockReaction.kind ==
                    fic::daemon::DeviceMissingReactionKind::Severity,
                "an upgraded configuration resolves the packaged STANDARD: " +
                    blockReaction.diagnostic);
    }

    std::error_code ignored;
    fs::remove_all(root, ignored);
    std::cout << "Device incident severity configuration upgrade proven\n";
    return 0;
}
