// Additive configuration upgrade for the device incident severity settings.
//
// An existing installation keeps every configured DC value; the migration adds
// ONLY the two new detector policies, and only when a policy is COMPLETELY
// absent. A partially present policy is damaged state and must stay untouched so
// the existing fail-closed resolution reports it instead of silently turning it
// into a valid factory setting. The pre-existing
// `permanent_device_missing_severity` is not part of this migration.
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

std::size_t countOccurrences(const std::string& haystack,
                             const std::string& needle) {
    std::size_t count = 0;
    for (std::size_t pos = haystack.find(needle); pos != std::string::npos;
         pos = haystack.find(needle, pos + needle.size())) {
        ++count;
    }
    return count;
}

// A configuration written by the PREVIOUS version: the category policies and
// the pre-existing permanent-missing severity are configured, the two new
// detector policies do not exist yet.
const std::string kLegacyConfig =
    "_schema_version=1\n"
    "block_usb_storage.status=DISABLE\n"
    "block_usb_storage.value=all\n"
    "block_printers_scanners.status=DISABLE\n"
    "block_printers_scanners.value=all\n"
    "block_optical_drives.status=DISABLE\n"
    "block_optical_drives.value=all\n"
    "permanent_device_missing_severity.status=ENABLE\n"
    "permanent_device_missing_severity.value=STANDARD\n";

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

    // The additive upgrade appends ONLY the two new policies as complete
    // groups; the pre-existing permanent policy is neither restored nor
    // rewritten.
    require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                configDir, error, identity),
            "DC severity upgrade failed: " + error);
    const std::string upgraded = readFile(dcConf);
    require(upgraded.rfind(kLegacyConfig, 0) == 0,
            "the upgrade must preserve the existing configuration bytes");
    for (const char* expected : {
             "static_device_present_severity.status=ENABLE\n",
             "static_device_present_severity.value=NONE\n",
             "device_block_failed_severity.status=ENABLE\n",
             "device_block_failed_severity.value=STANDARD\n"}) {
        require(upgraded.find(expected) != std::string::npos,
                std::string("missing upgraded default: ") + expected);
    }
    require(countOccurrences(upgraded, "permanent_device_missing_severity") == 2,
            "the migration must not touch the pre-existing permanent policy");
    require(upgraded.find("block_usb_storage.value=all\n") != std::string::npos,
            "the upgrade must keep every other DC setting");
    require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                configDir, error, identity) &&
                readFile(dcConf) == upgraded,
            "the upgrade must be idempotent");

    // A completely absent new policy uses the packaged factory value (see the
    // resolver check above and below); a PARTIALLY present policy must not be
    // repaired by the migration.
    {
        const std::string statusOnly =
            kLegacyConfig + "static_device_present_severity.status=ENABLE\n";
        writeFile(dcConf, statusOnly);
        require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                    configDir, error, identity),
                "DC severity upgrade failed on a partial policy: " + error);
        const std::string after = readFile(dcConf);
        require(countOccurrences(after, "static_device_present_severity") == 1,
                "a partially present policy must not be completed");
        require(after.find("static_device_present_severity.value") ==
                    std::string::npos,
                "a missing value of a partially present policy must stay "
                "missing");
        require(after.find("static_device_present_severity.status=ENABLE\n") !=
                    std::string::npos,
                "an existing status must never be rewritten");
        require(after.find("device_block_failed_severity.value=STANDARD\n") !=
                    std::string::npos,
                "the completely absent policy must still be added");

        // The remaining damaged entry stays fail-closed: ENABLE without a value
        // must never degrade to the factory NONE.
        DC_static_device_present_severity staticPolicy;
        const auto reaction = fic::daemon::resolve_device_incident_severity(
            staticPolicy,
            fic::daemon::device_incident_severity_spec(
                fic::ipc::DeviceIncidentKind::StaticDevicePresent));
        require(reaction.kind ==
                    fic::daemon::DeviceMissingReactionKind::Unproven &&
                reaction.severity == fic::core::IncidentSeverity::Isolate,
                "a partially present policy must stay fail-closed ISOLATE: " +
                    reaction.diagnostic);
    }
    {
        const std::string valueOnly =
            kLegacyConfig + "device_block_failed_severity.value=HARD\n";
        writeFile(dcConf, valueOnly);
        require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                    configDir, error, identity),
                "DC severity upgrade failed on a partial policy: " + error);
        const std::string after = readFile(dcConf);
        require(countOccurrences(after, "device_block_failed_severity") == 1,
                "a partially present policy must not be completed");
        require(after.find("device_block_failed_severity.status") ==
                    std::string::npos,
                "a missing status of a partially present policy must stay "
                "missing");
        require(after.find("device_block_failed_severity.value=HARD\n") !=
                    std::string::npos,
                "an existing value must never be rewritten");
        require(after.find("static_device_present_severity.status=ENABLE\n") !=
                    std::string::npos,
                "the completely absent policy must still be added");
    }

    // A completely absent PERMANENT policy is not restored by this migration:
    // only the two new policies are in scope.
    {
        std::string withoutPermanent;
        {
            std::istringstream input(kLegacyConfig);
            std::string line;
            while (std::getline(input, line)) {
                if (line.rfind("permanent_device_missing_severity", 0) == 0) {
                    continue;
                }
                withoutPermanent += line + "\n";
            }
        }
        writeFile(dcConf, withoutPermanent);
        require(fic::core::ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(
                    configDir, error, identity),
                "DC severity upgrade failed without the permanent policy: " +
                    error);
        const std::string after = readFile(dcConf);
        require(after.find("permanent_device_missing_severity") ==
                    std::string::npos,
                "the migration must not restore the pre-existing permanent "
                "policy");
        require(after.find("static_device_present_severity.value=NONE\n") !=
                    std::string::npos,
                "the new policies must still be added");
    }

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
