#include "core/DeviceTreeSnapshot.h"

#include <fic/core/FicRuntimePaths.h>
#include <fic/device-db/DB.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <set>
#include <string>
#include <unistd.h>

namespace {

const DeviceTreeEntry* findEntry(const DeviceTreeSnapshot& snapshot, int id)
{
    const auto found = std::find_if(snapshot.entries.begin(), snapshot.entries.end(),
        [id](const DeviceTreeEntry& entry) { return entry.device.id == id; });
    return found == snapshot.entries.end() ? nullptr : &*found;
}

const nlohmann::json* findJsonDevice(const nlohmann::json& response, int id)
{
    for (const auto& device : response["devices"]) {
        if (device.value("id", -1) == id) {
            return &device;
        }
    }
    return nullptr;
}

} // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path rootPath = fs::temp_directory_path() /
        ("fic-device-tree-snapshot-test-" + std::to_string(::getpid()));
    fs::remove_all(rootPath);
    fs::create_directories(rootPath / "data");
    fs::create_directories(rootPath / "log");

    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = rootPath / "bin";
    paths.configDir = rootPath / "config";
    paths.languageDir = rootPath / "lang";
    paths.logDir = rootPath / "log";
    paths.notifyDir = rootPath / "notify";
    paths.dataDir = rootPath / "data";
    paths.shareDir = rootPath / "share";
    paths.imageDir = rootPath / "image";
    paths.runtimeDir = rootPath / "run";
    paths.lockStatusFile = rootPath / "lockstatus";
    paths.commandHashFile = rootPath / "data/commandhash.txt";
    paths.deviceDatabaseFile = rootPath / "devices.db";
    paths.deviceDatabaseLockFile = rootPath / "devices.lock";
    paths.lockDebugLogFile = rootPath / "db-lock.log";
    std::string error;
    assert(paths.validate(error));
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    DB database({paths.deviceDatabaseFile, paths.deviceDatabaseLockFile,
                 paths.lockDebugLogFile, false});
    assert(database.initializeDatabase());

    const DeviceInfo root = database.getComputerRoot();
    assert(root.id > 0);
    DeviceInfo standalone;
    standalone.device_hash = "snapshot-standalone";
    standalone.devpath = "/snapshot-standalone";
    standalone.subsystem = "test";
    standalone.device_type = "test";
    standalone.parent_id = root.id;
    standalone.control_level = "allowed";
    standalone.boot_id = "boot-current";
    const int standaloneId = database.addDevice(standalone);
    assert(standaloneId > 0);
    DeviceTreeSnapshot rootOnly;
    assert(database.getDeviceTreeSnapshot(standaloneId, false, "boot-current",
                                          rootOnly, error));
    assert(rootOnly.entries.size() == 1);
    assert(rootOnly.entries.front().device.id == standaloneId);
    assert(rootOnly.entries.front().attributes.empty());

    DeviceInfo current;
    current.device_hash = "snapshot-current";
    current.devpath = "/devices/snapshot/current";
    current.subsystem = "block";
    current.device_type = "disk";
    current.parent_id = root.id;
    current.control_level = "allowed";
    current.control_explicit = false;
    current.boot_id = "boot-current";
    current.notes = "snapshot current";
    const int currentId = database.addDevice(current);
    assert(currentId > 0);
    assert(database.addDeviceAttribute(currentId, "ID_BUS", "usb"));
    assert(database.addDeviceAttribute(currentId, "EMPTY_VALUE", ""));

    DeviceInfo nested = current;
    nested.device_hash = "snapshot-nested";
    nested.devpath = "/devices/snapshot/current/nested";
    nested.subsystem = "usb";
    nested.device_type = "usb_device";
    nested.parent_id = currentId;
    nested.control_level = "blocked";
    nested.control_explicit = true;
    const int nestedId = database.addDevice(nested);
    assert(nestedId > 0);

    DeviceInfo old = current;
    old.device_hash = "snapshot-old";
    old.devpath = "/devices/snapshot/old";
    old.parent_id = root.id;
    old.boot_id = "boot-old";
    const int oldId = database.addDevice(old);
    assert(oldId > 0);

    DeviceTreeSnapshot currentSnapshot;
    assert(database.getDeviceTreeSnapshot(root.id, false, "boot-current",
                                          currentSnapshot, error));
    assert(currentSnapshot.revision >= 0);
    assert(findEntry(currentSnapshot, root.id) != nullptr);
    const DeviceTreeEntry* currentEntry = findEntry(currentSnapshot, currentId);
    assert(currentEntry != nullptr);
    assert(currentEntry->attributes.at("ID_BUS") == "usb");
    assert(currentEntry->attributes.at("EMPTY_VALUE").empty());
    assert(findEntry(currentSnapshot, nestedId) != nullptr);
    assert(findEntry(currentSnapshot, oldId) == nullptr);
    assert(findEntry(currentSnapshot, nestedId)->attributes.empty());
    assert(std::any_of(currentSnapshot.entries.begin(), currentSnapshot.entries.end(),
        [](const DeviceTreeEntry& entry) { return entry.device.boot_id == "-1"; }));
    std::set<int> currentIds;
    for (const DeviceTreeEntry& entry : currentSnapshot.entries) {
        assert(currentIds.find(entry.device.id) == currentIds.end());
        currentIds.insert(entry.device.id);
    }

    DeviceTreeSnapshot historySnapshot;
    assert(database.getDeviceTreeSnapshot(root.id, true, "boot-current",
                                          historySnapshot, error));
    assert(findEntry(historySnapshot, oldId) != nullptr);
    assert(historySnapshot.entries.size() > currentSnapshot.entries.size());

    DeviceCategoryPolicyState categories;
    categories.block_usb_storage = true;
    assert(database.updateDeviceCategoryPolicyState(categories));
    const auto response = fic::device_control::device_tree_snapshot_response(
        database,
        nlohmann::json{{"command", "device_tree_snapshot"},
                       {"include_disconnected", false}},
        "boot-current");
    assert(response.value("ok", false));
    assert(response["revision"].is_number_integer());
    assert(response["boot_id"] == "boot-current");
    const nlohmann::json* currentJson = findJsonDevice(response, currentId);
    assert(currentJson != nullptr);
    assert((*currentJson)["parent_id"] == root.id);
    assert((*currentJson)["attributes"]["ID_BUS"] == "usb");
    assert((*currentJson)["effective_control_level"] == "blocked");
    assert((*currentJson)["effective_source"] == "dc:block_usb_storage");
    assert(findJsonDevice(response, oldId) == nullptr);

    DeviceInfo identityOverride = current;
    identityOverride.devpath = "/devices/snapshot/identity-override";
    identityOverride.control_level = "permanent";
    identityOverride.control_explicit = true;
    identityOverride.ignore_hierarchy = true;
    identityOverride.boot_id = "boot-old";
    const int identityOverrideId = database.addDevice(identityOverride);
    assert(identityOverrideId > 0);
    const auto identityResponse =
        fic::device_control::device_tree_snapshot_response(
            database,
            nlohmann::json{{"command", "device_tree_snapshot"},
                           {"include_disconnected", false}},
            "boot-current");
    assert(identityResponse.value("ok", false));
    const nlohmann::json* identityJson =
        findJsonDevice(identityResponse, currentId);
    assert(identityJson != nullptr);
    assert((*identityJson)["effective_control_level"] == "permanent");
    assert((*identityJson)["effective_source"] ==
           "identity:" + std::to_string(identityOverrideId));
    assert(findJsonDevice(identityResponse, identityOverrideId) == nullptr);

    const auto historyResponse = fic::device_control::device_tree_snapshot_response(
        database,
        nlohmann::json{{"command", "device_tree_snapshot"},
                       {"include_disconnected", true}},
        "boot-current");
    assert(historyResponse.value("ok", false));
    assert(findJsonDevice(historyResponse, oldId) != nullptr);

    const auto malformed = fic::device_control::device_tree_snapshot_response(
        database, nlohmann::json{{"include_disconnected", "yes"}},
        "boot-current");
    assert(!malformed.value("ok", true));
    assert(malformed.value("message", "").find("must be boolean") != std::string::npos);

    DeviceInfo corruptRoot = root;
    corruptRoot.parent_id = nestedId;
    assert(database.updateDevice(corruptRoot, root.id));
    DeviceTreeSnapshot unchanged = historySnapshot;
    assert(!database.getDeviceTreeSnapshot(root.id, true, "boot-current",
                                           unchanged, error));
    assert(error.find("cycle") != std::string::npos);
    assert(unchanged.entries.size() == historySnapshot.entries.size());

    fs::remove_all(rootPath);
    return 0;
}
