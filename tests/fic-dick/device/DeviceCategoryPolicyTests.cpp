#include <fic/device-db/DeviceCategoryPolicy.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include "device/DeviceTreeSnapshot.h"
#include "policy/DevicePolicyCompiler.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <sys/wait.h>
#include <nlohmann/json.hpp>

using namespace fic::device_control;

int main(int argc, char** argv) {
    const auto root = argc > 1 ? std::filesystem::path(argv[1]) : std::filesystem::temp_directory_path() / ("fic-category-" + std::to_string(getpid()));
    if (argc == 1) std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "devices.db";
    paths.deviceDatabaseLockFile = root / "devices.lock";
    paths.lockDebugLogFile = root / "db-lock.log";
    std::string error;
    assert(paths.validate(error));
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    DBOptions options{root / "devices.db", root / "db.lock", root / "lock.log", false};
    if (argc > 1) {
        DB db(options);
        assert(db.initializeDatabase());
        auto desired = db.getDeviceCategoryPolicyState();
        desired.block_optical_drives = "new";
        const int ready = std::stoi(argv[2]);
        assert(write(ready, "r", 1) == 1);
        assert(db.updateDeviceCategoryPolicyState(desired));
        bool found = false;
        const auto captured = db.getDeviceCategoryPolicyState();
        for (const auto& identity : captured.known.at("block_optical_drives"))
            if (identity.device_hash == "concurrent") {
                assert(identity.attributes.at("ID_WWN") == "atomic-identity");
                found = true;
            }
        assert(found);
        return 0;
    }
    std::int64_t epoch, revision;
    int knownId, newId;
    {
        DB db(options);
        assert(db.initializeDatabase());
        DeviceInfo known;
        known.device_hash = "known-usb";
        known.subsystem = "usb";
        known.device_type = "usb";
        known.devpath = "/devices/category/known";
        known.parent_id = db.getComputerRoot().id;
        known.control_level = "allowed";
        known.control_explicit = false;
        known.boot_id = "test-boot";
        knownId = db.addDevice(known);
        assert(knownId > 0);
        const DeviceIdentityTerms attrs{{"DEVTYPE", "usb_device"}, {"ID_VENDOR_ID", "1234"},
            {"ID_MODEL_ID", "5678"}, {"ID_SERIAL", "physical-001"}, {"ID_SERIAL_SHORT", "physical-001"}, {"ID_USB_INTERFACES", ":080650:"}};
        for (const auto& [key, value] : attrs) assert(db.addDeviceAttribute(knownId, key, value));
        known.id = knownId;
        DeviceCategoryPolicyState desired;
        desired.block_usb_storage = "new";
        assert(db.updateDeviceCategoryPolicyState(desired));
        auto state = db.getDeviceCategoryPolicyState();
        epoch = state.epochs.at("block_usb_storage");
        revision = db.getDesiredPolicyRevision();
        assert(epoch == 1 && !categoryDenial(state, known, attrs, false));
        const auto knownRules = DevicePolicyCompiler({"/opt/fic/bin/fic-dick"}).compile(db);
        assert(knownRules.ok);
        assert(knownRules.rules.find("ATTRS{serial}==\"physical-001\"") != std::string::npos);
        assert(knownRules.rules.find("ENV{ID_SERIAL_SHORT}==\"physical-001\"") != std::string::npos);
        assert(db.updateDeviceCategoryPolicyState(desired));
        assert(db.getDesiredPolicyRevision() == revision);
        assert(db.getDeviceCategoryPolicyState().epochs.at("block_usb_storage") == epoch);
        auto fresh = known;
        fresh.device_hash = "new-usb";
        fresh.devpath = "/devices/category/new";
        newId = db.addDevice(fresh);
        fresh.id = newId;
        auto freshAttrs = attrs;
        freshAttrs["ID_SERIAL_SHORT"] = "physical-002";
        freshAttrs["ID_SERIAL"] = "physical-002";
        for (const auto& [key, value] : freshAttrs) assert(db.addDeviceAttribute(newId, key, value));
        assert(categoryDenial(db.getDeviceCategoryPolicyState(), fresh, freshAttrs, false));
        auto reconnect = known;
        reconnect.devpath = "/devices/category/reconnected";
        reconnect.id = db.addDevice(reconnect);
        assert(!categoryDenial(state, reconnect, attrs, false));
        assert(db.deleteDevice(knownId));
        assert(!categoryDenial(db.getDeviceCategoryPolicyState(), reconnect, attrs, false));
        // Different placement/occurrence does not turn a new identity into known.
        auto freshReconnect = fresh;
        freshReconnect.devpath = "/devices/category/new-reconnected";
        freshReconnect.id = db.addDevice(freshReconnect);
        assert(categoryDenial(db.getDeviceCategoryPolicyState(), freshReconnect, freshAttrs, false));
        assert(db.updateDeviceControl(newId, "allowed", true, false, "inherit"));
        const auto effective = [&](int id) {
            const auto response = device_tree_snapshot_response(db, {{"include_disconnected", true}}, "test-boot");
            assert(response.value("ok", false));
            for (const auto& device : response["devices"])
                if (device["id"] == id) return device["effective_control_level"].get<std::string>();
            std::abort();
        };
        assert(effective(newId) == "allowed");
        assert(db.updateDeviceChildrenControl(fresh.parent_id, "deny"));
        assert(effective(reconnect.id) == "blocked");
        desired.block_usb_storage = "all";
        assert(db.updateDeviceCategoryPolicyState(desired));
        for (const auto* explicitLevel : {"allowed", "ignored", "permanent"}) {
            assert(db.updateDeviceControl(newId, explicitLevel, true, true, "allow"));
            assert(effective(newId) == "blocked");
        }
        const auto compiled = DevicePolicyCompiler({"/opt/fic/libexec/fic-dick"}).compile(db);
        assert(compiled.ok && compiled.rules.find("FIC_CATEGORY_HARD") != std::string::npos);
        desired.block_usb_storage = "new";
        assert(db.updateDeviceCategoryPolicyState(desired));
        state = db.getDeviceCategoryPolicyState();
        assert(state.epochs.at("block_usb_storage") == epoch + 1);
        assert(!categoryDenial(state, fresh, freshAttrs, false));
        desired.block_usb_storage = "disabled";
        assert(db.updateDeviceCategoryPolicyState(desired));
        assert(effective(newId) == "permanent");
        desired.block_usb_storage = "new";
        assert(db.updateDeviceCategoryPolicyState(desired));
        assert(db.getDeviceCategoryPolicyState().epochs.at("block_usb_storage") == epoch + 2);
        assert(db.setActivePolicyRevision(db.getDesiredPolicyRevision()));
        desired.block_usb_storage = "all";
        assert(db.updateDeviceCategoryPolicyState(desired));
        assert(db.getDesiredPolicyRevision() > db.getActivePolicyRevision());
        desired.block_usb_storage = "nonsense";
        revision = db.getDesiredPolicyRevision();
        assert(!db.updateDeviceCategoryPolicyState(desired));
        assert(db.getDesiredPolicyRevision() == revision);
    }
    {
        DB db(options);
        assert(db.initializeDatabase());
        const auto state = db.getDeviceCategoryPolicyState();
        assert(state.block_usb_storage == "all");
        assert(state.epochs.at("block_usb_storage") == epoch + 2);
        assert(db.updateDeviceCategoryPolicyState(state));
        assert(db.getDesiredPolicyRevision() == revision);
    }
    {
        DB db(options);
        assert(db.initializeDatabase());
        const std::pair<const char*, std::string DeviceCategoryPolicyState::*> categories[] = {
            {"block_usb_storage", &DeviceCategoryPolicyState::block_usb_storage},
            {"block_printers_scanners", &DeviceCategoryPolicyState::block_printers_scanners},
            {"block_optical_drives", &DeviceCategoryPolicyState::block_optical_drives}};
        for (const auto& [category, member] : categories) {
            auto desired = db.getDeviceCategoryPolicyState();
            desired.*member = "disabled";
            assert(db.updateDeviceCategoryPolicyState(desired));
            auto epochBefore = db.getDeviceCategoryPolicyState().epochs.at(category);
            for (const auto* mode : {"new", "new", "all", "all", "new", "disabled"}) {
                const auto before = db.getDeviceCategoryPolicyState();
                const auto revisionBefore = db.getDesiredPolicyRevision();
                desired.*member = mode;
                assert(db.updateDeviceCategoryPolicyState(desired));
                const auto after = db.getDeviceCategoryPolicyState();
                if (std::string(mode) == "new" && before.*member != "new") ++epochBefore;
                assert(after.epochs.at(category) == epochBefore);
                assert(db.getDesiredPolicyRevision() == revisionBefore + (before.*member == mode ? 0 : 1));
            }
        }
        // A late SQLite write failure rolls back both epoch capture and modes.
        sqlite3* raw = nullptr;
        assert(sqlite3_open(options.databaseFile.c_str(), &raw) == SQLITE_OK);
        assert(sqlite3_exec(raw, "CREATE TRIGGER category_failure BEFORE UPDATE ON device_policy_state BEGIN SELECT RAISE(ABORT,'injected category write failure'); END", nullptr, nullptr, nullptr) == SQLITE_OK);
        const auto before = db.getDeviceCategoryPolicyState();
        auto desired = before;
        desired.block_optical_drives = "new";
        assert(!db.updateDeviceCategoryPolicyState(desired));
        const auto after = db.getDeviceCategoryPolicyState();
        assert(after.block_optical_drives == before.block_optical_drives && after.epochs == before.epochs);
        assert(sqlite3_exec(raw, "DROP TRIGGER category_failure", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }
    // SQLite serializes a concurrent writer before the epoch snapshot. The
    // child cannot observe half of an identity/attribute insertion transaction.
    {
        sqlite3* writer = nullptr;
        assert(sqlite3_open(options.databaseFile.c_str(), &writer) == SQLITE_OK);
        assert(sqlite3_exec(writer, "BEGIN IMMEDIATE; INSERT INTO devices(device_hash,subsystem,device_type,control_level) VALUES('concurrent','block','disk','allowed'); INSERT INTO device_attributes(device_id,attribute_name,attribute_value) VALUES(last_insert_rowid(),'ID_WWN','atomic-identity');", nullptr, nullptr, nullptr) == SQLITE_OK);
        int ready[2];
        assert(pipe(ready) == 0);
        const auto child = fork();
        assert(child >= 0);
        if (child == 0) {
            close(ready[0]);
            const auto fd = std::to_string(ready[1]);
            execl("/proc/self/exe", "device_category_policy_tests", root.c_str(), fd.c_str(), nullptr);
            _exit(127);
        }
        close(ready[1]);
        char byte;
        assert(read(ready[0], &byte, 1) == 1);
        assert(sqlite3_exec(writer, "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(writer);
        close(ready[0]);
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    // Incomplete physical identity cannot receive a new-mode exemption.
    DeviceCategoryPolicyState state;
    state.block_usb_storage = "new";
    DeviceInfo unknown;
    unknown.subsystem = "usb";
    assert(categoryDenial(state, unknown, {{"ID_USB_INTERFACES", ":080650:"}}, false));
    assert(!categoryDenial(state, unknown, {{"ID_USB_INTERFACES", ":030101:"}}, false));
    DeviceCategoryPolicyState physical;
    physical.block_usb_storage = "new";
    physical.known["block_usb_storage"].push_back({"old-disk-hash", "block", {{"ID_WWN", "physical-wwn"}, {"DEVTYPE", "disk"}}});
    DeviceInfo partition;
    partition.subsystem = "block";
    partition.device_hash = "new-partition-hash";
    assert(!categoryDenial(physical, partition, {{"ID_BUS", "usb"}, {"ID_WWN", "physical-wwn"}, {"DEVTYPE", "partition"}}, false));
    auto interfaceAttrs = DeviceIdentityTerms{{"DEVTYPE", "usb_interface"}, {"INTERFACE", "8/6/80"},
        {"FIC_PHYSICAL_VENDOR", "1234"}, {"FIC_PHYSICAL_MODEL", "5678"}, {"FIC_PHYSICAL_SERIAL", "parent-serial"}};
    physical.known["block_usb_storage"].push_back({"usb-parent", "usb", {{"DEVTYPE", "usb_device"},
        {"ID_VENDOR_ID", "1234"}, {"ID_MODEL_ID", "5678"}, {"ID_SERIAL_SHORT", "parent-serial"}}});
    DeviceInfo interface;
    interface.subsystem = "usb";
    assert(!categoryDenial(physical, interface, interfaceAttrs, false));
    interfaceAttrs["FIC_PHYSICAL_SERIAL"] = "different-parent";
    assert(categoryDenial(physical, interface, interfaceAttrs, false));
    DeviceInfo printer;
    printer.subsystem = "usbmisc";
    DeviceCategoryPolicyState printers;
    printers.block_printers_scanners = "all";
    assert(categoryDenial(printers, printer, {{"ID_BUS", "usb"}, {"TYPE", "7/1/2"}}, true));
    for (const auto& [category, predicates] : categoryPredicates()) {
        DeviceCategoryPolicyState modes;
        if (category == "block_usb_storage") modes.block_usb_storage = "all";
        if (category == "block_printers_scanners") modes.block_printers_scanners = "all";
        if (category == "block_optical_drives") modes.block_optical_drives = "all";
        DeviceInfo example;
        example.subsystem = predicates.front().subsystem;
        DeviceIdentityTerms attributes;
        if (category == "block_usb_storage") attributes["ID_BUS"] = "usb";
        if (category == "block_printers_scanners") attributes["ID_USB_INTERFACES"] = ":070101:";
        if (category == "block_optical_drives") attributes["ID_CDROM"] = "1";
        assert(categoryDenial(modes, example, attributes, true));
    }
    std::filesystem::remove_all(root);
}
