#include <fic/core/FicRuntimePaths.h>
#include <fic/device-db/DB.h>

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unistd.h>

int main()
{
    namespace fs = std::filesystem;

    const fs::path root = fs::temp_directory_path() /
        ("fic-device-tree-revision-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);

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

    std::string pathError;
    assert(paths.validate(pathError));
    assert(fic::core::FicRuntimePaths::initialize(paths, pathError));

    fs::create_directories(paths.logDir);
    fs::create_directories(paths.dataDir);

    const fs::path databasePath = root / "devices.db";
    fs::copy_file(FIC_TEST_DEVICE_SEED_DB, databasePath);

    const DBOptions options{
        databasePath,
        root / "devices.lock",
        root / "db-lock.log",
        false
    };

    std::int64_t finalRevision = -1;
    {
        DB database(options);
        assert(database.initializeDatabase());

        const std::int64_t initialRevision = database.getDeviceTreeRevision();
        assert(initialRevision >= 0);
        assert(database.initializeDatabase());
        assert(database.getDeviceTreeRevision() == initialRevision);

        const DeviceInfo computer = database.getComputerRoot();
        assert(computer.id > 0);
        assert(database.getDeviceTreeRevision() == initialRevision);

        DeviceInfo device;
        device.device_hash = "device-tree-revision-test";
        device.devpath = "/devices/fic-revision-test";
        device.subsystem = "test";
        device.device_type = "test";
        device.parent_id = computer.id;
        device.control_level = "allowed";
        device.control_explicit = true;
        device.ignore_hierarchy = false;
        device.boot_id = "-1";
        device.notes = "revision test";

        const int deviceId = database.addDevice(device);
        assert(deviceId > 0);
        const std::int64_t afterDeviceInsert = database.getDeviceTreeRevision();
        assert(afterDeviceInsert > initialRevision);

        assert(database.addDeviceAttribute(deviceId, "TEST_ATTRIBUTE", "one"));
        const std::int64_t afterAttributeInsert = database.getDeviceTreeRevision();
        assert(afterAttributeInsert > afterDeviceInsert);

        assert(database.addDeviceAttribute(deviceId, "TEST_ATTRIBUTE", "two"));
        const std::int64_t afterAttributeUpdate = database.getDeviceTreeRevision();
        assert(afterAttributeUpdate > afterAttributeInsert);

        DeviceEvent event;
        event.device_id = deviceId;
        event.event_type = "connect";
        event.event_result = "success";
        event.event_details = "revision test";
        assert(database.addDeviceEvent(event) > 0);
        const std::int64_t afterEventInsert = database.getDeviceTreeRevision();
        assert(afterEventInsert > afterAttributeUpdate);

        assert(database.updateDeviceControl(deviceId, "blocked", true, false));
        const std::int64_t afterDeviceUpdate = database.getDeviceTreeRevision();
        assert(afterDeviceUpdate > afterEventInsert);

        assert(database.deleteDevice(deviceId));
        finalRevision = database.getDeviceTreeRevision();
        assert(finalRevision > afterDeviceUpdate);
    }

    {
        DB database(options);
        assert(database.initializeDatabase());
        assert(database.getDeviceTreeRevision() == finalRevision);
    }

    fs::remove_all(root);
    return 0;
}
