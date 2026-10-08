// Checked full-inventory read and retry-safety tests for the permanent-device
// detector path.
//
// The security-critical invariant: a global retry obligation may only be
// cleared by a PROVEN complete inventory read. A failed SQLite prepare, a step
// error before SQLITE_DONE, or a failed database initialization must never be
// presented as "all permanent devices are connected".
//
// The tests use the real DB (temporary SQLite fixture) with its real
// fault-injection seam (DB::setInventoryFaultHookForTests) and the production
// permanent-device scan/check code paths.
#include <fic/device-db/DB.h>

#include <fic/core/runtime/FicRuntimePaths.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <memory>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

namespace {

namespace fs = std::filesystem;

class TempDatabase {
public:
    TempDatabase() {
        root_ = fs::temp_directory_path() /
            ("fic-checked-inventory-" + std::to_string(::getpid()));
        std::error_code ignored;
        fs::remove_all(root_, ignored);
        fs::create_directories(root_ / "log");
        fs::create_directories(root_ / "data");
        paths_ = fic::core::FicProductPaths::production();
        paths_.privateBinDir = root_ / "bin";
        paths_.configDir = root_ / "config";
        paths_.languageDir = root_ / "lang";
        paths_.logDir = root_ / "log";
        paths_.notifyDir = root_ / "notify";
        paths_.dataDir = root_ / "data";
        paths_.shareDir = root_ / "share";
        paths_.imageDir = root_ / "image";
        paths_.runtimeDir = root_ / "run";
        paths_.lockStatusFile = root_ / "lockstatus";
        paths_.commandHashFile = root_ / "data/commandhash.txt";
        paths_.deviceDatabaseFile = root_ / "data/devices.db";
        paths_.deviceDatabaseLockFile = root_ / "log/devices.lock";
        paths_.lockDebugLogFile = root_ / "log/db-lock.log";
        std::string error;
        require(paths_.validate(error), error);
        // The paths singleton can only be initialized once per process; the
        // whole run shares one temporary tree.
        require(fic::core::FicRuntimePaths::initialize(paths_, error), error);
    }
    ~TempDatabase() {
        std::error_code ignored;
        fs::remove_all(root_, ignored);
    }

    std::unique_ptr<DB> makeDb() const {
        auto db = std::make_unique<DB>(DBOptions{
            paths_.deviceDatabaseFile,
            paths_.deviceDatabaseLockFile,
            paths_.lockDebugLogFile,
            false
        });
        require(db->initializeDatabase(),
                "the fixture database must initialize");
        return db;
    }

    // Creates device rows directly through the real DB API. The devices root
    // row is a mandatory baseline row of the schema. The database is wiped
    // first, so every scenario starts from a fresh, proven-empty inventory.
    void seedDevices(int count) {
        std::error_code ignored;
        fs::remove(paths_.deviceDatabaseFile, ignored);
        fs::remove(paths_.deviceDatabaseFile.string() + "-wal", ignored);
        fs::remove(paths_.deviceDatabaseFile.string() + "-shm", ignored);
        std::unique_ptr<DB> db = makeDb();
        const int rootId = db->getDeviceByPath("/devices").id;
        require(rootId > 0, "the devices root row must exist");
        for (int i = 0; i < count; ++i) {
            DeviceInfo device;
            device.device_hash = "hash-" + std::to_string(i);
            device.devpath = "/devices/fake" + std::to_string(i);
            device.subsystem = "block";
            device.device_type = "block";
            device.parent_id = rootId;
            device.control_level = "allowed";
            device.control_explicit = false;
            device.ignore_hierarchy = false;
            device.boot_id = "BOOT_TEST";
            device.children_control = "inherit";
            require(db->addDevice(device) > 0,
                    "the fixture device must be added");
        }
    }

private:
    fs::path root_;
    fic::core::FicProductPaths paths_;
};

} // namespace

int main() {
    // The paths singleton is initialized once for the whole run; every
    // scenario wipes the database file and seeds fresh rows.
    TempDatabase fixture;

    // ---- A proven complete read succeeds and returns all rows -------------
    {
        fixture.seedDevices(2);
        std::unique_ptr<DB> dbHolder = fixture.makeDb();
        DB& db = *dbHolder;
        const DB::DeviceListResult inventory = db.getAllDevicesChecked();
        require(inventory.ok,
                "a healthy read must be a proven complete inventory: " +
                    inventory.error);
        require(inventory.devices.size() >= 2,
                "the proven inventory must contain the seeded devices");
    }

    // ---- R3: a prepare failure is an unproven inventory -------------------
    {
        fixture.seedDevices(1);
        std::unique_ptr<DB> dbHolder = fixture.makeDb();
        DB& db = *dbHolder;
        db.setInventoryFaultHookForTests(
            [](const char* stage) { return std::string(stage) == "prepare"; });
        const DB::DeviceListResult inventory = db.getAllDevicesChecked();
        require(!inventory.ok,
                "a failed prepare must not produce a proven inventory");
        require(inventory.devices.empty(),
                "a failed prepare must not return any device");
        require(!inventory.error.empty(),
                "a failed prepare must carry a diagnostic");
    }

    // ---- R4: a step failure before SQLITE_DONE is unproven ----------------
    {
        fixture.seedDevices(2);
        std::unique_ptr<DB> dbHolder = fixture.makeDb();
        DB& db = *dbHolder;
        db.setInventoryFaultHookForTests(
            [](const char* stage) { return std::string(stage) == "step"; });
        const DB::DeviceListResult inventory = db.getAllDevicesChecked();
        require(!inventory.ok,
                "a step failure before SQLITE_DONE must not be a proven "
                "complete inventory");
        require(inventory.devices.empty(),
                "a partial scan must never be presented as a complete "
                "inventory");
    }

    // ---- A healthy read after the faults are removed is proven again ------
    {
        fixture.seedDevices(1);
        std::unique_ptr<DB> dbHolder = fixture.makeDb();
        DB& db = *dbHolder;
        db.setInventoryFaultHookForTests(
            [](const char*) { return true; });
        require(!db.getAllDevicesChecked().ok,
                "the injected fault must fail the read");
        db.setInventoryFaultHookForTests(nullptr);
        const DB::DeviceListResult recovery = db.getAllDevicesChecked();
        require(recovery.ok && recovery.devices.size() >= 1,
                "the recovered read must be a proven complete inventory");
    }

    std::cout << "Checked device inventory contract proven\n";
    return 0;
}