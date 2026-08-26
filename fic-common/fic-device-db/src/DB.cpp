#include <fic/device-db/DB.h>

#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/logging/Logger.h>
#include <fic/version/ProductVersion.h>

#include <algorithm>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {
std::string validatedDatabasePath(const DBOptions& options) {
    const std::filesystem::path* paths[] = {
        &options.databaseFile,
        &options.lockFile,
        &options.lockDebugLogFile
    };
    for (const auto* path : paths) {
        if (path->empty() || !path->is_absolute() ||
            path->lexically_normal() != *path) {
            throw std::invalid_argument(
                "DBOptions paths must be absolute and lexically normalized");
        }
    }
    if (options.databaseFile == options.lockFile) {
        throw std::invalid_argument("database and lock paths must be different");
    }
    return options.databaseFile.string();
}

bool databaseHasContent(const std::filesystem::path& path) {
    std::error_code error;
    return std::filesystem::exists(path, error) && !error &&
        std::filesystem::file_size(path, error) > 0 && !error;
}

constexpr const char* SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS devices ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    device_hash TEXT NOT NULL,"
    "    devpath TEXT,"
    "    subsystem TEXT NOT NULL,"
    "    device_type TEXT NOT NULL,"
    "    parent_id INTEGER,"
    "    control_level TEXT NOT NULL CHECK(control_level IN ('blocked', 'allowed', 'permanent', 'ignored')),"
    "    control_explicit BOOLEAN DEFAULT 1,"
    "    ignore_hierarchy BOOLEAN DEFAULT 0,"
    "    boot_id TEXT,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    last_event_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    notes TEXT,"
    "    children_control TEXT NOT NULL DEFAULT 'inherit' "
    "        CHECK(children_control IN ('allow', 'deny', 'inherit')),"
    "    FOREIGN KEY (parent_id) REFERENCES devices(id) ON DELETE CASCADE"
    ");"
    "CREATE TABLE IF NOT EXISTS device_attributes ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    device_id INTEGER NOT NULL,"
    "    attribute_name TEXT NOT NULL,"
    "    attribute_value TEXT,"
    "    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,"
    "    UNIQUE(device_id, attribute_name)"
    ");"
    "CREATE TABLE IF NOT EXISTS device_events ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    device_id INTEGER NOT NULL,"
    "    event_type TEXT NOT NULL CHECK(event_type IN ('connect', 'disconnect', 'block', 'allow', 'lock', 'unlock')),"
    "    event_result TEXT CHECK(event_result IN ('success', 'blocked_by_parent', 'blocked_by_policy', 'error', 'temporary_allowed')),"
    "    event_details TEXT,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE"
    ");"
    "CREATE TABLE IF NOT EXISTS device_tree_state ("
    "    id INTEGER PRIMARY KEY CHECK(id = 1),"
    "    revision INTEGER NOT NULL DEFAULT 0"
    ");"
    "INSERT OR IGNORE INTO device_tree_state (id, revision) VALUES (1, 0);"
    "CREATE TABLE IF NOT EXISTS device_policy_state ("
    "    id INTEGER PRIMARY KEY CHECK(id = 1),"
    "    desired_revision INTEGER NOT NULL DEFAULT 0,"
    "    active_revision INTEGER NOT NULL DEFAULT 0,"
    "    block_usb_storage BOOLEAN NOT NULL DEFAULT 0,"
    "    block_printers_scanners BOOLEAN NOT NULL DEFAULT 0,"
    "    block_optical_drives BOOLEAN NOT NULL DEFAULT 0"
    ");"
    "INSERT OR IGNORE INTO device_policy_state "
    "(id, desired_revision, active_revision, block_usb_storage, "
    "block_printers_scanners, block_optical_drives) VALUES (1, 0, 0, 0, 0, 0);"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_devices_insert "
    "AFTER INSERT ON devices BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_devices_update "
    "AFTER UPDATE ON devices BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_devices_delete "
    "AFTER DELETE ON devices BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_attributes_insert "
    "AFTER INSERT ON device_attributes BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_attributes_update "
    "AFTER UPDATE ON device_attributes BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_attributes_delete "
    "AFTER DELETE ON device_attributes BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_events_insert "
    "AFTER INSERT ON device_events BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_events_update "
    "AFTER UPDATE ON device_events BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_tree_revision_events_delete "
    "AFTER DELETE ON device_events BEGIN "
    "    UPDATE device_tree_state SET revision = revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_policy_revision_devices_update "
    "AFTER UPDATE OF control_level, control_explicit, ignore_hierarchy, children_control ON devices "
    "WHEN OLD.control_level IS NOT NEW.control_level "
    " OR OLD.control_explicit IS NOT NEW.control_explicit "
    " OR OLD.ignore_hierarchy IS NOT NEW.ignore_hierarchy "
    " OR OLD.children_control IS NOT NEW.children_control BEGIN "
    "    UPDATE device_policy_state SET desired_revision = desired_revision + 1 WHERE id = 1;"
    "END;"
    "CREATE TRIGGER IF NOT EXISTS device_policy_revision_devices_delete "
    "AFTER DELETE ON devices BEGIN "
    "    UPDATE device_policy_state SET desired_revision = desired_revision + 1 WHERE id = 1;"
    "END;";

constexpr const char* INDEX_SQL =
    "CREATE INDEX IF NOT EXISTS idx_devices_hash ON devices(device_hash);"
    "CREATE INDEX IF NOT EXISTS idx_devices_devpath ON devices(devpath);"
    "CREATE INDEX IF NOT EXISTS idx_devices_parent ON devices(parent_id);"
    "CREATE INDEX IF NOT EXISTS idx_devices_control ON devices(control_level);"
    "CREATE INDEX IF NOT EXISTS idx_devices_subsystem ON devices(subsystem);";

constexpr const char* BASELINE_DATA_SQL =
    "INSERT INTO devices (device_hash,devpath,subsystem,device_type,parent_id,"
    "control_level,control_explicit,ignore_hierarchy,boot_id,notes) "
    "SELECT 'virtual_computer_root_sha256_placeholder','/','__computer__',"
    "'computer',NULL,'allowed',1,0,'-1','FIC virtual computer root' "
    "WHERE NOT EXISTS (SELECT 1 FROM devices WHERE "
    "device_hash='virtual_computer_root_sha256_placeholder');"
    "INSERT INTO devices (device_hash,devpath,subsystem,device_type,parent_id,"
    "control_level,control_explicit,ignore_hierarchy,boot_id,notes) "
    "SELECT 'virtual_container_cpu_sha256_placeholder','/cpu_list','__cpu__',"
    "'container_cpu',id,'allowed',1,0,'-1','FIC virtual CPU container' "
    "FROM devices WHERE device_hash='virtual_computer_root_sha256_placeholder' "
    "AND NOT EXISTS (SELECT 1 FROM devices WHERE "
    "device_hash='virtual_container_cpu_sha256_placeholder') LIMIT 1;"
    "INSERT INTO devices (device_hash,devpath,subsystem,device_type,parent_id,"
    "control_level,control_explicit,ignore_hierarchy,boot_id,notes) "
    "SELECT 'virtual_container_memory_sha256_placeholder','/memory_list','__memory__',"
    "'container_memory',id,'allowed',1,0,'-1','FIC virtual memory container' "
    "FROM devices WHERE device_hash='virtual_computer_root_sha256_placeholder' "
    "AND NOT EXISTS (SELECT 1 FROM devices WHERE "
    "device_hash='virtual_container_memory_sha256_placeholder') LIMIT 1;"
    "INSERT INTO devices (device_hash,devpath,subsystem,device_type,parent_id,"
    "control_level,control_explicit,ignore_hierarchy,boot_id,notes) "
    "SELECT 'virtual_container_board_sha256_placeholder','/board_list','__board__',"
    "'container_board',id,'allowed',1,0,'-1','FIC virtual board container' "
    "FROM devices WHERE device_hash='virtual_computer_root_sha256_placeholder' "
    "AND NOT EXISTS (SELECT 1 FROM devices WHERE "
    "device_hash='virtual_container_board_sha256_placeholder') LIMIT 1;"
    "INSERT INTO devices (device_hash,devpath,subsystem,device_type,parent_id,"
    "control_level,control_explicit,ignore_hierarchy,boot_id,notes) "
    "SELECT 'virtual_container_udev_sha256_placeholder','/devices','__udev__',"
    "'container_udev',id,'allowed',1,0,'-1','FIC virtual udev container' "
    "FROM devices WHERE device_hash='virtual_computer_root_sha256_placeholder' "
    "AND NOT EXISTS (SELECT 1 FROM devices WHERE "
    "device_hash='virtual_container_udev_sha256_placeholder') LIMIT 1;"
    "INSERT INTO devices (device_hash,devpath,subsystem,device_type,parent_id,"
    "control_level,control_explicit,ignore_hierarchy,boot_id,notes) "
    "SELECT 'virtual_container_pci_sha256_placeholder','/devices/pci0000:00','__pci__',"
    "'container_pci',id,'allowed',1,0,'-1','FIC virtual PCI container' "
    "FROM devices WHERE device_hash='virtual_container_udev_sha256_placeholder' "
    "AND NOT EXISTS (SELECT 1 FROM devices WHERE "
    "device_hash='virtual_container_pci_sha256_placeholder') LIMIT 1;";

bool executeSql(sqlite3* database, const std::string& sql, std::string& error) {
    char* message = nullptr;
    const int result = sqlite3_exec(database, sql.c_str(), nullptr, nullptr, &message);
    if (result == SQLITE_OK) {
        return true;
    }
    error = message == nullptr ? sqlite3_errmsg(database) : message;
    sqlite3_free(message);
    return false;
}

bool readPragmaInt(sqlite3* database, const char* pragma, int& value, std::string& error) {
    sqlite3_stmt* statement = nullptr;
    const std::string sql = std::string("PRAGMA ") + pragma + ";";
    if (sqlite3_prepare_v2(database, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    const int step = sqlite3_step(statement);
    if (step != SQLITE_ROW) {
        error = sqlite3_errmsg(database);
        sqlite3_finalize(statement);
        return false;
    }
    value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return true;
}

bool hasExpectedApplicationTables(sqlite3* database, std::string& error) {
    constexpr const char* sql =
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%';";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    std::set<std::string> actual;
    int step = SQLITE_OK;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(statement, 0);
        if (name != nullptr) {
            actual.emplace(reinterpret_cast<const char*>(name));
        }
    }
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE) {
        error = sqlite3_errmsg(database);
        return false;
    }
    std::set<std::string> required = {
        "devices", "device_attributes", "device_events", "device_tree_state",
        "device_policy_state"
    };
    if (actual != required) {
        error = "device database contains a missing or unknown application table";
        return false;
    }
    return true;
}

bool tableHasExactColumns(sqlite3* database,
                          const char* table,
                          const std::vector<std::string>& expected,
                          std::string& error) {
    const std::string sql = std::string("PRAGMA table_info('") + table + "');";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    std::vector<std::string> actual;
    int step = SQLITE_OK;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(statement, 1);
        if (name == nullptr) {
            sqlite3_finalize(statement);
            error = std::string("invalid column metadata for ") + table;
            return false;
        }
        actual.emplace_back(reinterpret_cast<const char*>(name));
    }
    if (step != SQLITE_DONE) {
        error = sqlite3_errmsg(database);
        sqlite3_finalize(statement);
        return false;
    }
    sqlite3_finalize(statement);
    if (std::set<std::string>(actual.begin(), actual.end()) !=
        std::set<std::string>(expected.begin(), expected.end())) {
        error = std::string("device database table has incompatible columns: ") + table;
        return false;
    }
    return true;
}

bool hasExpectedTableLayout(sqlite3* database, std::string& error) {
    std::vector<std::string> deviceColumns = {
        "id", "device_hash", "devpath", "subsystem", "device_type",
        "parent_id", "control_level", "control_explicit",
        "ignore_hierarchy", "boot_id", "created_at", "last_event_at",
        "notes", "children_control"
    };
    return hasExpectedApplicationTables(database, error) &&
        tableHasExactColumns(database, "devices", deviceColumns, error) &&
        tableHasExactColumns(database, "device_attributes", {
            "id", "device_id", "attribute_name", "attribute_value"
        }, error) &&
        tableHasExactColumns(database, "device_events", {
            "id", "device_id", "event_type", "event_result",
            "event_details", "created_at"
        }, error) &&
        tableHasExactColumns(database, "device_tree_state", {
            "id", "revision"
        }, error) &&
        tableHasExactColumns(database, "device_policy_state", {
            "id", "desired_revision", "active_revision", "block_usb_storage",
            "block_printers_scanners", "block_optical_drives"
        }, error);
}

bool hasExpectedIndexesAndTriggers(sqlite3* database, std::string& error) {
    constexpr const char* sql =
        "SELECT "
        "sum(CASE WHEN type='index' AND name IN ("
        "'idx_devices_hash','idx_devices_devpath','idx_devices_parent',"
        "'idx_devices_control','idx_devices_subsystem') THEN 1 ELSE 0 END),"
        "sum(CASE WHEN type='trigger' AND name IN ("
        "'device_tree_revision_devices_insert',"
        "'device_tree_revision_devices_update',"
        "'device_tree_revision_devices_delete',"
        "'device_tree_revision_attributes_insert',"
        "'device_tree_revision_attributes_update',"
        "'device_tree_revision_attributes_delete',"
        "'device_tree_revision_events_insert',"
        "'device_tree_revision_events_update',"
        "'device_tree_revision_events_delete',"
        "'device_policy_revision_devices_update',"
        "'device_policy_revision_devices_delete') THEN 1 ELSE 0 END) "
        "FROM sqlite_master;";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    const bool valid = sqlite3_step(statement) == SQLITE_ROW &&
        sqlite3_column_int(statement, 0) == 5 &&
        sqlite3_column_int(statement, 1) == 11;
    sqlite3_finalize(statement);
    if (!valid) {
        error = "device database is missing required indexes or revision triggers";
    }
    return valid;
}

bool hasRequiredBaselineRows(sqlite3* database, std::string& error) {
    constexpr const char* sql =
        "SELECT count(*) FROM devices d WHERE "
        "(d.device_hash='virtual_computer_root_sha256_placeholder' "
        " AND d.devpath='/' AND d.subsystem='__computer__' "
        " AND d.device_type='computer' AND d.parent_id IS NULL) OR "
        "(d.device_hash='virtual_container_cpu_sha256_placeholder' "
        " AND d.devpath='/cpu_list' AND d.subsystem='__cpu__' "
        " AND d.device_type='container_cpu' AND d.parent_id=(SELECT id FROM devices "
        " WHERE device_hash='virtual_computer_root_sha256_placeholder' LIMIT 1)) OR "
        "(d.device_hash='virtual_container_memory_sha256_placeholder' "
        " AND d.devpath='/memory_list' AND d.subsystem='__memory__' "
        " AND d.device_type='container_memory' AND d.parent_id=(SELECT id FROM devices "
        " WHERE device_hash='virtual_computer_root_sha256_placeholder' LIMIT 1)) OR "
        "(d.device_hash='virtual_container_board_sha256_placeholder' "
        " AND d.devpath='/board_list' AND d.subsystem='__board__' "
        " AND d.device_type='container_board' AND d.parent_id=(SELECT id FROM devices "
        " WHERE device_hash='virtual_computer_root_sha256_placeholder' LIMIT 1)) OR "
        "(d.device_hash='virtual_container_udev_sha256_placeholder' "
        " AND d.devpath='/devices' AND d.subsystem='__udev__' "
        " AND d.device_type='container_udev' AND d.parent_id=(SELECT id FROM devices "
        " WHERE device_hash='virtual_computer_root_sha256_placeholder' LIMIT 1)) OR "
        "(d.device_hash='virtual_container_pci_sha256_placeholder' "
        " AND d.devpath='/devices/pci0000:00' AND d.subsystem='__pci__' "
        " AND d.device_type='container_pci' AND d.parent_id=(SELECT id FROM devices "
        " WHERE device_hash='virtual_container_udev_sha256_placeholder' LIMIT 1));";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    const bool valid = sqlite3_step(statement) == SQLITE_ROW &&
        sqlite3_column_int(statement, 0) == 6;
    sqlite3_finalize(statement);
    if (!valid) {
        error = "device database is missing the canonical virtual root hierarchy";
    }
    return valid;
}

bool integrityChecksPass(sqlite3* database, std::string& error) {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, "PRAGMA quick_check;", -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    const bool quickOk = sqlite3_step(statement) == SQLITE_ROW &&
        std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0))) == "ok";
    sqlite3_finalize(statement);
    if (!quickOk) {
        error = "SQLite quick_check failed";
        return false;
    }
    if (sqlite3_prepare_v2(database, "PRAGMA foreign_key_check;", -1, &statement, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database);
        return false;
    }
    const bool foreignKeysOk = sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    if (!foreignKeysOk) {
        error = "SQLite foreign_key_check failed";
    }
    return foreignKeysOk;
}

} // namespace

DB::DB(DBOptions options)
    : db_path(validatedDatabasePath(options)),
      db(nullptr),
      databaseHadContent_(databaseHasContent(options.databaseFile)),
      lock_(std::make_unique<ExclusivePidLock>(options.lockFile.string(),
                                               options.lockDebugLogFile.string(),
                                               options.lockDebugEnabled)) {

    while(!this->acquireLock()){
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Открываем базу данных только после получения блокировки
    if (!openDatabase()) {
        releaseLock();
        this->log("Failed to open database", logLevel::FATAL);
        throw std::runtime_error("Failed to open database");
    }

}

DB::~DB() {
    closeDatabase();
    releaseLock();
}


bool DB::acquireLock() {
    return lock_->acquire();
}

void DB::releaseLock() {
    lock_->release();

}

bool DB::log(std::string message, logLevel logLev) {
    if(message.empty()){
       return true;
    }
    //Логгируем действия в БД
    return Logger::log(message, logLev, "db");
}


bool DB::openDatabase() {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        this->log("Cannot open database: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
        //Защищаемся от утечки памяти
        sqlite3_close(db);
        db = nullptr;
        return false;
    }

    if (::chmod(db_path.c_str(), 0640) != 0) {
        this->log("Cannot enforce database permissions: " +
                      std::string(std::strerror(errno)),
                  logLevel::FATAL);
        sqlite3_close(db);
        db = nullptr;
        return false;
    }

    sqlite3_busy_timeout(db, 5000);

    // Включаем поддержку внешних ключей
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);

    return true;
}

void DB::closeDatabase() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}
// Получить устройство по хешу
DeviceInfo DB::getDeviceByHash(const std::string& device_hash) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE device_hash = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1}; // Возвращаем устройство с id = -1 при ошибке
    }

    sqlite3_bind_text(stmt, 1, device_hash.c_str(), -1, SQLITE_TRANSIENT);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}

DeviceInfo DB::getDeviceById(int id) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE id = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1};
    }

    sqlite3_bind_int(stmt, 1, id);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}

std::map<std::string, std::string> DB::getDeviceAttributes(int device_id) {
    std::map<std::string, std::string> attributesMap;

    const char* sql = "SELECT attribute_name, attribute_value "
                     "FROM device_attributes WHERE device_id = ? "
                     "ORDER BY attribute_name";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return attributesMap; // Возвращаем пустой словарь при ошибке
    }

    sqlite3_bind_int(stmt, 1, device_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Получаем название атрибута
        std::string attribute_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        // Получаем значение атрибута (обрабатываем NULL)
        std::string attribute_value;
        if (sqlite3_column_type(stmt, 1) == SQLITE_NULL) {
            attribute_value = "";
        } else {
            attribute_value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }

        // Добавляем в словарь
        attributesMap[attribute_name] = attribute_value;
    }

    sqlite3_finalize(stmt);
    return attributesMap;
}

/*
DeviceAttribute DB::resultToDeviceAttribute(sqlite3_stmt* stmt) {
    DeviceAttribute attr;

    attr.id = sqlite3_column_int(stmt, 0);
    attr.device_id = sqlite3_column_int(stmt, 1);
    attr.attribute_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

    // Обработка attribute_value (может быть NULL)
    if (sqlite3_column_type(stmt, 3) == SQLITE_NULL) {
        attr.attribute_value = "";
    } else {
        attr.attribute_value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    }

    return attr;
}
*/
/*
std::map<std::string, std::string> DB::getDeviceAttributesMap(int device_id) {
    std::map<std::string, std::string> attributesMap;

    auto attributes = getDeviceAttributes(device_id);
    for (const auto& attr : attributes) {
        attributesMap[attr.attribute_name] = attr.attribute_value;
    }

    return attributesMap;
}
*/

std::string DB::getDeviceAttribute(int device_id, const std::string& attribute_name, const std::string& default_string) {
    const char* sql = "SELECT attribute_value FROM device_attributes "
                     "WHERE device_id = ? AND attribute_name = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return default_string; // Возвращаем значение по умолчанию при ошибке
    }

    sqlite3_bind_int(stmt, 1, device_id);
    sqlite3_bind_text(stmt, 2, attribute_name.c_str(), -1, SQLITE_TRANSIENT);

    std::string result = default_string;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Проверяем, не NULL ли значение в базе
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            //Игнорируем null и пустую строку
            if (value != nullptr && value[0] != '\0') {
                result = value;
            }
        }
        // Если значение NULL в базе, оставляем default_string
    }

    sqlite3_finalize(stmt);
    return result;
}

// Получить устройство по пути
DeviceInfo DB::getDeviceByPath(const std::string& devpath) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE devpath = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1}; // Возвращаем устройство с id = -1 при ошибке
    }

    sqlite3_bind_text(stmt, 1, devpath.c_str(), -1, SQLITE_TRANSIENT);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}


DeviceInfo DB::resultToDeviceInfo(sqlite3_stmt* stmt) {
    DeviceInfo device;

    device.id = sqlite3_column_int(stmt, 0);
    device.device_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    device.devpath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    device.subsystem = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    device.device_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));

    // Обработка parent_id (может быть NULL)
    if (sqlite3_column_type(stmt, 5) == SQLITE_NULL) {
        device.parent_id = -1;
    } else {
        device.parent_id = sqlite3_column_int(stmt, 5);
    }

    device.control_level = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
    device.control_explicit = sqlite3_column_int(stmt, 7) != 0;
    device.ignore_hierarchy = sqlite3_column_int(stmt, 8) != 0;

    //
    if (sqlite3_column_type(stmt, 9) == SQLITE_NULL) {
        device.boot_id = "";
    } else {
        device.boot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    }

    device.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
    device.last_event_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));

    // Обработка notes (может быть NULL)
    if (sqlite3_column_type(stmt, 12) == SQLITE_NULL) {
        device.notes = "";
    } else {
        device.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
    }
    device.children_control = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));

    return device;
}

bool DB::initializeDatabase() {
    log("Начало инициализации БД, PID: " + std::to_string(getpid()), logLevel::TRACE);
    if (!databaseHadContent_) {
        const std::string versionSql =
            std::string("PRAGMA application_id=") +
                std::to_string(fic::version::DEVICE_DB_APPLICATION_ID) + ";" +
            "PRAGMA user_version=" +
                std::to_string(fic::version::DEVICE_DB_SCHEMA_VERSION) + ";";
        if (!executeSql(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", lastError_) ||
            !executeSql(db, "BEGIN IMMEDIATE;", lastError_) ||
            !executeSql(db, SCHEMA_SQL, lastError_) ||
            !executeSql(db, INDEX_SQL, lastError_) ||
            !executeSql(db, BASELINE_DATA_SQL, lastError_) ||
            !executeSql(db, versionSql, lastError_) ||
            !executeSql(db, "COMMIT;", lastError_)) {
            std::string rollbackError;
            executeSql(db, "ROLLBACK;", rollbackError);
            log("Failed to create device database schema: " + lastError_, logLevel::FATAL);
            return false;
        }
        databaseHadContent_ = true;
    }

    if (!verifyDatabaseSchema(lastError_)) {
        log("Device database schema verification failed: " + lastError_, logLevel::FATAL);
        return false;
    }
    if (!executeSql(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", lastError_)) {
        log("Failed to configure device database runtime pragmas: " + lastError_, logLevel::FATAL);
        return false;
    }
    return true;
}

bool DB::verifyDatabaseSchemaMetadata(std::string& error) {
    int applicationId = 0;
    int schemaVersion = 0;
    if (!readPragmaInt(db, "application_id", applicationId, error) ||
        !readPragmaInt(db, "user_version", schemaVersion, error)) {
        return false;
    }
    if (applicationId != static_cast<int>(fic::version::DEVICE_DB_APPLICATION_ID)) {
        error = applicationId == 0
            ? "unversioned device database is unsupported"
            : "database application_id does not identify a FIC device database";
        return false;
    }
    if (schemaVersion != fic::version::DEVICE_DB_SCHEMA_VERSION) {
        error = schemaVersion > fic::version::DEVICE_DB_SCHEMA_VERSION
            ? "device database schema is newer than this binary"
            : "device database schema is unsupported";
        return false;
    }
    return hasExpectedTableLayout(db, error) &&
        hasExpectedIndexesAndTriggers(db, error) &&
        hasRequiredBaselineRows(db, error);
}

bool DB::verifyDatabaseSchema(std::string& error) {
    return verifyDatabaseSchemaMetadata(error) && integrityChecksPass(db, error);
}

const std::string& DB::lastError() const {
    return lastError_;
}

std::int64_t DB::getDeviceTreeRevision()
{
    const char* sql = "SELECT revision FROM device_tree_state WHERE id = 1";
    sqlite3_stmt* stmt = nullptr;
    const int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        this->log("Failed to prepare device tree revision query: " +
                      std::string(sqlite3_errmsg(db)),
                  logLevel::DEBUG);
        return -1;
    }

    std::int64_t revision = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        revision = sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return revision;
}

bool DB::getDeviceTreeSnapshot(int rootId,
                               bool includeDisconnected,
                               const std::string& bootId,
                               DeviceTreeSnapshot& snapshot,
                               std::string& error)
{
    DeviceTreeSnapshot candidate;
    auto fail = [&](const std::string& message) {
        error = message;
        std::string rollbackError;
        executeSql(db, "ROLLBACK;", rollbackError);
        return false;
    };
    auto textColumn = [](sqlite3_stmt* statement, int column,
                         std::string& value) {
        if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
            value.clear();
            return true;
        }
        const unsigned char* text = sqlite3_column_text(statement, column);
        if (text == nullptr) {
            return false;
        }
        value = reinterpret_cast<const char*>(text);
        return true;
    };
    auto readDevice = [&](sqlite3_stmt* statement, DeviceInfo& device) {
        device.id = sqlite3_column_int(statement, 0);
        if (device.id <= 0 ||
            !textColumn(statement, 1, device.device_hash) ||
            !textColumn(statement, 2, device.devpath) ||
            !textColumn(statement, 3, device.subsystem) ||
            !textColumn(statement, 4, device.device_type) ||
            !textColumn(statement, 6, device.control_level) ||
            !textColumn(statement, 9, device.boot_id) ||
            !textColumn(statement, 10, device.created_at) ||
            !textColumn(statement, 11, device.last_event_at) ||
            !textColumn(statement, 12, device.notes) ||
            !textColumn(statement, 13, device.children_control)) {
            return false;
        }
        device.parent_id = sqlite3_column_type(statement, 5) == SQLITE_NULL
            ? -1 : sqlite3_column_int(statement, 5);
        device.control_explicit = sqlite3_column_int(statement, 7) != 0;
        device.ignore_hierarchy = sqlite3_column_int(statement, 8) != 0;
        return true;
    };

    if (rootId <= 0 || !executeSql(db, "BEGIN TRANSACTION;", error)) {
        if (rootId <= 0) {
            error = "invalid device tree root";
        }
        return false;
    }

    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT revision FROM device_tree_state WHERE id = 1", -1,
            &statement, nullptr) != SQLITE_OK) {
        return fail("failed to read device tree revision: " +
                    std::string(sqlite3_errmsg(db)));
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return fail("device tree revision is missing");
    }
    candidate.revision = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);

    constexpr const char* treeSql =
        "WITH RECURSIVE tree(id, depth, path, cycle, depth_exceeded) AS ("
        " SELECT id, 0, printf('/%d/', id), 0, 0 FROM devices WHERE id = ?1"
        " UNION ALL"
        " SELECT child.id, tree.depth + 1, tree.path || child.id || '/',"
        "        instr(tree.path, printf('/%d/', child.id)) != 0,"
        "        tree.depth >= 1024"
        " FROM devices child JOIN tree ON child.parent_id = tree.id"
        " WHERE tree.cycle = 0 AND tree.depth_exceeded = 0"
        "   AND (?2 OR child.boot_id = '-1' OR child.boot_id = ?3)"
        ")"
        " SELECT d.id,d.device_hash,d.devpath,d.subsystem,d.device_type,d.parent_id,"
        " d.control_level,d.control_explicit,d.ignore_hierarchy,d.boot_id,"
        " d.created_at,d.last_event_at,d.notes,d.children_control,"
        " a.attribute_name,a.attribute_value,tree.cycle,tree.depth_exceeded"
        " FROM tree JOIN devices d ON d.id = tree.id"
        " LEFT JOIN device_attributes a ON a.device_id = d.id"
        " ORDER BY tree.depth,d.id,a.attribute_name";
    if (sqlite3_prepare_v2(db, treeSql, -1, &statement, nullptr) != SQLITE_OK) {
        return fail("failed to prepare device tree snapshot: " +
                    std::string(sqlite3_errmsg(db)));
    }
    sqlite3_bind_int(statement, 1, rootId);
    sqlite3_bind_int(statement, 2, includeDisconnected ? 1 : 0);
    sqlite3_bind_text(statement, 3, bootId.c_str(), -1, SQLITE_TRANSIENT);
    std::map<int, std::size_t> entryById;
    int step = SQLITE_OK;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        if (sqlite3_column_int(statement, 16) != 0 ||
            sqlite3_column_int(statement, 17) != 0) {
            const bool cycle = sqlite3_column_int(statement, 16) != 0;
            sqlite3_finalize(statement);
            return fail(cycle
                ? "cycle detected in device tree"
                : "device tree exceeds maximum depth of 1024");
        }
        DeviceInfo device;
        if (!readDevice(statement, device)) {
            sqlite3_finalize(statement);
            return fail("malformed device row in tree snapshot");
        }
        auto [position, inserted] = entryById.emplace(
            device.id, candidate.entries.size());
        if (inserted) {
            candidate.entries.push_back({device, {}});
        }
        if (sqlite3_column_type(statement, 14) != SQLITE_NULL) {
            std::string name;
            std::string value;
            if (!textColumn(statement, 14, name) || name.empty() ||
                !textColumn(statement, 15, value)) {
                sqlite3_finalize(statement);
                return fail("malformed device attribute in tree snapshot");
            }
            candidate.entries[position->second].attributes.emplace(name, value);
        }
    }
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE) {
        return fail("failed to read device tree snapshot: " +
                    std::string(sqlite3_errmsg(db)));
    }
    if (candidate.entries.empty() || candidate.entries.front().device.id != rootId) {
        return fail("device tree root was not found");
    }

    constexpr const char* allSql =
        "SELECT id,device_hash,devpath,subsystem,device_type,parent_id,"
        "control_level,control_explicit,ignore_hierarchy,boot_id,created_at,"
        "last_event_at,notes,children_control FROM devices ORDER BY id";
    if (sqlite3_prepare_v2(db, allSql, -1, &statement, nullptr) != SQLITE_OK) {
        return fail("failed to prepare identity snapshot: " +
                    std::string(sqlite3_errmsg(db)));
    }
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        DeviceInfo device;
        if (!readDevice(statement, device)) {
            sqlite3_finalize(statement);
            return fail("malformed device row in identity snapshot");
        }
        candidate.identityOccurrences.push_back(std::move(device));
    }
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE) {
        return fail("failed to read identity snapshot: " +
                    std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_prepare_v2(db,
            "SELECT block_usb_storage,block_printers_scanners,"
            "block_optical_drives FROM device_policy_state WHERE id = 1",
            -1, &statement, nullptr) != SQLITE_OK) {
        return fail("failed to prepare category policy snapshot: " +
                    std::string(sqlite3_errmsg(db)));
    }
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return fail("device category policy state is missing");
    }
    candidate.categoryPolicy.block_usb_storage = sqlite3_column_int(statement, 0) != 0;
    candidate.categoryPolicy.block_printers_scanners = sqlite3_column_int(statement, 1) != 0;
    candidate.categoryPolicy.block_optical_drives = sqlite3_column_int(statement, 2) != 0;
    sqlite3_finalize(statement);

    if (!executeSql(db, "COMMIT;", error)) {
        return fail("failed to commit device tree snapshot: " + error);
    }
    snapshot = std::move(candidate);
    error.clear();
    return true;
}

std::int64_t DB::getDesiredPolicyRevision()
{
    const char* sql = "SELECT desired_revision FROM device_policy_state WHERE id = 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    const std::int64_t revision = sqlite3_step(stmt) == SQLITE_ROW
        ? sqlite3_column_int64(stmt, 0)
        : -1;
    sqlite3_finalize(stmt);
    return revision;
}

std::int64_t DB::getActivePolicyRevision()
{
    const char* sql = "SELECT active_revision FROM device_policy_state WHERE id = 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    const std::int64_t revision = sqlite3_step(stmt) == SQLITE_ROW
        ? sqlite3_column_int64(stmt, 0)
        : -1;
    sqlite3_finalize(stmt);
    return revision;
}

bool DB::setActivePolicyRevision(std::int64_t revision)
{
    const char* sql = "UPDATE device_policy_state SET active_revision = ? WHERE id = 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int64(stmt, 1, revision);
    const bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

DeviceCategoryPolicyState DB::getDeviceCategoryPolicyState()
{
    const char* sql =
        "SELECT block_usb_storage, block_printers_scanners, block_optical_drives "
        "FROM device_policy_state WHERE id = 1";
    sqlite3_stmt* stmt = nullptr;
    DeviceCategoryPolicyState state;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        state.block_usb_storage = sqlite3_column_int(stmt, 0) != 0;
        state.block_printers_scanners = sqlite3_column_int(stmt, 1) != 0;
        state.block_optical_drives = sqlite3_column_int(stmt, 2) != 0;
    }
    sqlite3_finalize(stmt);
    return state;
}

bool DB::updateDeviceCategoryPolicyState(const DeviceCategoryPolicyState& state)
{
    const char* sql =
        "UPDATE device_policy_state SET "
        "desired_revision = desired_revision + CASE WHEN "
        "block_usb_storage != ?1 OR block_printers_scanners != ?2 OR "
        "block_optical_drives != ?3 THEN 1 ELSE 0 END, "
        "block_usb_storage = ?1, block_printers_scanners = ?2, "
        "block_optical_drives = ?3 WHERE id = 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int(stmt, 1, state.block_usb_storage ? 1 : 0);
    sqlite3_bind_int(stmt, 2, state.block_printers_scanners ? 1 : 0);
    sqlite3_bind_int(stmt, 3, state.block_optical_drives ? 1 : 0);
    const bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

DeviceInfo DB::getDeviceByPathAndBootId(const std::string& devpath, const std::string& boot_id){
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE devpath = ? AND boot_id = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1};
    }

    sqlite3_bind_text(stmt, 1, devpath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, boot_id.c_str(), -1, SQLITE_TRANSIENT);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}
// В методе addDevice:
int DB::addDevice(const DeviceInfo& device) {
    const char* sql = "INSERT INTO devices (device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, notes, children_control) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        this->log("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)), logLevel::DEBUG);
        //std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    sqlite3_bind_text(stmt, 1, device.device_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, device.devpath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, device.subsystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, device.device_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, device.parent_id);
    sqlite3_bind_text(stmt, 6, device.control_level.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, device.control_explicit ? 1 : 0);
    sqlite3_bind_int(stmt, 8, device.ignore_hierarchy ? 1 : 0);
    sqlite3_bind_text(stmt, 9, device.boot_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, device.notes.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, device.children_control.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    int device_id = -1;

    if (rc == SQLITE_DONE) {
        device_id = sqlite3_last_insert_rowid(db);
    } else {
        this->log("Failed to insert device: " + std::string(sqlite3_errmsg(db)), logLevel::DEBUG);
        //std::cerr << "Failed to insert device: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    return device_id;
}

int DB::getDeviceIdByPath(const std::string& devpath) {
    const char* sql = "SELECT id FROM devices WHERE devpath = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    sqlite3_bind_text(stmt, 1, devpath.c_str(), -1, SQLITE_TRANSIENT);

    int device_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device_id = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return device_id;
}

bool DB::addDeviceAttribute(int device_id, const std::string& name, const std::string& value) {
    const char* sql = "INSERT OR REPLACE INTO device_attributes (device_id, attribute_name, attribute_value) "
                     "VALUES (?, ?, ?)";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, device_id);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, value.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success) {
        std::cerr << "Failed to add attribute: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
    return success;
}

DeviceInfo DB::getComputerRoot() {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices "
                     "WHERE device_hash = 'virtual_computer_root_sha256_placeholder' "
                     "AND subsystem = '__computer__' "
                     "AND device_type = 'computer' "
                     "LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1};
    }

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}

int DB::getVirtualContainerId(const std::string& container_type) {
    std::string container_hash;

    if (container_type == "cpu") {
        container_hash = "virtual_container_cpu_sha256_placeholder";
    } else if (container_type == "memory") {
        container_hash = "virtual_container_memory_sha256_placeholder";
    } else if (container_type == "board") {
        container_hash = "virtual_container_board_sha256_placeholder";
    } else if (container_type == "devices") {
        //????
        container_hash = "virtual_container_udev_sha256_placeholder";
    } else {
        return -1;
    }

    const char* sql = "SELECT id FROM devices WHERE device_hash = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, container_hash.c_str(), -1, SQLITE_TRANSIENT);

    int container_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        container_id = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return container_id;
}

bool DB::updateDevice(const DeviceInfo& device, const int& device_id){
    const char* sql = "UPDATE devices SET device_hash = ?, devpath = ?, subsystem = ?, device_type = ?, "
                      "parent_id = ?, control_level = ?, control_explicit = ?, ignore_hierarchy = ?, boot_id = ?, notes = ?, children_control = ? "
                      "WHERE id = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, device.device_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, device.devpath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, device.subsystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, device.device_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, device.parent_id);
    sqlite3_bind_text(stmt, 6, device.control_level.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, device.control_explicit ? 1 : 0);
    sqlite3_bind_int(stmt, 8, device.ignore_hierarchy ? 1 : 0);
    sqlite3_bind_text(stmt, 9, device.boot_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, device.notes.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, device.children_control.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 12, device_id);

    // Выполнение UPDATE
    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success) {
        this->log("Failed to execute statement: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
    }

    sqlite3_finalize(stmt);
    return success;
}
// Получить непосредственных потомков устройства
bool DB::updateDeviceControlLevel(int device_id, const std::string& control_level)
{
    const char* sql = "UPDATE devices SET control_level = ?, control_explicit = 1 WHERE id = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, control_level.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, device_id);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success) {
        this->log("Failed to update device control_level: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
    }

    sqlite3_finalize(stmt);
    return success;
}

bool DB::updateDeviceControl(int device_id,
                             const std::string& control_level,
                             bool control_explicit,
                             bool ignore_hierarchy,
                             const std::string& children_control)
{
    const char* sql = "UPDATE devices SET control_level = ?, control_explicit = ?, "
                      "ignore_hierarchy = ?, children_control = ? WHERE id = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, control_level.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, control_explicit ? 1 : 0);
    sqlite3_bind_int(stmt, 3, ignore_hierarchy ? 1 : 0);
    sqlite3_bind_text(stmt, 4, children_control.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, device_id);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success) {
        this->log("Failed to update device control fields: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
    }

    sqlite3_finalize(stmt);
    return success;
}

bool DB::updateDeviceIgnoreHierarchy(int device_id, bool ignore_hierarchy)
{
    const char* sql = "UPDATE devices SET ignore_hierarchy = ? WHERE id = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, ignore_hierarchy ? 1 : 0);
    sqlite3_bind_int(stmt, 2, device_id);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success) {
        this->log("Failed to update device ignore_hierarchy: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
    }

    sqlite3_finalize(stmt);
    return success;
}

bool DB::updateDeviceChildrenControl(int device_id, const std::string& children_control)
{
    const char* sql = "UPDATE devices SET children_control = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        this->log("Failed to prepare children_control update: " +
                      std::string(sqlite3_errmsg(db)),
                  logLevel::FATAL);
        return false;
    }
    sqlite3_bind_text(stmt, 1, children_control.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, device_id);
    const bool success = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) > 0;
    if (!success) {
        this->log("Failed to update device children_control: " +
                      std::string(sqlite3_errmsg(db)),
                  logLevel::FATAL);
    }
    sqlite3_finalize(stmt);
    return success;
}

bool DB::deleteDevice(int device_id)
{
    const char* sql = "DELETE FROM devices WHERE id = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, device_id);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE && sqlite3_changes(db) > 0);

    if (!success) {
        this->log("Failed to delete device: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
    }

    sqlite3_finalize(stmt);
    return success;
}

std::vector<DeviceInfo> DB::getChildDevices(int parent_id) {
    std::vector<DeviceInfo> children;

    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE parent_id = ?";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return children; // Возвращаем пустой вектор при ошибке
    }

    // Привязываем параметр parent_id
    if (parent_id > 0) {
        sqlite3_bind_int(stmt, 1, parent_id);
    } else {
        // Если parent_id <= 0 (например, -1 для корневых устройств), ищем устройства без родителя
        sqlite3_bind_null(stmt, 1);
    }

    // Обрабатываем результаты
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DeviceInfo device = resultToDeviceInfo(stmt);
        children.push_back(device);
    }

    sqlite3_finalize(stmt);
    return children;
}

std::vector<DeviceInfo> DB::getDescendantDevices(int parent_id) {
    std::vector<DeviceInfo> descendants;
    for (const DeviceInfo& child : getChildDevices(parent_id)) {
        descendants.push_back(child);
        std::vector<DeviceInfo> childDescendants = getDescendantDevices(child.id);
        descendants.insert(descendants.end(), childDescendants.begin(), childDescendants.end());
    }
    return descendants;
}

DeviceInfo DB::getDeviceByHashAndSubsystem(const std::string& device_hash, const std::string& subsystem) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE device_hash = ? AND subsystem = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1}; // Возвращаем устройство с id = -1 при ошибке
    }

    sqlite3_bind_text(stmt, 1, device_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subsystem.c_str(), -1, SQLITE_TRANSIENT);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}

std::vector<DeviceInfo> DB::getDevicesByHashAndSubsystem(const std::string& device_hash, const std::string& subsystem) {
    std::vector<DeviceInfo> devices;
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE device_hash = ? AND subsystem = ? ORDER BY id";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return devices;
    }

    sqlite3_bind_text(stmt, 1, device_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subsystem.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        devices.push_back(resultToDeviceInfo(stmt));
    }

    sqlite3_finalize(stmt);
    return devices;
}

std::vector<DeviceInfo> DB::getAllDevices() {
    std::vector<DeviceInfo> devices;
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices ORDER BY id";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return devices;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        devices.push_back(resultToDeviceInfo(stmt));
    }

    sqlite3_finalize(stmt);
    return devices;
}

DeviceInfo DB::getDeviceByDevpathAndSubsystem(const std::string& devpath,
                                          const std::string& subsystem){
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE devpath = ? AND subsystem = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1}; // Возвращаем устройство с id = -1 при ошибке
    }

    sqlite3_bind_text(stmt, 1, devpath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subsystem.c_str(), -1, SQLITE_TRANSIENT);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;

}

// Метод для обновления boot_id по id устройства
DeviceInfo DB::getDeviceByDevpathSubsystemAndBootId(const std::string& devpath,
                                                    const std::string& subsystem,
                                                    const std::string& boot_id) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE devpath = ? AND subsystem = ? AND boot_id = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1};
    }

    sqlite3_bind_text(stmt, 1, devpath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subsystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, boot_id.c_str(), -1, SQLITE_TRANSIENT);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}

bool DB::updateBootId(int device_id, const std::string& boot_id) {
    this->log("Старт функции updateBootId с параметрами: device_id="+std::to_string(device_id)+"; boot_id="+boot_id, logLevel::TRACE);
    if (device_id <= 0) {
        this->log("Некорректный device_id", logLevel::FATAL);
        return false;
    }

    const char* sql = "UPDATE devices SET boot_id = ?, last_event_at = CURRENT_TIMESTAMP WHERE id = ?";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        this->log("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
        return false;
    }

    // Привязываем параметры
    sqlite3_bind_text(stmt, 1, boot_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, device_id);

    // Выполняем запрос
    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success) {
        this->log("Failed to update boot_id " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
    }

    sqlite3_finalize(stmt);

    // Проверяем, была ли обновлена хотя бы одна строка
    if (success && sqlite3_changes(db) == 0) {
        this->log("No device found with id " + std::to_string(device_id), logLevel::FATAL);
        return false;
    }

    this->log("Обновление boot_id было проведено успешно", logLevel::DEBUG);
    return success;
}


DeviceInfo DB::getDeviceByHashAndSubsystemAndParent(const std::string& device_hash,
                                                    const std::string& subsystem,
                                                    int parent_id) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE device_hash = ? AND subsystem = ? AND parent_id = ? LIMIT 1";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return DeviceInfo{-1};
    }

    sqlite3_bind_text(stmt, 1, device_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, subsystem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, parent_id);

    DeviceInfo device{-1};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        device = resultToDeviceInfo(stmt);
    }

    sqlite3_finalize(stmt);
    return device;
}

DeviceEvent DB::resultToDeviceEvent(sqlite3_stmt* stmt) {
    DeviceEvent event;
    event.id = sqlite3_column_int(stmt, 0);
    event.device_id = sqlite3_column_int(stmt, 1);
    event.event_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

    if (sqlite3_column_type(stmt, 3) == SQLITE_NULL) {
        event.event_result = "";
    } else {
        event.event_result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    }

    if (sqlite3_column_type(stmt, 4) == SQLITE_NULL) {
        event.event_details = "";
    } else {
        event.event_details = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    }

    event.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    return event;
}

int DB::addDeviceEvent(const DeviceEvent& event) {
    const char* sql = "INSERT INTO device_events (device_id, event_type, event_result, event_details) "
                     "VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        this->log("Failed to prepare device event insert: " + std::string(sqlite3_errmsg(db)), logLevel::DEBUG);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, event.device_id);
    sqlite3_bind_text(stmt, 2, event.event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, event.event_result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, event.event_details.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    int event_id = -1;
    if (rc == SQLITE_DONE) {
        event_id = static_cast<int>(sqlite3_last_insert_rowid(db));
    } else {
        this->log("Failed to insert device event: " + std::string(sqlite3_errmsg(db)), logLevel::DEBUG);
    }

    sqlite3_finalize(stmt);
    return event_id;
}

std::vector<DeviceEvent> DB::getDeviceEvents(int device_id, int limit) {
    std::vector<DeviceEvent> events;
    const char* sql = "SELECT id, device_id, event_type, event_result, event_details, created_at "
                     "FROM device_events WHERE device_id = ? ORDER BY id DESC LIMIT ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        this->log("Failed to prepare device events query: " + std::string(sqlite3_errmsg(db)), logLevel::DEBUG);
        return events;
    }

    sqlite3_bind_int(stmt, 1, device_id);
    sqlite3_bind_int(stmt, 2, limit > 0 ? limit : 100);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        events.push_back(resultToDeviceEvent(stmt));
    }

    sqlite3_finalize(stmt);
    return events;
}

std::vector<DeviceEvent> DB::getRecentEvents(const std::string& event_type, int limit) {
    std::vector<DeviceEvent> events;
    const bool filterByType = !event_type.empty();
    const char* sqlWithType = "SELECT id, device_id, event_type, event_result, event_details, created_at "
                             "FROM device_events WHERE event_type = ? ORDER BY id DESC LIMIT ?";
    const char* sqlAll = "SELECT id, device_id, event_type, event_result, event_details, created_at "
                         "FROM device_events ORDER BY id DESC LIMIT ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, filterByType ? sqlWithType : sqlAll, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        this->log("Failed to prepare recent device events query: " + std::string(sqlite3_errmsg(db)), logLevel::DEBUG);
        return events;
    }

    if (filterByType) {
        sqlite3_bind_text(stmt, 1, event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, limit > 0 ? limit : 100);
    } else {
        sqlite3_bind_int(stmt, 1, limit > 0 ? limit : 100);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        events.push_back(resultToDeviceEvent(stmt));
    }

    sqlite3_finalize(stmt);
    return events;
}

std::vector<DeviceInfo> DB::getDevicesByType(const std::string& device_type) {
    std::vector<DeviceInfo> devices;
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, control_explicit, ignore_hierarchy, boot_id, created_at, last_event_at, notes, children_control "
                     "FROM devices WHERE device_type = ? ORDER BY id";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return devices;
    }

    sqlite3_bind_text(stmt, 1, device_type.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        devices.push_back(resultToDeviceInfo(stmt));
    }

    sqlite3_finalize(stmt);
    return devices;
}

bool DB::deviceExists(const std::string& device_hash) {
    return getDeviceIdByHash(device_hash) > 0;
}

int DB::getDeviceIdByHash(const std::string& device_hash) {
    const char* sql = "SELECT id FROM devices WHERE device_hash = ? LIMIT 1";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, device_hash.c_str(), -1, SQLITE_TRANSIENT);
    int id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return id;
}

bool DB::beginTransaction() {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        this->log("Failed to begin transaction: " + std::string(err_msg), logLevel::DEBUG);
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool DB::commitTransaction() {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        this->log("Failed to commit transaction: " + std::string(err_msg), logLevel::DEBUG);
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool DB::rollbackTransaction() {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        this->log("Failed to rollback transaction: " + std::string(err_msg), logLevel::DEBUG);
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

DeviceAttribute DB::resultToDeviceAttribute(sqlite3_stmt* stmt) {
    DeviceAttribute attr;
    attr.id = sqlite3_column_int(stmt, 0);
    attr.device_id = sqlite3_column_int(stmt, 1);
    attr.attribute_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    if (sqlite3_column_type(stmt, 3) == SQLITE_NULL) {
        attr.attribute_value = "";
    } else {
        attr.attribute_value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    }
    return attr;
}
