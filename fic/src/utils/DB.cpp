#include "DB.h"
DB::DB(const std::string& db_path) : db_path(db_path),lock_("/opt/fic/log/db_lock") {

    while(!this->acquireLock()){
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    /*
    // Создаем путь для файла блокировки
    lock_path = db_path + ".lock";

    // Захватываем блокировку (бесконечное ожидание)
    if (!acquireLock()) {
        throw std::runtime_error("Failed to acquire database lock");
    }
    */
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
    return lock_.acquire();
}

void DB::releaseLock() {
    lock_.release();

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
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
    device.ignore_hierarchy = sqlite3_column_int(stmt, 7) != 0;

    //
    if (sqlite3_column_type(stmt, 8) == SQLITE_NULL) {
        device.boot_id = "";
    } else {
        device.boot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    }

    device.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    device.last_event_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));

    // Обработка notes (может быть NULL)
    if (sqlite3_column_type(stmt, 11) == SQLITE_NULL) {
        device.notes = "";
    } else {
        device.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
    }

    return device;
}

// В методе initializeDatabase:
bool DB::initializeDatabase() {
    log("Начало инициализации БД, PID: " + std::to_string(getpid()), logLevel::TRACE);
    auto hasColumn = [this](const std::string& tableName, const std::string& columnName) {
        std::string sql = "PRAGMA table_info(" + tableName + ")";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            this->log("Не удалось проверить структуру таблицы " + tableName + ": " +
                      std::string(sqlite3_errmsg(db)), logLevel::FATAL);
            return false;
        }

        bool found = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* name = sqlite3_column_text(stmt, 1);
            if (name != nullptr && columnName == reinterpret_cast<const char*>(name)) {
                found = true;
                break;
            }
        }

        sqlite3_finalize(stmt);
        return found;
    };
    // SQL для создания таблиц
    const char* sql =
        "PRAGMA foreign_keys = ON;"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"

        "CREATE TABLE IF NOT EXISTS devices ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    device_hash TEXT NOT NULL,"
        "    devpath TEXT,"
        "    subsystem TEXT NOT NULL,"
        "    device_type TEXT NOT NULL,"
        "    parent_id INTEGER,"
        "    control_level TEXT NOT NULL CHECK(control_level IN ('blocked', 'allowed', 'permanent', 'ignored')),"
        "    ignore_hierarchy BOOLEAN DEFAULT 0,"
        "    boot_id TEXT,"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    last_event_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    notes TEXT,"
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
        ");";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);

    if (rc != SQLITE_OK) {
        this->log("Ошибка инициализации БД:" + std::string(err_msg),logLevel::FATAL);
        sqlite3_free(err_msg);
        return false;
    }

    bool hasBootId = hasColumn("devices", "boot_id");
    const std::string legacyBootIdColumn = std::string("os_") + "timestart";
    bool hasLegacyBootIdColumn = hasColumn("devices", legacyBootIdColumn);
    if (!hasBootId && hasLegacyBootIdColumn) {
        std::string migrateSql = "ALTER TABLE devices RENAME COLUMN " + legacyBootIdColumn + " TO boot_id;";
        rc = sqlite3_exec(db, migrateSql.c_str(), nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            this->log("Ошибка миграции legacy колонки в boot_id: " + std::string(err_msg), logLevel::FATAL);
            sqlite3_free(err_msg);
            return false;
        }
    } else if (!hasBootId) {
        rc = sqlite3_exec(db, "ALTER TABLE devices ADD COLUMN boot_id TEXT;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            this->log("Failed to add boot_id column: " + std::string(err_msg), logLevel::FATAL);
            sqlite3_free(err_msg);
            return false;
        }
    }

    auto hasTable = [this](const std::string& tableName) {
        const char* sql = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            this->log("Failed to check table " + tableName + ": " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
            return false;
        }

        sqlite3_bind_text(stmt, 1, tableName.c_str(), -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return found;
    };

    auto foreignKeyHasOnDelete = [this](const std::string& tableName,
                                        const std::string& fromColumn,
                                        const std::string& referencedTable,
                                        const std::string& onDelete) {
        std::string sql = "PRAGMA foreign_key_list(" + tableName + ")";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            this->log("Failed to check foreign keys for " + tableName + ": " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
            return false;
        }

        bool found = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* fkTable = sqlite3_column_text(stmt, 2);
            const unsigned char* fkFrom = sqlite3_column_text(stmt, 3);
            const unsigned char* fkOnDelete = sqlite3_column_text(stmt, 6);
            if (fkTable != nullptr && fkFrom != nullptr && fkOnDelete != nullptr &&
                referencedTable == reinterpret_cast<const char*>(fkTable) &&
                fromColumn == reinterpret_cast<const char*>(fkFrom) &&
                onDelete == reinterpret_cast<const char*>(fkOnDelete)) {
                found = true;
                break;
            }
        }

        sqlite3_finalize(stmt);
        return found;
    };

    auto tableSqlContains = [this](const std::string& tableName, const std::string& fragment) {
        const char* sql = "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            this->log("Failed to read table SQL for " + tableName + ": " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
            return false;
        }

        sqlite3_bind_text(stmt, 1, tableName.c_str(), -1, SQLITE_TRANSIENT);
        bool contains = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* tableSql = sqlite3_column_text(stmt, 0);
            if (tableSql != nullptr) {
                contains = std::string(reinterpret_cast<const char*>(tableSql)).find(fragment) != std::string::npos;
            }
        }

        sqlite3_finalize(stmt);
        return contains;
    };

    auto execSql = [this, &err_msg](const std::string& sql, const std::string& errorMessage) {
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            this->log(errorMessage + ": " + std::string(err_msg), logLevel::FATAL);
            sqlite3_free(err_msg);
            err_msg = nullptr;
            return false;
        }

        return true;
    };

    bool migrateDevices = hasTable("devices") &&
        !foreignKeyHasOnDelete("devices", "parent_id", "devices", "CASCADE");
    bool migrateDeviceAttributes = hasTable("device_attributes") &&
        (!foreignKeyHasOnDelete("device_attributes", "device_id", "devices", "CASCADE") ||
         !tableSqlContains("device_attributes", "UNIQUE(device_id, attribute_name)"));
    bool migrateDeviceEvents = hasTable("device_events") &&
        !foreignKeyHasOnDelete("device_events", "device_id", "devices", "CASCADE");
    bool migrateLockHistory = hasTable("lock_history") &&
        !foreignKeyHasOnDelete("lock_history", "triggered_by_device_id", "devices", "SET NULL");

    if (migrateDevices || migrateDeviceAttributes || migrateDeviceEvents || migrateLockHistory) {
        if (!execSql("PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE TRANSACTION;",
                     "Failed to begin foreign key migration")) {
            sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
            return false;
        }

        bool migrated = true;
        if (migrateDevices) {
            migrated = migrated && execSql(
                "CREATE TABLE devices_new ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    device_hash TEXT NOT NULL,"
                "    devpath TEXT,"
                "    subsystem TEXT NOT NULL,"
                "    device_type TEXT NOT NULL,"
                "    parent_id INTEGER,"
                "    control_level TEXT NOT NULL CHECK(control_level IN ('blocked', 'allowed', 'permanent', 'ignored')),"
                "    ignore_hierarchy BOOLEAN DEFAULT 0,"
                "    boot_id TEXT,"
                "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "    last_event_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "    notes TEXT,"
                "    FOREIGN KEY (parent_id) REFERENCES devices(id) ON DELETE CASCADE"
                ");"
                "INSERT INTO devices_new (id, device_hash, devpath, subsystem, device_type, parent_id, control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes) "
                "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes FROM devices;"
                "DROP TABLE devices;"
                "ALTER TABLE devices_new RENAME TO devices;",
                "Failed to migrate devices table");
        }

        if (migrateDeviceAttributes) {
            migrated = migrated && execSql(
                "CREATE TABLE device_attributes_new ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    device_id INTEGER NOT NULL,"
                "    attribute_name TEXT NOT NULL,"
                "    attribute_value TEXT,"
                "    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,"
                "    UNIQUE(device_id, attribute_name)"
                ");"
                "INSERT OR IGNORE INTO device_attributes_new (id, device_id, attribute_name, attribute_value) "
                "SELECT id, device_id, attribute_name, attribute_value FROM device_attributes ORDER BY id;"
                "DROP TABLE device_attributes;"
                "ALTER TABLE device_attributes_new RENAME TO device_attributes;",
                "Failed to migrate device_attributes table");
        }

        if (migrateDeviceEvents) {
            migrated = migrated && execSql(
                "CREATE TABLE device_events_new ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    device_id INTEGER NOT NULL,"
                "    event_type TEXT NOT NULL CHECK(event_type IN ('connect', 'disconnect', 'block', 'allow', 'lock', 'unlock')),"
                "    event_result TEXT CHECK(event_result IN ('success', 'blocked_by_parent', 'blocked_by_policy', 'error', 'temporary_allowed')),"
                "    event_details TEXT,"
                "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE"
                ");"
                "INSERT INTO device_events_new (id, device_id, event_type, event_result, event_details, created_at) "
                "SELECT id, device_id, event_type, event_result, event_details, created_at FROM device_events;"
                "DROP TABLE device_events;"
                "ALTER TABLE device_events_new RENAME TO device_events;",
                "Failed to migrate device_events table");
        }

        if (migrateLockHistory) {
            migrated = migrated && execSql(
                "CREATE TABLE lock_history_new ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    lock_type TEXT NOT NULL CHECK(lock_type IN ('device', 'computer', 'user')),"
                "    reason TEXT NOT NULL,"
                "    triggered_by_device_id INTEGER,"
                "    admin_user TEXT,"
                "    unlocked_by TEXT,"
                "    locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "    unlocked_at TIMESTAMP,"
                "    FOREIGN KEY (triggered_by_device_id) REFERENCES devices(id) ON DELETE SET NULL"
                ");"
                "INSERT INTO lock_history_new (id, lock_type, reason, triggered_by_device_id, admin_user, unlocked_by, locked_at, unlocked_at) "
                "SELECT id, lock_type, reason, triggered_by_device_id, admin_user, unlocked_by, locked_at, unlocked_at FROM lock_history;"
                "DROP TABLE lock_history;"
                "ALTER TABLE lock_history_new RENAME TO lock_history;",
                "Failed to migrate lock_history table");
        }

        if (!migrated || !execSql("COMMIT;", "Failed to commit foreign key migration")) {
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
            return false;
        }

        sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);

        sqlite3_stmt* fkCheckStmt = nullptr;
        rc = sqlite3_prepare_v2(db, "PRAGMA foreign_key_check", -1, &fkCheckStmt, nullptr);
        if (rc != SQLITE_OK) {
            this->log("Failed to run foreign_key_check: " + std::string(sqlite3_errmsg(db)), logLevel::FATAL);
            return false;
        }

        bool hasForeignKeyErrors = (sqlite3_step(fkCheckStmt) == SQLITE_ROW);
        sqlite3_finalize(fkCheckStmt);
        if (hasForeignKeyErrors) {
            this->log("Foreign key errors remain after database migration", logLevel::FATAL);
            return false;
        }
    }

    // Создаем индексы
    const char* index_sql =
        "CREATE INDEX IF NOT EXISTS idx_devices_hash ON devices(device_hash);"
        "CREATE INDEX IF NOT EXISTS idx_devices_devpath ON devices(devpath);"
        "CREATE INDEX IF NOT EXISTS idx_devices_parent ON devices(parent_id);"
        "CREATE INDEX IF NOT EXISTS idx_devices_control ON devices(control_level);"
        "CREATE INDEX IF NOT EXISTS idx_devices_subsystem ON devices(subsystem);";

    rc = sqlite3_exec(db, index_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        this->log("Ошибка создания индексов БД: " + std::string(err_msg),logLevel::FATAL);
        sqlite3_free(err_msg);
        return false;
    }

    return true;
}

DeviceInfo DB::getDeviceByPathAndBootId(const std::string& devpath, const std::string& boot_id){
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
                     "control_level, ignore_hierarchy, boot_id, notes) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

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
    sqlite3_bind_int(stmt, 7, device.ignore_hierarchy ? 1 : 0);
    sqlite3_bind_text(stmt, 8, device.boot_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, device.notes.c_str(), -1, SQLITE_TRANSIENT);

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
                      "parent_id = ?, control_level = ?, ignore_hierarchy = ?, boot_id = ?, notes = ? "
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
    sqlite3_bind_int(stmt, 7, device.ignore_hierarchy ? 1 : 0);
    sqlite3_bind_text(stmt, 8, device.boot_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, device.notes.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 10, device_id);

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
    const char* sql = "UPDATE devices SET control_level = ? WHERE id = ?";
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
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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

DeviceInfo DB::getDeviceByHashAndSubsystem(const std::string& device_hash, const std::string& subsystem) {
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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

DeviceInfo DB::getDeviceByDevpathAndSubsystem(const std::string& devpath,
                                          const std::string& subsystem){
    const char* sql = "SELECT id, device_hash, devpath, subsystem, device_type, parent_id, "
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
                     "control_level, ignore_hierarchy, boot_id, created_at, last_event_at, notes "
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
