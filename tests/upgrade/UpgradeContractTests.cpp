#include <fic/core/FicRuntimePaths.h>
#include <fic/core/UpgradeManager.h>
#include <fic/device-db/DB.h>
#include <fic/version/ProductVersion.h>

#include <sqlite3.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr const char* CONFIG_FILES[] = {
    "DAC.conf", "DC.conf", "GLOBAL.conf", "IDENTITY_ACCESS.conf",
    "NET.conf", "OSS.conf", "SYSCTL.conf"
};

void executePragmas(const std::filesystem::path& databasePath,
                    const std::string& sql) {
    sqlite3* database = nullptr;
    assert(sqlite3_open(databasePath.c_str(), &database) == SQLITE_OK);
    char* error = nullptr;
    assert(sqlite3_exec(database, sql.c_str(), nullptr, nullptr, &error) == SQLITE_OK);
    sqlite3_free(error);
    sqlite3_close(database);
}

int readPragma(const std::filesystem::path& databasePath, const char* pragma) {
    sqlite3* database = nullptr;
    assert(sqlite3_open_v2(databasePath.c_str(), &database,
                           SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    sqlite3_stmt* statement = nullptr;
    const std::string sql = std::string("PRAGMA ") + pragma + ";";
    assert(sqlite3_prepare_v2(database, sql.c_str(), -1,
                              &statement, nullptr) == SQLITE_OK);
    assert(sqlite3_step(statement) == SQLITE_ROW);
    const int value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return value;
}

bool tableExists(const std::filesystem::path& databasePath, const char* table) {
    sqlite3* database = nullptr;
    assert(sqlite3_open_v2(databasePath.c_str(), &database,
                           SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    sqlite3_stmt* statement = nullptr;
    assert(sqlite3_prepare_v2(
        database,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?;",
        -1, &statement, nullptr) == SQLITE_OK);
    sqlite3_bind_text(statement, 1, table, -1, SQLITE_STATIC);
    const bool exists = sqlite3_step(statement) == SQLITE_ROW;
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return exists;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

mode_t fileMode(const std::filesystem::path& path) {
    struct stat info {};
    assert(::lstat(path.c_str(), &info) == 0);
    return info.st_mode & 07777;
}
} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-upgrade-contract-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "share/default-config");
    fs::create_directories(root / "log");
    fs::create_directories(root / "data");

    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.defaultConfigDir = root / "share/default-config";
    paths.logDir = root / "log";
    paths.dataDir = root / "data";
    paths.stateDir = root / "state";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";
    std::string error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    for (const char* fileName : CONFIG_FILES) {
        std::ofstream(paths.defaultConfigDir / fileName)
            << "default=" << fileName << "\n";
    }

    assert(fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    for (const char* fileName : CONFIG_FILES) {
        const fs::path working = paths.configDir / fileName;
        assert(fs::is_regular_file(working));
        assert(readFile(working) == readFile(paths.defaultConfigDir / fileName));
        assert(fileMode(working) == 0640);
    }

    const fs::path dac = paths.configDir / "DAC.conf";
    std::ofstream(dac, std::ios::binary | std::ios::trunc) << "custom DAC\n";
    assert(fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    assert(readFile(dac) == "custom DAC\n");

    fs::remove(dac);
    assert(fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    assert(readFile(dac) == readFile(paths.defaultConfigDir / "DAC.conf"));

    const fs::path symlinkTarget = root / "symlink-target";
    std::ofstream(symlinkTarget) << "must remain unchanged\n";
    fs::remove(dac);
    fs::create_symlink(symlinkTarget, dac);
    assert(!fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    assert(fs::is_symlink(dac));
    assert(readFile(symlinkTarget) == "must remain unchanged\n");
    fs::remove(dac);
    fs::create_directory(dac);
    assert(!fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    fs::remove(dac);

    const fs::path defaultDac = paths.defaultConfigDir / "DAC.conf";
    const std::string defaultDacContent = readFile(defaultDac);
    fs::remove(defaultDac);
    assert(!fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    fs::create_symlink(symlinkTarget, defaultDac);
    assert(!fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    assert(readFile(symlinkTarget) == "must remain unchanged\n");
    fs::remove(defaultDac);
    fs::create_directory(defaultDac);
    assert(!fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    fs::remove(defaultDac);
    std::ofstream(defaultDac, std::ios::binary) << defaultDacContent;
    assert(fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    fs::remove(defaultDac);
    assert(!fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    assert(readFile(dac) == defaultDacContent);
    std::ofstream(defaultDac, std::ios::binary) << defaultDacContent;

    for (const char* fileName : CONFIG_FILES) {
        std::ofstream(paths.configDir / fileName, std::ios::trunc)
            << "sample.status=DISABLE\n";
    }
    assert(fic::core::UpgradeManager::ensureConfigs(
        paths.defaultConfigDir, paths.configDir, error));
    for (const char* fileName : CONFIG_FILES) {
        assert(readFile(paths.configDir / fileName) == "sample.status=DISABLE\n");
    }

    fic::core::UpgradeState upgrade;
    assert(fic::core::UpgradeManager::begin(
        paths.stateDir, fic::version::PRODUCT_VERSION, upgrade, error));
    assert(upgrade.phase == "prepared");
    assert(!fic::core::UpgradeManager::requireNoIncompleteUpgrade(
        paths.stateDir, error));

    fic::core::ConfigMigrationResult configMigration;
    assert(fic::core::UpgradeManager::migrateConfigs(
        paths.configDir, paths.stateDir, configMigration, error));
    assert(configMigration.migratedFiles == 7);
    for (const char* fileName : CONFIG_FILES) {
        assert(fs::is_regular_file(configMigration.backupDirectory / fileName));
    }
    assert(fic::core::UpgradeManager::verifyConfigs(paths.configDir, error));
    fic::core::ConfigMigrationResult resumedConfigMigration;
    assert(fic::core::UpgradeManager::migrateConfigs(
        paths.configDir, paths.stateDir, resumedConfigMigration, error));
    assert(resumedConfigMigration.migratedFiles == 0);

    const DBOptions options{
        paths.deviceDatabaseFile,
        paths.deviceDatabaseLockFile,
        paths.lockDebugLogFile,
        false
    };
    fs::copy_file(
        fs::path(FIC_TEST_SOURCE_DIR) / "fic/src/scripts/db/devices.db",
        paths.deviceDatabaseFile);
    fs::path primaryBackup;
    bool backupRecordedBeforeMigration = false;
    {
        DB database(options);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("offline migration") != std::string::npos);
        DBMigrationResult migration;
        assert(database.migrateDatabase(
            paths.stateDir / "db-backups", migration, error,
            [&](const fs::path& backup, std::string& callbackError) {
                if (!fic::core::UpgradeManager::recordDatabaseBackupIfActive(
                        paths.stateDir, backup, callbackError)) {
                    return false;
                }
                fic::core::UpgradeState recordedState;
                bool recordedStateExists = false;
                if (!fic::core::UpgradeManager::readState(
                        paths.stateDir, recordedState, recordedStateExists,
                        callbackError)) {
                    return false;
                }
                backupRecordedBeforeMigration = recordedStateExists &&
                    recordedState.phase == "config_migrated" &&
                    recordedState.databaseBackup == backup;
                return backupRecordedBeforeMigration;
            }));
        assert(migration.migrated);
        assert(migration.fromVersion == 0);
        assert(migration.toVersion == fic::version::DEVICE_DB_SCHEMA_VERSION);
        assert(fs::is_regular_file(migration.backupFile));
        primaryBackup = migration.backupFile;
        assert(readPragma(migration.backupFile, "user_version") == 0);
        assert(readPragma(migration.backupFile, "application_id") == 0);
        assert(database.initializeDatabase());
        DBMigrationResult resumedMigration;
        assert(database.migrateDatabase(
            paths.stateDir / "db-backups", resumedMigration, error));
        assert(!resumedMigration.migrated);
    }
    assert(backupRecordedBeforeMigration);
    assert(fic::core::UpgradeManager::markDatabaseMigratedIfActive(
        paths.stateDir, {}, error));
    bool stateExists = false;
    assert(fic::core::UpgradeManager::readState(
        paths.stateDir, upgrade, stateExists, error));
    assert(stateExists && upgrade.databaseBackup == primaryBackup);
    assert(fic::core::UpgradeManager::commit(paths.stateDir, error));
    assert(fs::is_regular_file(upgrade.transactionDirectory / "manifest"));
    {
        std::ifstream manifest(upgrade.transactionDirectory / "manifest");
        const std::string content(
            (std::istreambuf_iterator<char>(manifest)),
            std::istreambuf_iterator<char>());
        assert(content.find(primaryBackup.string()) != std::string::npos);
        assert(content.find("phase=committed") != std::string::npos);
    }
    fs::create_directories(root / "rollback/config");
    for (const char* fileName : CONFIG_FILES) {
        fs::copy_file(configMigration.backupDirectory / fileName,
                      root / "rollback/config" / fileName);
        std::ifstream restored(root / "rollback/config" / fileName);
        std::string firstLine;
        std::getline(restored, firstLine);
        assert(firstLine == "sample.status=DISABLE");
    }
    fs::copy_file(primaryBackup, root / "rollback/devices.db");
    assert(readPragma(root / "rollback/devices.db", "user_version") == 0);
    assert(fic::core::UpgradeManager::requireNoIncompleteUpgrade(
        paths.stateDir, error));

    fic::core::UpgradeState rejectedDowngrade;
    assert(!fic::core::UpgradeManager::begin(
        paths.stateDir, "0.0.0-0", rejectedDowngrade, error));
    assert(error.find("downgrade") != std::string::npos);

    fic::core::UpgradeState reinstall;
    assert(fic::core::UpgradeManager::begin(
        paths.stateDir, fic::version::PRODUCT_VERSION, reinstall, error));
    assert(reinstall.phase == "prepared");
    assert(fic::core::UpgradeManager::migrateConfigs(
        paths.configDir, paths.stateDir, resumedConfigMigration, error));
    assert(resumedConfigMigration.migratedFiles == 0);
    {
        DB database(options);
        DBMigrationResult migration;
        assert(database.migrateDatabase(
            paths.stateDir / "db-backups", migration, error));
        assert(!migration.migrated);
    }
    assert(fic::core::UpgradeManager::markDatabaseMigratedIfActive(
        paths.stateDir, {}, error));
    assert(fic::core::UpgradeManager::commit(paths.stateDir, error));

    DBOptions freshOptions = options;
    freshOptions.databaseFile = root / "data/fresh.db";
    freshOptions.lockFile = root / "log/fresh.lock";
    {
        DB freshDatabase(freshOptions);
        DBMigrationResult migration;
        assert(freshDatabase.migrateDatabase(
            paths.stateDir / "db-backups", migration, error));
        assert(migration.migrated);
        assert(migration.backupFile.empty());
        assert(freshDatabase.verifyDatabaseSchema(error));
        assert(freshDatabase.getComputerRoot().id > 0);
        assert(freshDatabase.getVirtualContainerId("devices") > 0);
    }

    DBOptions legacyOptions = options;
    legacyOptions.databaseFile = root / "data/legacy.db";
    legacyOptions.lockFile = root / "log/legacy.lock";
    fs::copy_file(
        fs::path(FIC_TEST_SOURCE_DIR) / "fic/src/scripts/db/devices.db",
        legacyOptions.databaseFile);
    {
        DB legacyDatabase(legacyOptions);
        assert(!legacyDatabase.initializeDatabase());
        DBMigrationResult migration;
        assert(legacyDatabase.migrateDatabase(
            paths.stateDir / "db-backups", migration, error));
        assert(migration.migrated);
        assert(!migration.backupFile.empty());
        assert(legacyDatabase.verifyDatabaseSchema(error));
        assert(!tableExists(legacyOptions.databaseFile, "system_settings"));
        assert(tableExists(migration.backupFile, "system_settings"));
    }

    DBOptions v1Options = options;
    v1Options.databaseFile = root / "data/v1.db";
    v1Options.lockFile = root / "log/v1.lock";
    fs::copy_file(
        fs::path(FIC_TEST_SOURCE_DIR) / "fic/src/scripts/db/devices.db",
        v1Options.databaseFile);
    executePragmas(
        v1Options.databaseFile,
        "PRAGMA application_id=" +
            std::to_string(fic::version::DEVICE_DB_APPLICATION_ID) +
            "; PRAGMA user_version=1;");
    {
        DB v1Database(v1Options);
        assert(!v1Database.initializeDatabase());
        DBMigrationResult migration;
        assert(v1Database.migrateDatabase(
            paths.stateDir / "db-backups", migration, error));
        assert(migration.migrated);
        assert(migration.fromVersion == 1);
        assert(migration.toVersion == fic::version::DEVICE_DB_SCHEMA_VERSION);
        assert(v1Database.verifyDatabaseSchema(error));
        assert(tableExists(v1Options.databaseFile, "device_policy_state"));
        assert(v1Database.getComputerRoot().children_control == "allow");
    }

    executePragmas(
        paths.deviceDatabaseFile,
        "PRAGMA user_version=" +
            std::to_string(fic::version::DEVICE_DB_SCHEMA_VERSION + 1) + ";");
    {
        DB database(options);
        assert(!database.initializeDatabase());
        DBMigrationResult migration;
        assert(!database.migrateDatabase(
            paths.stateDir / "db-backups", migration, error));
        assert(error.find("downgrade refused") != std::string::npos);
    }

    executePragmas(
        paths.deviceDatabaseFile,
        "PRAGMA user_version=" +
            std::to_string(fic::version::DEVICE_DB_SCHEMA_VERSION) +
            "; DROP INDEX idx_devices_hash;");
    {
        DB database(options);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("indexes") != std::string::npos);
    }

    std::ofstream(paths.configDir / "DAC.conf", std::ios::trunc)
        << "_schema_version=2\nsample.status=DISABLE\n";
    assert(!fic::core::UpgradeManager::verifyConfigs(paths.configDir, error));
    assert(error.find("newer than this binary") != std::string::npos);
    std::ofstream(paths.configDir / "DAC.conf", std::ios::trunc)
        << "_schema_version=" << fic::version::CONFIG_SCHEMA_VERSION
        << "\nsample.status=DISABLE\n";
    fs::remove(paths.configDir / "NET.conf");
    assert(!fic::core::UpgradeManager::verifyConfigs(paths.configDir, error));
    assert(error.find("missing or not a regular file") != std::string::npos);

    fs::remove_all(root);
    return 0;
}
