#include <fic/core/config/ConfigSchemaManager.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/device-db/DB.h>
#include <fic/version/ProductVersion.h>

#include <sqlite3.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;

constexpr const char* CONFIG_FILES[] = {
    "AUDIT.conf", "DAC.conf", "DC.conf", "GLOBAL.conf", "IDENTITY_ACCESS.conf",
    "FIREWALL.conf", "NET.conf", "OSS.conf", "SYSCTL.conf"
};

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void writeFile(const fs::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    assert(output.is_open());
    output << content;
    output.close();
    assert(output.good());
}

void executeSql(const fs::path& path, const std::string& sql) {
    sqlite3* database = nullptr;
    assert(sqlite3_open(path.c_str(), &database) == SQLITE_OK);
    char* message = nullptr;
    const int result = sqlite3_exec(
        database, sql.c_str(), nullptr, nullptr, &message);
    if (result != SQLITE_OK) {
        sqlite3_free(message);
    }
    assert(result == SQLITE_OK);
    sqlite3_close(database);
}

int readPragma(const fs::path& path, const char* name) {
    sqlite3* database = nullptr;
    assert(sqlite3_open_v2(
        path.c_str(), &database, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    sqlite3_stmt* statement = nullptr;
    const std::string sql = std::string("PRAGMA ") + name + ";";
    assert(sqlite3_prepare_v2(
        database, sql.c_str(), -1, &statement, nullptr) == SQLITE_OK);
    assert(sqlite3_step(statement) == SQLITE_ROW);
    const int value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return value;
}

DBOptions optionsFor(const fs::path& root, const std::string& name) {
    return {
        root / (name + ".db"),
        root / (name + ".lock"),
        root / (name + ".log"),
        false
    };
}

void createCurrentDatabase(const DBOptions& options) {
    DB database(options);
    assert(database.initializeDatabase());
    std::string error;
    assert(database.verifyDatabaseSchema(error));
}

bool ensureTestConfigs(const fs::path& defaults, const fs::path& working,
                       std::string& error, bool bootstrap = false) {
    return fic::core::ConfigSchemaManager::ensureConfigs(
        defaults, working, error, bootstrap,
        fic::core::ConfigAuthorityIdentity{::geteuid(), ::getegid()});
}

bool verifyTestConfigs(const fs::path& working, std::string& error) {
    return fic::core::ConfigSchemaManager::verifyConfigs(
        working, error,
        fic::core::ConfigAuthorityIdentity{::geteuid(), ::getegid()});
}

void testConfigContract(const fs::path& root) {
    const fs::path defaults = root / "default-config";
    const fs::path working = root / "config";
    fs::create_directories(defaults);
    for (const char* fileName : CONFIG_FILES) {
        writeFile(
            defaults / fileName,
            "_schema_version=" +
                std::to_string(fic::version::CONFIG_SCHEMA_VERSION) +
                "\nsample.status=DISABLE\n");
    }

    std::string error;
    assert(ensureTestConfigs(
        defaults, working, error, true));
    struct stat directoryInfo {};
    assert(::lstat(working.c_str(), &directoryInfo) == 0);
    assert((directoryInfo.st_mode & 07777) == 02750);
    assert(directoryInfo.st_uid == ::geteuid());
    assert(verifyTestConfigs(working, error));
    fs::remove(working / "GLOBAL.conf");
    assert(!ensureTestConfigs(
        defaults, working, error, true));
    assert(!fs::exists(working / "GLOBAL.conf"));
    fs::copy_file(defaults / "GLOBAL.conf", working / "GLOBAL.conf");
    fs::permissions(working, fs::perms::all, fs::perm_options::replace);
    fs::permissions(working / "GLOBAL.conf", fs::perms::all,
                    fs::perm_options::replace);
    assert(!ensureTestConfigs(
        defaults, working, error));
    assert(!verifyTestConfigs(working, error));
    assert((fs::status(working).permissions() & fs::perms::all) ==
           fs::perms::all);
    assert((fs::status(working / "GLOBAL.conf").permissions() & fs::perms::all) ==
           fs::perms::all);
    fs::permissions(working, fs::perms::owner_all, fs::perm_options::replace);
    fs::remove_all(working);
    assert(!ensureTestConfigs(
        defaults, working, error));
    assert(!fs::exists(working));
    assert(ensureTestConfigs(
        defaults, working, error, true));
    for (const char* fileName : CONFIG_FILES) {
        assert(readFile(working / fileName) == readFile(defaults / fileName));
        struct stat info {};
        assert(::lstat((working / fileName).c_str(), &info) == 0);
        assert((info.st_mode & 07777) == 0640);
    }

    const fs::path dac = working / "DAC.conf";
    const std::string custom = "_schema_version=1\ncustom.status=ENABLE\n";
    writeFile(dac, custom);
    assert(ensureTestConfigs(
        defaults, working, error));
    assert(readFile(dac) == custom);

    writeFile(dac, "custom.status=ENABLE\n");
    assert(ensureTestConfigs(
        defaults, working, error));
    assert(readFile(dac) == "custom.status=ENABLE\n");
    assert(!verifyTestConfigs(working, error));
    assert(error.find("does not declare") != std::string::npos);

    writeFile(dac, "_schema_version=0\ncustom.status=ENABLE\n");
    assert(!verifyTestConfigs(working, error));
    assert(error.find("unsupported configuration schema 0") != std::string::npos);

    writeFile(dac, "_schema_version=01\ncustom.status=ENABLE\n");
    assert(!verifyTestConfigs(working, error));
    assert(error.find("invalid _schema_version") != std::string::npos);

    writeFile(
        dac,
        "_schema_version=" +
            std::to_string(fic::version::CONFIG_SCHEMA_VERSION + 1) + "\n");
    assert(!verifyTestConfigs(working, error));
    assert(error.find("unsupported configuration schema") != std::string::npos);

    writeFile(dac, custom);
    assert(verifyTestConfigs(working, error));
}

void testModeAndOwnerFreshInstallConfig(const fs::path& root) {
    const fs::path defaults = root / "mode-owner-defaults";
    const fs::path working = root / "mode-owner-config";
    fs::create_directories(defaults);
    for (const char* fileName : CONFIG_FILES) {
        if (std::string(fileName) == "DAC.conf") {
            fs::copy_file(fs::path(FIC_SOURCE_DIR) /
                              "fic/src/resources/config/DAC.conf.in",
                          defaults / fileName);
        } else {
            writeFile(defaults / fileName,
                "_schema_version=" +
                std::to_string(fic::version::CONFIG_SCHEMA_VERSION) + "\n");
        }
    }
    std::string error;
    assert(ensureTestConfigs(
        defaults, working, error, true));
    const std::string dac = readFile(working / "DAC.conf");
    assert(dac.find("mode_and_owner_profiles.status=DISABLE") !=
           std::string::npos);
    assert(dac.find("mode_and_owner_profiles.value=") == std::string::npos);
}

void testConfigAuthorityRejection(const fs::path& root) {
    const fs::path defaults = root / "authority-defaults";
    const fs::path working = root / "authority-config";
    fs::create_directories(defaults);
    for (const char* fileName : CONFIG_FILES) {
        writeFile(defaults / fileName,
                  "_schema_version=" +
                  std::to_string(fic::version::CONFIG_SCHEMA_VERSION) + "\n");
    }
    std::string error;
    assert(ensureTestConfigs(defaults, working, error, true));
    auto rejected = [&] {
        assert(!ensureTestConfigs(defaults, working, error));
        assert(!verifyTestConfigs(working, error));
    };
    const fs::path global = working / "GLOBAL.conf";
    const fs::path ordinary = working / "DAC.conf";
    fs::permissions(working, static_cast<fs::perms>(0777),
                    fs::perm_options::replace);
    rejected();
    assert((fs::status(working).permissions() & fs::perms::all) ==
           fs::perms::all);
    fs::permissions(working, static_cast<fs::perms>(02750),
                    fs::perm_options::replace);

    for (const fs::path& file : {global, ordinary}) {
        fs::permissions(file, static_cast<fs::perms>(0666),
                        fs::perm_options::replace);
        rejected();
        assert((fs::status(file).permissions() & fs::perms::all) ==
               static_cast<fs::perms>(0666));
        fs::permissions(file, static_cast<fs::perms>(0640),
                        fs::perm_options::replace);
        const fs::path saved = file.string() + ".saved";
        fs::rename(file, saved);
        fs::create_symlink(saved, file);
        rejected();
        fs::remove(file);
        fs::rename(saved, file);
        const fs::path alias = file.string() + ".alias";
        fs::create_hard_link(file, alias);
        rejected();
        fs::remove(alias);
    }

    const fs::path savedDirectory = root / "authority-config-saved";
    fs::rename(working, savedDirectory);
    fs::create_directory_symlink(savedDirectory, working);
    rejected();
    fs::remove(working);
    fs::rename(savedDirectory, working);

    if (::geteuid() == 0) {
        const uid_t wrongOwner = 65534;
        const gid_t wrongGroup = ::getegid() == 65534 ? 65533 : 65534;
        assert(::chown(working.c_str(), wrongOwner, ::getegid()) == 0);
        rejected();
        assert(::lchown(working.c_str(), ::geteuid(), ::getegid()) == 0);
        fs::permissions(working, static_cast<fs::perms>(02750),
                        fs::perm_options::replace);
        assert(::chown(working.c_str(), ::geteuid(), wrongGroup) == 0);
        rejected();
        assert(::lchown(working.c_str(), ::geteuid(), ::getegid()) == 0);
        fs::permissions(working, static_cast<fs::perms>(02750),
                        fs::perm_options::replace);
        assert(::chown(global.c_str(), wrongOwner, ::getegid()) == 0);
        rejected();
        assert(::chown(global.c_str(), ::geteuid(), ::getegid()) == 0);
        assert(::chown(ordinary.c_str(), ::geteuid(), wrongGroup) == 0);
        rejected();
        assert(::chown(ordinary.c_str(), ::geteuid(), ::getegid()) == 0);
    }
    const auto before = readFile(global);
    assert(ensureTestConfigs(defaults, working, error));
    assert(verifyTestConfigs(working, error));
    assert(readFile(global) == before);
}

void testDatabaseContract(const fs::path& root) {
    std::string error;
    const DBOptions fresh = optionsFor(root, "fresh");
    createCurrentDatabase(fresh);
    assert(readPragma(fresh.databaseFile, "application_id") ==
           static_cast<int>(fic::version::DEVICE_DB_APPLICATION_ID));
    assert(readPragma(fresh.databaseFile, "user_version") ==
           fic::version::DEVICE_DB_SCHEMA_VERSION);
    {
        DB current(fresh);
        assert(current.initializeDatabase());
        assert(current.verifyDatabaseSchema(error));
        assert(current.getComputerRoot().id > 0);
    }

    const DBOptions unversioned = optionsFor(root, "unversioned");
    executeSql(unversioned.databaseFile, "CREATE TABLE old_state(id INTEGER);");
    {
        DB database(unversioned);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("unversioned") != std::string::npos);
        assert(!database.verifyDatabaseSchema(error));
    }

    const DBOptions schemaZero = optionsFor(root, "schema-zero");
    fs::copy_file(fresh.databaseFile, schemaZero.databaseFile);
    executeSql(schemaZero.databaseFile, "PRAGMA user_version=0;");
    {
        DB database(schemaZero);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("unsupported") != std::string::npos);
    }

    const DBOptions future = optionsFor(root, "future");
    fs::copy_file(fresh.databaseFile, future.databaseFile);
    executeSql(
        future.databaseFile,
        "PRAGMA user_version=" +
            std::to_string(fic::version::DEVICE_DB_SCHEMA_VERSION + 1) + ";");
    {
        DB database(future);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("newer") != std::string::npos);
    }

    const DBOptions wrongApplication = optionsFor(root, "wrong-application");
    fs::copy_file(fresh.databaseFile, wrongApplication.databaseFile);
    executeSql(wrongApplication.databaseFile, "PRAGMA application_id=1234;");
    {
        DB database(wrongApplication);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("application_id") != std::string::npos);
    }

    const DBOptions wrongLayout = optionsFor(root, "wrong-layout");
    fs::copy_file(fresh.databaseFile, wrongLayout.databaseFile);
    executeSql(wrongLayout.databaseFile, "DROP INDEX idx_devices_hash;");
    {
        DB database(wrongLayout);
        assert(!database.initializeDatabase());
        assert(database.lastError().find("indexes") != std::string::npos);
    }
}
} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-schema-contract-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);
    fs::permissions(root, static_cast<fs::perms>(02750),
                    fs::perm_options::replace);

    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "runtime-config";
    paths.defaultConfigDir = root / "runtime-default-config";
    paths.languageDir = root / "lang";
    paths.logDir = root;
    paths.notifyDir = root / "notify";
    paths.dataDir = root;
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "commandhash.txt";
    paths.deviceDatabaseFile = root / "runtime.db";
    paths.deviceDatabaseLockFile = root / "runtime.lock";
    paths.lockDebugLogFile = root / "runtime-lock.log";
    std::string pathError;
    assert(fic::core::FicRuntimePaths::initialize(paths, pathError));

    testConfigContract(root);
    testModeAndOwnerFreshInstallConfig(root);
    testConfigAuthorityRejection(root);
    testDatabaseContract(root);

    fs::remove_all(root);
    return 0;
}
