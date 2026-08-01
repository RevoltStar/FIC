#include <fic/core/FicRuntimePaths.h>
#include <fic/device-db/DB.h>

#include <cassert>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
mode_t fileMode(const std::filesystem::path& path) {
    struct stat info {};
    assert(::stat(path.c_str(), &info) == 0);
    return info.st_mode & 07777;
}
}

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-runtime-paths-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "data");
    fs::create_directories(root / "log");

    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.stateDir = root / "state";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/db.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";

    std::string error;
    assert(paths.validate(error));
    assert(fic::core::FicRuntimePaths::initialize(paths, error));
    assert(fic::core::FicRuntimePaths::get().configDir == root / "config");
    assert(fic::core::FicRuntimePaths::get().stateDir == root / "state");
    assert(!fic::core::FicRuntimePaths::initialize(paths, error));

    bool rejectedInvalidDbOptions = false;
    try {
        DB invalidDatabase({"relative.db", root / "log/invalid.lock", {}, false});
    } catch (const std::invalid_argument&) {
        rejectedInvalidDbOptions = true;
    }
    assert(rejectedInvalidDbOptions);

    DBOptions options{
        paths.deviceDatabaseFile,
        paths.deviceDatabaseLockFile,
        paths.lockDebugLogFile,
        false
    };
    {
        DB database(options);
        assert(database.initializeDatabase());
    }
    assert(fs::is_regular_file(paths.deviceDatabaseFile));
    assert(fs::is_regular_file(paths.deviceDatabaseLockFile));
    assert(fileMode(paths.deviceDatabaseFile) == 0640);
    assert(fileMode(paths.deviceDatabaseLockFile) == 0640);

    fs::remove_all(root);
    return 0;
}
