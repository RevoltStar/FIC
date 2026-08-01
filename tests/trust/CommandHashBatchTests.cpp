#include <fic/core/CommandHashStore.h>
#include <fic/core/FicRuntimePaths.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path);
    std::ostringstream content;
    content << stream.rdbuf();
    return content.str();
}

mode_t fileMode(const std::filesystem::path& path) {
    struct stat info {};
    assert(::stat(path.c_str(), &info) == 0);
    return info.st_mode & 07777;
}
} // namespace

int main() {
    if (::geteuid() != 0) {
        return 77;
    }

    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-command-hash-batch-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "db");

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
    paths.commandHashFile = root / "db/commandhash.txt";
    paths.deviceDatabaseFile = root / "db/devices.db";
    paths.deviceDatabaseLockFile = root / "db/devices.lock";
    paths.lockDebugLogFile = root / "db/lock.log";

    std::string error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    const fs::path first = root / "first";
    const fs::path second = root / "second";
    {
        std::ofstream(first) << "first executable\n";
        std::ofstream(second) << "second executable\n";
        std::ofstream(paths.commandHashFile) << "/manual/path=preserved\n";
    }

    assert(CommandHashStore::saveHashes(
        {first.string(), second.string()}, error));
    assert(CommandHashStore::verifyHash(first.string(), error));
    assert(CommandHashStore::verifyHash(second.string(), error));
    assert(fileMode(paths.commandHashFile) == 0640);
    assert(fileMode(paths.commandHashFile.string() + ".lock") == 0640);
    assert(readFile(paths.commandHashFile).find("/manual/path=preserved") !=
           std::string::npos);

    assert(CommandHashStore::updateHashes(
        {second.string()}, {first.string()}, error));
    assert(!CommandHashStore::verifyHash(first.string(), error));
    assert(error.find("no stored reference hash") != std::string::npos);
    assert(CommandHashStore::verifyHash(second.string(), error));
    assert(readFile(paths.commandHashFile).find("/manual/path=preserved") !=
           std::string::npos);

    const std::string beforeFailure = readFile(paths.commandHashFile);
    assert(!CommandHashStore::saveHashes(
        {first.string(), "relative/path"}, error));
    assert(readFile(paths.commandHashFile) == beforeFailure);

    fs::remove_all(root);
    return 0;
}
