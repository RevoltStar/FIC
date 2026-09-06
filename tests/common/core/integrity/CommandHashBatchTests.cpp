#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/runtime/FicRuntimePaths.h>

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
    const fs::path second = root / "second executable";
    const fs::path unusual = root / u8"исполняемый  foo..bar ";
    const fs::path equalsName = root / "invalid=name";
    const fs::path commentName = root / "invalid#name";
    {
        std::ofstream(first) << "first executable\n";
        std::ofstream(second) << "second executable\n";
        std::ofstream(unusual) << "unusual executable\n";
        std::ofstream(equalsName) << "invalid store key\n";
        std::ofstream(commentName) << "invalid store key\n";
        std::ofstream(paths.commandHashFile) << "/manual/path=preserved\n";
    }
    assert(::chmod(first.c_str(), 0755) == 0);
    assert(::chmod(second.c_str(), 0755) == 0);
    assert(::chmod(unusual.c_str(), 0755) == 0);
    assert(::chmod(equalsName.c_str(), 0755) == 0);
    assert(::chmod(commentName.c_str(), 0755) == 0);

    assert(CommandHashStore::saveHashes(
        {first.string(), second.string(), unusual.string()}, error));
    assert(CommandHashStore::verifyHash(first.string(), error));
    assert(CommandHashStore::verifyHash(second.string(), error));
    assert(CommandHashStore::verifyHash(unusual.string(), error));
    assert(fileMode(paths.commandHashFile) == 0640);
    assert(fileMode(paths.commandHashFile.string() + ".lock") == 0640);
    assert(readFile(paths.commandHashFile).find("/manual/path=preserved") !=
           std::string::npos);
    assert(readFile(paths.commandHashFile).find(unusual.string() + "=") !=
           std::string::npos);

    assert(CommandHashStore::updateHashes(
        {second.string()}, {first.string()}, error));
    assert(!CommandHashStore::verifyHash(first.string(), error));
    assert(error.find("no stored reference hash") != std::string::npos);
    assert(CommandHashStore::verifyHash(second.string(), error));
    assert(readFile(paths.commandHashFile).find("/manual/path=preserved") !=
           std::string::npos);

    const std::string beforeFailure = readFile(paths.commandHashFile);
    const fs::path nonExecutable = root / "non-executable";
    std::ofstream(nonExecutable) << "not executable\n";
    assert(::chmod(nonExecutable.c_str(), 0644) == 0);
    assert(!CommandHashStore::saveHashes(
        {first.string(), nonExecutable.string(), second.string()}, error));
    assert(readFile(paths.commandHashFile) == beforeFailure);
    assert(!CommandHashStore::saveHashes(
        {first.string(), "relative/path"}, error));
    assert(readFile(paths.commandHashFile) == beforeFailure);
    assert(!CommandHashStore::saveHashes(
        {second.string(), equalsName.string(), unusual.string()}, error));
    assert(error.find("0x3D") != std::string::npos);
    assert(readFile(paths.commandHashFile) == beforeFailure);
    assert(!CommandHashStore::saveHash(commentName.string(), error));
    assert(error.find("0x23") != std::string::npos);
    assert(readFile(paths.commandHashFile) == beforeFailure);
    assert(!CommandHashStore::saveHash(
        root.string() + "/line\nfeed", error));
    assert(error.find("0x0A") != std::string::npos);
    assert(readFile(paths.commandHashFile) == beforeFailure);
    assert(!CommandHashStore::updateHashes(
        {}, {equalsName.string()}, error));
    assert(error.find("0x3D") != std::string::npos);
    assert(readFile(paths.commandHashFile) == beforeFailure);

    const fs::path hashBackup = root / "db/commandhash.backup";
    fs::rename(paths.commandHashFile, hashBackup);
    assert(!CommandHashStore::verifyHash(equalsName.string(), error));
    assert(error.find("0x3D") != std::string::npos);
    fs::rename(hashBackup, paths.commandHashFile);

    fs::remove_all(root);
    return 0;
}
