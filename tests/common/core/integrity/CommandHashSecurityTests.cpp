#include "integrity/CommandHashStoreInternal.h"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
void writeFile(const std::filesystem::path& path, mode_t mode)
{
    std::ofstream(path) << "test executable content\n";
    assert(::chmod(path.c_str(), mode) == 0);
}

bool calculate(const std::string& path, std::string& error)
{
    std::string hash;
    return command_hash_store_detail::calculateValidatedExecutableSha256(
        path, hash, error);
}

void assertUnsafeStoreKeyRejected(const std::string& path)
{
    std::string error;
    assert(!command_hash_store_detail::validateCommandHashStoreKey(path, error));
    assert(error.find("0x") != std::string::npos);
    for (const unsigned char byte : error) {
        assert(byte >= 0x20 && byte != 0x7f);
    }
}
} // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-command-hash-security-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "component");

    std::string error;
    const fs::path executableWithSpaces = root / "valid executable";
    writeFile(executableWithSpaces, 0755);
    std::string hash;
    assert(command_hash_store_detail::calculateValidatedExecutableSha256(
        executableWithSpaces.string(), hash, error));
    assert(hash.size() == 64);

    const fs::path doubleDotName = root / "foo..bar";
    writeFile(doubleDotName, 0711);
    assert(calculate(doubleDotName.string(), error));

    const fs::path utf8Name = root / u8"исполняемый файл";
    writeFile(utf8Name, 0755);
    assert(calculate(utf8Name.string(), error));

    assert(command_hash_store_detail::validateCommandHashStoreKey(
        executableWithSpaces.string(), error));
    assert(command_hash_store_detail::validateCommandHashStoreKey(
        doubleDotName.string(), error));
    assert(command_hash_store_detail::validateCommandHashStoreKey(
        utf8Name.string(), error));

    std::vector<std::string> unsafeStoreKeys = {
        root.string() + "/equals=name",
        root.string() + "/comment#name",
        root.string() + "/line\nfeed",
        root.string() + "/carriage\rreturn",
        root.string() + "/horizontal\ttab",
        root.string() + "/control" + std::string(1, '\x01'),
        root.string() + "/delete" + std::string(1, '\x7f'),
        root.string() + "/nul" + std::string(1, '\0') + "suffix",
    };
    for (const std::string& unsafeStoreKey : unsafeStoreKeys) {
        assertUnsafeStoreKeyRejected(unsafeStoreKey);
        assert(!calculate(unsafeStoreKey, error));
        assert(error.find("0x") != std::string::npos);
    }

    const fs::path nonExecutable = root / "regular-no-execute";
    writeFile(nonExecutable, 0644);
    assert(!calculate(nonExecutable.string(), error));
    assert(error.find("no execute permission bits") != std::string::npos);

    const fs::path sensitiveSimulation = root / "shadow-simulation";
    writeFile(sensitiveSimulation, 0600);
    assert(!calculate(sensitiveSimulation.string(), error));

    const fs::path fifo = root / "attacker-fifo";
    assert(::mkfifo(fifo.c_str(), 0600) == 0);
    const auto fifoStart = std::chrono::steady_clock::now();
    assert(!calculate(fifo.string(), error));
    assert(std::chrono::steady_clock::now() - fifoStart <
           std::chrono::seconds(1));
    assert(error.find("not a regular file") != std::string::npos);

    if (fs::exists("/dev/null")) {
        assert(!calculate("/dev/null", error));
        assert(error.find("not a regular file") != std::string::npos);
    }
    assert(!calculate(root.string(), error));
    assert(error.find("not a regular file") != std::string::npos);

    const fs::path symlink = root / "executable-link";
    fs::create_symlink(executableWithSpaces, symlink);
    assert(!calculate(symlink.string(), error));
    assert(error.find("symbolic link") != std::string::npos);

    assert(!calculate("", error));
    assert(!calculate("relative/path", error));
    assert(!calculate(executableWithSpaces.string() + "/", error));
    assert(!calculate(
        root.string() + "/component/../valid executable", error));

    const fs::path racePath = root / "race-target";
    const fs::path openedObject = root / "opened-object";
    writeFile(racePath, 0755);
    const int openedDescriptor = ::open(racePath.c_str(), O_RDONLY | O_CLOEXEC);
    assert(openedDescriptor >= 0);
    fs::rename(racePath, openedObject);
    std::ofstream(racePath) << "replacement content\n";
    assert(::chmod(racePath.c_str(), 0755) == 0);

    std::string openedHash;
    assert(command_hash_store_detail::calculateSha256FromFd(
        openedDescriptor, openedHash, error));
    assert(::close(openedDescriptor) == 0);
    std::string originalHash;
    assert(command_hash_store_detail::calculateValidatedExecutableSha256(
        openedObject.string(), originalHash, error));
    std::string replacementHash;
    assert(command_hash_store_detail::calculateValidatedExecutableSha256(
        racePath.string(), replacementHash, error));
    assert(openedHash == originalHash);
    assert(openedHash != replacementHash);

    fs::remove_all(root);
    return 0;
}
