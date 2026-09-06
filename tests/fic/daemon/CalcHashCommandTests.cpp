#include "daemon/CalcHashCommand.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <nlohmann/json.hpp>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
std::string readFile(const std::filesystem::path& path)
{
    std::ifstream input(path);
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}
} // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-calc-hash-command-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "db");

    auto paths = fic::core::FicProductPaths::production();
    paths.dataDir = root / "db";
    paths.logDir = root / "db";
    paths.commandHashFile = root / "db/commandhash.txt";
    paths.lockDebugLogFile = root / "db/lock.log";
    std::string error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));
    std::ofstream(paths.commandHashFile) << "/preserved=value\n";
    const std::string before = readFile(paths.commandHashFile);

    const auto specialResponse = calcHashCommandResponse("/dev/null");
    assert(!specialResponse.value("ok", true));
    assert(specialResponse.value("message", "").find("not a regular file") !=
           std::string::npos);
    assert(readFile(paths.commandHashFile) == before);

    const fs::path nonExecutable = root / "not-executable";
    std::ofstream(nonExecutable) << "sensitive simulation\n";
    assert(::chmod(nonExecutable.c_str(), 0600) == 0);
    const auto modeResponse = calcHashCommandResponse(nonExecutable.string());
    assert(!modeResponse.value("ok", true));
    assert(modeResponse.value("message", "").find(
               "no execute permission bits") != std::string::npos);
    assert(readFile(paths.commandHashFile) == before);

    const auto storeKeyResponse = calcHashCommandResponse(
        root.string() + "/invalid\npathname");
    assert(!storeKeyResponse.value("ok", true));
    const std::string storeKeyMessage = storeKeyResponse.value("message", "");
    assert(storeKeyMessage.find("0x0A") != std::string::npos);
    assert(storeKeyMessage.find('\n') == std::string::npos);
    assert(readFile(paths.commandHashFile) == before);

    fs::remove_all(root);
    return 0;
}
