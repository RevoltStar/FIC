#include "incident/IncidentRecoveryConfigReader.h"

#include <fic/core/fs/SecureStateFile.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace {
void require(bool value) {
    if (!value) throw std::runtime_error("incident recovery config proof regression");
}
void write(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0640);
}
}

int main() {
    char pattern[] = "/tmp/fic-recovery-reader-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    if (created == nullptr) throw std::runtime_error("mkdtemp failed");
    const std::filesystem::path root(created);
    try {
        const auto config = root / "config";
        std::filesystem::create_directory(config);
        ::chmod(root.c_str(), 02750);
        ::chmod(config.c_str(), 02750);
        const auto file = config / "GLOBAL.conf";
        fic::core::SecureStateFileExpectation expected;
        expected.owner = ::geteuid();
        expected.group = ::getegid();
        expected.exactMode = 0640;
        expected.maxSize = fic::core::SECURE_STATE_READ_HARD_MAX_BYTES;
        expected.requireSingleLink = true;
        expected.parentOwner = ::geteuid();
        expected.parentGroup = ::getegid();
        expected.exactParentMode = 02750;
        std::string diagnostic;
        auto enabled = [&] {
            return fic::incident::IncidentRecoveryConfigReader::read(
                file, expected, diagnostic);
        };
        write(file, "lang=ru\nlock_exempt_fic_members.status=ENABLE\n");
        require(enabled());
        write(file, "lock_exempt_fic_members.status=DISABLE\n");
        require(!enabled());
        write(file, "lock_exempt_fic_members.status=ENABLE\n"
                    "lock_exempt_fic_members.status=DISABLE\n");
        require(!enabled());
        write(file, "lock_exempt_fic_members.status=INVALID\n");
        require(!enabled());
        write(file, "other=value\n");
        require(!enabled());
        write(file, "lock_exempt_fic_members.status=ENABLE\n");
        ::chmod(file.c_str(), 0666);
        require(!enabled());
        ::chmod(file.c_str(), 0640);
        ::chmod(config.c_str(), 0777);
        require(!enabled());
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
    std::filesystem::remove_all(root);
}
