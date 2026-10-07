#include "incident/IncidentRecoveryConfigReader.h"

#include <fic/core/config/ConfigAuthority.h>
#include <fic/core/config/ConfigSchemaManager.h>
#include <fic/core/fs/SecureStateFile.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace {
#define require(value) do { \
    if (!(value)) throw std::runtime_error( \
        "incident recovery config proof regression at line " + \
        std::to_string(__LINE__)); \
} while (false)
void write(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0640);
}
std::string sizedConfig(std::size_t size, const std::string& tail) {
    const std::string prefix = "_schema_version=1\n#";
    require(size >= prefix.size() + tail.size() + 1);
    return prefix + std::string(size - prefix.size() - tail.size() - 1, 'x') +
        "\n" + tail;
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
        expected.maxSize = fic::core::MAX_WORKING_CONFIG_BYTES;
        expected.requireSingleLink = true;
        expected.parentOwner = ::geteuid();
        expected.parentGroup = ::getegid();
        expected.exactParentMode = 02750;
        std::string diagnostic;
        auto enabled = [&] {
            return fic::incident::IncidentRecoveryConfigReader::read(
                file, expected, diagnostic);
        };
        constexpr const char* key = "lock_exempt_fic_members.status=ENABLE\n";
        for (const char* name : {"AUDIT.conf", "DAC.conf", "DC.conf",
                                 "IDENTITY_ACCESS.conf", "FIREWALL.conf",
                                 "NET.conf", "OSS.conf", "SYSCTL.conf"}) {
            write(config / name, "_schema_version=1\n");
        }
        auto schemaValid = [&] {
            std::string error;
            return fic::core::ConfigSchemaManager::verifyConfigs(
                config, error,
                fic::core::ConfigAuthorityIdentity{::geteuid(), ::getegid()});
        };
        write(file, "_schema_version=1\nlang=ru\n" + std::string(key));
        require(enabled());
        for (const std::size_t size : {4096U, 4097U, 65536U, 1048576U}) {
            write(file, sizedConfig(size, key));
            require(std::filesystem::file_size(file) == size);
            require(schemaValid());
            require(enabled());
        }
        write(file, sizedConfig(1048577U, key));
        require(!schemaValid());
        require(!enabled());
        // The short incident-state API retains its independent 4096-byte cap.
        write(file, sizedConfig(4097U, key));
        require(fic::core::readSecureStateFile(file, expected).status !=
                fic::core::SecureStateReadStatus::Proven);
        write(file, sizedConfig(65536U,
              std::string(key) + "lock_exempt_fic_members.status=DISABLE\n"));
        require(!enabled());
        write(file, sizedConfig(65536U,
              "lock_exempt_fic_members.status=INVALID\n"));
        require(!enabled());
        const auto stable = sizedConfig(65536U, key);
        write(file, stable);
        fic::core::setSecureStatePostReadHookForTests([&](const auto&) {
            write(file, stable + "#");
        });
        require(!enabled());
        fic::core::setSecureStatePostReadHookForTests({});
        write(file, stable);
        fic::core::setSecureStatePostReadHookForTests([&](const auto&) {
            std::string changed = stable;
            changed[20] = 'y';
            write(file, changed);
        });
        require(!enabled());
        fic::core::setSecureStatePostReadHookForTests({});
        write(file, stable);
        const auto alias = config / "GLOBAL.alias";
        std::filesystem::rename(file, alias);
        std::filesystem::create_symlink(alias, file);
        require(!enabled());
        std::filesystem::remove(file);
        std::filesystem::rename(alias, file);
        std::filesystem::create_hard_link(file, alias);
        require(!enabled());
        std::filesystem::remove(alias);
        if (::geteuid() == 0) {
            require(::chown(file.c_str(), 65534, ::getegid()) == 0);
            require(!enabled());
            require(::chown(file.c_str(), ::geteuid(), ::getegid()) == 0);
            ::chmod(file.c_str(), 0640);
        }
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
