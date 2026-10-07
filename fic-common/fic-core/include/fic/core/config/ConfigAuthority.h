#ifndef FIC_CORE_CONFIG_AUTHORITY_H
#define FIC_CORE_CONFIG_AUTHORITY_H

#include <fic/core/fs/SecureStateFile.h>

#include <filesystem>
#include <string>
#include <sys/stat.h>

namespace fic::core {

inline constexpr std::uintmax_t MAX_WORKING_CONFIG_BYTES = 1024U * 1024U;

struct ConfigAuthorityIdentity {
    uid_t owner = 0;
    gid_t group = 0;
};

bool productionConfigAuthority(ConfigAuthorityIdentity& identity,
                               std::string& error);
SecureStateFileExpectation configAuthorityExpectation(
    const ConfigAuthorityIdentity& identity);
bool proveConfigDirectory(const std::filesystem::path& directory,
                          const ConfigAuthorityIdentity& identity,
                          std::string& error);
bool canonicalConfigFileMetadata(const struct stat& info,
                                 const ConfigAuthorityIdentity& identity,
                                 const std::filesystem::path& path,
                                 std::string& error);

} // namespace fic::core

#endif
