#include <fic/core/config/ConfigAuthority.h>

#include <cerrno>
#include <grp.h>
#include <vector>

namespace fic::core {

bool productionConfigAuthority(ConfigAuthorityIdentity& identity,
                               std::string& error) {
    std::vector<char> buffer(16384);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        group record {};
        group* found = nullptr;
        const int rc = ::getgrnam_r(
            "fic", &record, buffer.data(), buffer.size(), &found);
        if (rc == ERANGE) {
            buffer.resize(buffer.size() * 2U);
            continue;
        }
        if (rc != 0 || found == nullptr) {
            error = "fic group cannot be proven";
            return false;
        }
        identity = {0, found->gr_gid};
        error.clear();
        return true;
    }
    error = "fic group lookup exceeded the size limit";
    return false;
}

SecureStateFileExpectation configAuthorityExpectation(
    const ConfigAuthorityIdentity& identity) {
    SecureStateFileExpectation expectation;
    expectation.owner = identity.owner;
    expectation.group = identity.group;
    expectation.exactMode = 0640;
    expectation.maxSize = MAX_WORKING_CONFIG_BYTES;
    expectation.requireSingleLink = true;
    expectation.parentOwner = identity.owner;
    expectation.parentGroup = identity.group;
    expectation.exactParentMode = 02750;
    return expectation;
}

bool proveConfigDirectory(const std::filesystem::path& directory,
                          const ConfigAuthorityIdentity& identity,
                          std::string& error) {
    const auto expectation = configAuthorityExpectation(identity);
    return proveSafeParentDirectory(directory.parent_path(), expectation, error) &&
        proveSafeParentDirectory(directory, expectation, error);
}

bool canonicalConfigFileMetadata(const struct stat& info,
                                 const ConfigAuthorityIdentity& identity,
                                 const std::filesystem::path& path,
                                 std::string& error) {
    if (!S_ISREG(info.st_mode) || info.st_uid != identity.owner ||
        info.st_gid != identity.group || (info.st_mode & 07777) != 0640 ||
        info.st_nlink != 1) {
        error = "working configuration has unsafe metadata: " + path.string();
        return false;
    }
    return true;
}

} // namespace fic::core
