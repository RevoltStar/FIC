#ifndef FIC_IDENTITY_ACCESS_PREPARED_FILE_CHANGE_H
#define FIC_IDENTITY_ACCESS_PREPARED_FILE_CHANGE_H

#include "modules/identity_access/composite/ConfigurationTransaction.h"

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <sys/types.h>

namespace fic::identity {

struct SecureConfigurationFileOptions {
    std::filesystem::path path;
    std::optional<uid_t> expectedOwner = 0;
    std::optional<gid_t> expectedGroup = 0;
    std::optional<mode_t> exactMode;
    mode_t forbiddenMode = 0022;
    std::size_t maximumBytes = 4U * 1024U * 1024U;
};

struct ConfigurationFileSnapshot {
    std::string content;
    uid_t owner = 0;
    gid_t group = 0;
    mode_t mode = 0;
};

using ConfigurationContentVerifier =
    std::function<bool(const std::string& content, std::string& error)>;

// A prepared file change verifies only the persistent representation.  A
// policy which needs a daemon reload, cache invalidation, or another runtime
// action must wrap it in a subsystem-specific participant before adding it to
// a composite transaction.

bool readSecureConfigurationFile(
    const SecureConfigurationFileOptions& options,
    ConfigurationFileSnapshot& snapshot,
    std::string& error);

bool verifySecureConfigurationDirectory(
    const std::filesystem::path& path,
    const SecureConfigurationFileOptions& fileOptions,
    std::string& error);

std::unique_ptr<PreparedConfigurationChange> makePreparedFileChange(
    std::string identifier,
    SecureConfigurationFileOptions options,
    ConfigurationFileSnapshot original,
    std::string candidate,
    ConfigurationContentVerifier verifier);

bool executePreparedFileChange(
    std::unique_ptr<PreparedConfigurationChange> change,
    std::string& error);

} // namespace fic::identity

#endif // FIC_IDENTITY_ACCESS_PREPARED_FILE_CHANGE_H
