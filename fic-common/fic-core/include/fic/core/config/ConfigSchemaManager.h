#ifndef FIC_CONFIG_SCHEMA_MANAGER_H
#define FIC_CONFIG_SCHEMA_MANAGER_H

#include <fic/core/config/ConfigAuthority.h>

#include <filesystem>
#include <optional>
#include <string>

namespace fic::core {

class ConfigSchemaManager {
public:
    static bool ensureConfigs(
        const std::filesystem::path& defaultConfigDirectory,
        const std::filesystem::path& configDirectory,
        std::string& error,
        bool allowRecoveryBootstrap = false,
        std::optional<ConfigAuthorityIdentity> testIdentity = std::nullopt);

    // Targeted additive upgrade for GLOBAL scheduling keys. Caller holds the
    // daemon/package admission lock; existing fields are never overwritten.
    static bool ensurePeriodicApplyDefaults(
        const std::filesystem::path& configDirectory, std::string& error,
        std::optional<ConfigAuthorityIdentity> testIdentity = std::nullopt);

    static bool verifyConfigs(const std::filesystem::path& configDirectory,
                              std::string& error,
                              std::optional<ConfigAuthorityIdentity> testIdentity =
                                  std::nullopt);
};

} // namespace fic::core

#endif // FIC_CONFIG_SCHEMA_MANAGER_H
