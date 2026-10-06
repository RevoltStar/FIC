#ifndef FIC_CONFIG_SCHEMA_MANAGER_H
#define FIC_CONFIG_SCHEMA_MANAGER_H

#include <filesystem>
#include <string>

namespace fic::core {

class ConfigSchemaManager {
public:
    static bool ensureConfigs(
        const std::filesystem::path& defaultConfigDirectory,
        const std::filesystem::path& configDirectory,
        std::string& error,
        bool allowRecoveryBootstrap = false);

    static bool verifyConfigs(const std::filesystem::path& configDirectory,
                              std::string& error);
};

} // namespace fic::core

#endif // FIC_CONFIG_SCHEMA_MANAGER_H
