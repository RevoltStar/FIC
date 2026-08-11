#ifndef FIC_UPGRADE_MANAGER_H
#define FIC_UPGRADE_MANAGER_H

#include <filesystem>
#include <string>

namespace fic::core {

struct UpgradeState {
    std::string targetVersion;
    std::string phase;
    std::filesystem::path transactionDirectory;
    std::filesystem::path databaseBackup;
};

struct ConfigMigrationResult {
    int migratedFiles = 0;
    std::filesystem::path backupDirectory;
};

class UpgradeManager {
public:
    static bool ensureConfigs(
        const std::filesystem::path& defaultConfigDirectory,
        const std::filesystem::path& configDirectory,
        std::string& error);

    static bool begin(const std::filesystem::path& stateDirectory,
                      const std::string& targetVersion,
                      UpgradeState& state,
                      std::string& error);

    static bool verifyConfigs(const std::filesystem::path& configDirectory,
                              std::string& error);

    static bool migrateConfigs(const std::filesystem::path& configDirectory,
                               const std::filesystem::path& stateDirectory,
                               ConfigMigrationResult& result,
                               std::string& error);

    static bool markDatabaseMigratedIfActive(
        const std::filesystem::path& stateDirectory,
        const std::filesystem::path& databaseBackup,
        std::string& error);

    static bool recordDatabaseBackupIfActive(
        const std::filesystem::path& stateDirectory,
        const std::filesystem::path& databaseBackup,
        std::string& error);

    static bool commit(const std::filesystem::path& stateDirectory,
                       std::string& error);

    static bool requireNoIncompleteUpgrade(
        const std::filesystem::path& stateDirectory,
        std::string& error);

    static bool readState(const std::filesystem::path& stateDirectory,
                          UpgradeState& state,
                          bool& exists,
                          std::string& error);
};

} // namespace fic::core

#endif // FIC_UPGRADE_MANAGER_H
