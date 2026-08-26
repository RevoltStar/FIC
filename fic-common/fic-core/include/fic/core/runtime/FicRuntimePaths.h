#ifndef FIC_RUNTIME_PATHS_H
#define FIC_RUNTIME_PATHS_H

#include <filesystem>
#include <string>

namespace fic::core {

struct FicProductPaths {
    std::filesystem::path privateBinDir;
    std::filesystem::path configDir;
    std::filesystem::path languageDir;
    std::filesystem::path logDir;
    std::filesystem::path notifyDir;
    std::filesystem::path dataDir;
    std::filesystem::path shareDir;
    std::filesystem::path defaultConfigDir;
    std::filesystem::path imageDir;
    std::filesystem::path runtimeDir;
    std::filesystem::path lockStatusFile;
    std::filesystem::path commandHashFile;
    std::filesystem::path deviceDatabaseFile;
    std::filesystem::path deviceDatabaseLockFile;
    std::filesystem::path lockDebugLogFile;

    static FicProductPaths production();
    bool validate(std::string& error) const;
};

class FicRuntimePaths {
public:
    static bool initialize(FicProductPaths paths, std::string& error);
    static bool initializeProduction(std::string& error);
    static bool isInitialized();
    static const FicProductPaths& get();
};

} // namespace fic::core

#endif // FIC_RUNTIME_PATHS_H
