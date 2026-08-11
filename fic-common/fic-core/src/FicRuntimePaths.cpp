#include <fic/core/FicRuntimePaths.h>

#include <fic/core/FicPathDefaults.h>

#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace fic::core {
namespace {
std::mutex runtimePathsMutex;
std::unique_ptr<const FicProductPaths> runtimePaths;

bool validatePath(const std::filesystem::path& path,
                  const char* name,
                  std::string& error) {
    if (path.empty() || !path.is_absolute()) {
        error = std::string(name) + " must be an absolute path";
        return false;
    }
    for (const auto& part : path) {
        if (part == "..") {
            error = std::string(name) + " must not contain '..'";
            return false;
        }
    }
    if (path.lexically_normal() != path) {
        error = std::string(name) + " must be lexically normalized";
        return false;
    }
    return true;
}
} // namespace

FicProductPaths FicProductPaths::production() {
    return {
        path_defaults::PRIVATE_BINDIR,
        path_defaults::CONFIG_DIR,
        path_defaults::LANGUAGE_DIR,
        path_defaults::LOG_DIR,
        path_defaults::NOTIFY_DIR,
        path_defaults::DATA_DIR,
        path_defaults::STATE_DIR,
        path_defaults::SHARE_DIR,
        path_defaults::DEFAULT_CONFIG_DIR,
        path_defaults::IMAGE_DIR,
        path_defaults::RUNTIME_DIR,
        path_defaults::LOCK_STATUS_FILE,
        path_defaults::COMMAND_HASH_FILE,
        path_defaults::DEVICE_DB_FILE,
        path_defaults::DEVICE_DB_LOCK_FILE,
        path_defaults::LOCK_DEBUG_LOG_FILE
    };
}

bool FicProductPaths::validate(std::string& error) const {
    const struct {
        const std::filesystem::path* value;
        const char* name;
    } fields[] = {
        {&privateBinDir, "privateBinDir"},
        {&configDir, "configDir"},
        {&languageDir, "languageDir"},
        {&logDir, "logDir"},
        {&notifyDir, "notifyDir"},
        {&dataDir, "dataDir"},
        {&stateDir, "stateDir"},
        {&shareDir, "shareDir"},
        {&defaultConfigDir, "defaultConfigDir"},
        {&imageDir, "imageDir"},
        {&runtimeDir, "runtimeDir"},
        {&lockStatusFile, "lockStatusFile"},
        {&commandHashFile, "commandHashFile"},
        {&deviceDatabaseFile, "deviceDatabaseFile"},
        {&deviceDatabaseLockFile, "deviceDatabaseLockFile"},
        {&lockDebugLogFile, "lockDebugLogFile"}
    };

    for (const auto& field : fields) {
        if (!validatePath(*field.value, field.name, error)) {
            return false;
        }
    }
    if (deviceDatabaseFile == deviceDatabaseLockFile) {
        error = "device database and lock paths must be different";
        return false;
    }
    return true;
}

bool FicRuntimePaths::initialize(FicProductPaths paths, std::string& error) {
    if (!paths.validate(error)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(runtimePathsMutex);
    if (runtimePaths != nullptr) {
        error = "FIC runtime paths have already been initialized";
        return false;
    }
    runtimePaths = std::make_unique<const FicProductPaths>(std::move(paths));
    return true;
}

bool FicRuntimePaths::initializeProduction(std::string& error) {
    return initialize(FicProductPaths::production(), error);
}

bool FicRuntimePaths::isInitialized() {
    std::lock_guard<std::mutex> lock(runtimePathsMutex);
    return runtimePaths != nullptr;
}

const FicProductPaths& FicRuntimePaths::get() {
    std::lock_guard<std::mutex> lock(runtimePathsMutex);
    if (runtimePaths == nullptr) {
        throw std::logic_error("FIC runtime paths have not been initialized");
    }
    return *runtimePaths;
}

} // namespace fic::core
