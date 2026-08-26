#include "modules/oss/grub/Grub.h"
#include "modules/oss/grub/GrubConfiguration.h"

#include <mutex>
#include <utility>

namespace {

std::mutex grubConfigurationMutex;

} // namespace

Grub::Grub(
    fic::platform::GrubPlatformConfig platformConfig,
    const fic::platform::PlatformExecutableResolver& executables,
    bool enforceOwnership)
    : OSS(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables),
      enforceOwnership_(enforceOwnership) {
    this->submoduleName = "Grub";
}

bool Grub::apply() {
    std::optional<std::string> value;
    try {
        value = this->getValue();
    } catch (const std::exception& error) {
        this->log(
            "Не удалось декодировать значение политики GRUB: " +
                std::string(error.what()),
            logLevel::ERROR);
        return false;
    }
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(grubConfigurationMutex);
    return this->applyGrub(*value);
}

bool Grub::applyGrubValue(
    const std::string& grubKey,
    const std::string& expectedValue,
    const std::function<std::string(const std::string&)>& normalizeExpected)
{
    const std::string actualExpected = normalizeExpected
        ? normalizeExpected(expectedValue)
        : expectedValue;

    std::filesystem::path rebuildExecutable;
    std::string resolverError;
    if (!executables_.resolve(
            fic::platform::ExecutableId::UpdateGrub,
            rebuildExecutable,
            resolverError)) {
        this->log(
            "Не удалось найти проверенную команду пересборки GRUB: " +
                resolverError,
            logLevel::ERROR);
        return false;
    }

    GrubConfiguration configuration(GrubConfigurationOptions{
        platformConfig_.defaultsPath,
        rebuildExecutable,
        platformConfig_.rebuildArguments,
        enforceOwnership_
    });
    std::string error;
    if (!configuration.load(error)) {
        this->log("Не удалось загрузить GRUB-конфигурацию: " + error,
                  logLevel::ERROR);
        return false;
    }

    const GrubOperationResult operation =
        configuration.ensureManagedValue(grubKey, actualExpected);
    for (const std::string& diagnostic : operation.diagnostics) {
        this->log(diagnostic, operation.ok ? logLevel::INFO : logLevel::WARN);
    }
    if (!operation.ok) {
        this->log(operation.message, logLevel::ERROR);
        return false;
    }
    this->log(operation.message, logLevel::INFO);
    if (operation.changed) {
        this->notify(
            "Исправлена конфигурация GRUB для политики: " +
                this->policyName,
            notifyLevel::WARN);
    }
    return true;
}
