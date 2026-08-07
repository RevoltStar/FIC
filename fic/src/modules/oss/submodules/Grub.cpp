#include "modules/oss/submodules/Grub.h"
#include "modules/oss/submodules/GrubConfiguration.h"

#include <mutex>
#include <utility>

namespace {

std::mutex grubConfigurationMutex;

} // namespace

Grub::Grub(fic::platform::GrubPlatformConfig platformConfig)
    : OSS(),
      platformConfig_(std::move(platformConfig)) {
    this->submoduleName = "Grub";
}

bool Grub::apply() {
    const auto value = this->getValue();
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

    GrubConfiguration configuration(GrubConfigurationOptions{
        platformConfig_.defaultsPath,
        platformConfig_.rebuildCandidates,
        true
    });
    std::string error;
    if (!configuration.load(error)) {
        this->log("Не удалось загрузить GRUB-конфигурацию: " + error,
                  logLevel::ERROR);
        return false;
    }

    const GrubValueObservation observation = configuration.inspect(grubKey);
    if (observation.found && observation.value == actualExpected) {
        this->log("Отклонений " + grubKey + " не обнаружено",
                  logLevel::INFO);
        return true;
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
    return true;
}
