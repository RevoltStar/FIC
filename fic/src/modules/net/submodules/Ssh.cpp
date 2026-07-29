#include "modules/net/submodules/Ssh.h"
#include "modules/net/submodules/SshRuntime.h"

#include <fic/core/AtomicFileWriter.h>
#include <fic/core/LocalizationManager.h>

#include <fstream>
#include <sstream>
#include <utility>

namespace {

bool readFileContent(const std::string& path, std::string& content) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        return false;
    }
    content = buffer.str();
    return true;
}

bool restoreSshConfig(const std::string& path,
                      const std::string& content,
                      std::string& error) {
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    return AtomicFileWriter::write(path, content, options, &error);
}

} // namespace

Ssh::~Ssh() = default;

Ssh::Ssh(fic::platform::SshPlatformConfig platformConfig,
         const fic::platform::PlatformExecutableResolver& executables)
    : Net(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables),
      runtimeOptions_(std::make_unique<SshRuntimeOptions>(SshRuntimeOptions{
          platformConfig_.configPath,
          platformConfig_.includeBasePath,
          platformConfig_.serviceUnits
      })),
      sshConfig_(std::make_unique<SshConfigFileHandler>(
          platformConfig_.configPath.string())) {
    this->submoduleName = "SshEdit";
}

bool Ssh::apply() {
    if (this->sshParameter.empty()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:parameter_not_configured_part1]") +
                      this->policyName +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:parameter_not_configured_part2]"),
                  logLevel::FATAL);
        return false;
    }

    const std::string sshPath = platformConfig_.configPath.string();
    std::string originalContent;
    if (!readFileContent(sshPath, originalContent) ||
        !this->sshConfig_->loadConfig()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:load_failed]"),
                  logLevel::ERROR);
        return false;
    }

    const std::optional valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    const std::string expectedValue = *valueOpt;
    if (expectedValue.empty() || expectedValue == "[NO VALUE SET]") {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:reference_value_empty_part1]") +
                      this->policyName +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:reference_value_empty_part2]"),
                  logLevel::ERROR);
        return false;
    }

    const std::string currentValue = this->sshConfig_->getValue(this->sshParameter);
    const bool changed = currentValue != expectedValue;
    if (currentValue == expectedValue) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:no_deviations_part1]") +
                      this->sshParameter +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:no_deviations_part2]"),
                  logLevel::INFO);
    } else {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:deviation_detected_part1]") +
                      this->sshParameter +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:deviation_detected_part2]") +
                      currentValue +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:deviation_detected_part3]") +
                      expectedValue +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:deviation_detected_part4]"),
                  logLevel::WARN);

        if (!this->sshConfig_->setValue(this->sshParameter, expectedValue)) {
            this->log(LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:update_failed_part1]") +
                          this->sshParameter +
                          LocalizationManager::getLang(
                              "[module:NET][submodule:SshEdit][message:update_failed_part2]"),
                      logLevel::ERROR);
            return false;
        }

        if (!this->sshConfig_->saveFile()) {
            this->log(LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:save_failed]"),
                      logLevel::ERROR);
            return false;
        }

        SshConfigFileHandler verification(sshPath);
        if (!verification.loadConfig() ||
            verification.getValue(this->sshParameter) != expectedValue) {
            std::string rollbackError;
            const bool rolledBack = restoreSshConfig(sshPath, originalContent, rollbackError);
            this->log(
                "Не удалось подтвердить записанное значение SSH-политики" +
                    std::string(rolledBack ? "" : ". Ошибка отката: " + rollbackError),
                logLevel::ERROR
            );
            return false;
        }
    }

    SshRuntime runtime(*runtimeOptions_, executables_);
    std::string runtimeError;
    if (!runtime.verifyPolicyValue(this->sshParameter, expectedValue, runtimeError)) {
        if (changed) {
            std::string rollbackError;
            if (!restoreSshConfig(sshPath, originalContent, rollbackError)) {
                runtimeError += ". Ошибка отката SSH-конфигурации: " + rollbackError;
            }
        }
        this->log("Проверка effective-конфигурации sshd не пройдена: " + runtimeError,
                  logLevel::ERROR);
        return false;
    }

    const SshActivationResult activation = runtime.activateIfRunning();
    if (!activation.ok) {
        this->log(
            "Persistent-конфигурация SSH подготовлена, но обязательная runtime-активация "
            "не завершена: " + activation.message,
            logLevel::ERROR
        );
        return false;
    }
    this->log(activation.message, logLevel::INFO);

    if (changed) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:deviation_fixed]"),
                  logLevel::INFO);
    }
    return true;
}
