#include "modules/dac/submodules/Sudo.h"
#include "modules/dac/submodules/sudo/SudoersConfiguration.h"

#include <filesystem>
#include <mutex>
#include <utility>
#include <vector>

namespace {

std::mutex sudoersMutex;

bool productionSudoersOptions(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables,
    SudoersConfigurationOptions& options,
    std::string& error) {
    options.mainPath = platformConfig.mainConfigPath;
    options.managedPath = platformConfig.managedConfigPath;
    std::filesystem::path validator;
    if (!executables.resolve(
            fic::platform::ExecutableId::Visudo, validator, error)) {
        return false;
    }
    options.validatorPath = validator.string();
    error.clear();
    return true;
}

std::string defaultsPrefix(const std::string& type,
                           const std::string& group,
                           const std::string& scope) {
    std::string result = type;
    if (!group.empty()) {
        result += ":" + group;
    }
    if (!scope.empty()) {
        result += scope;
    }
    result += " ";
    return result;
}

} // namespace

std::string SingleDefaultsSudoersParam::getParamString() const {
    return defaultsPrefix(sectionName_, group_, scope_) + key_;
}

std::string KeyValueDefaultsSudoersParam::getParamString() const {
    return defaultsPrefix(sectionName_, group_, scope_) + key_ + operation_ + value_;
}

Sudo::~Sudo() {
    // Реализация деструктора
}

Sudo::Sudo(
    fic::platform::SudoPlatformConfig platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : DAC(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables) {
    this->submoduleName = "SudoEdit";
    /*this->Check_And_Fix::postProcessingParameter = std::make_unique<PostProcessingParameter>(PostProcessingParameter::ToJsonWithColon);*/
    /*this->Check_And_Fix::postProcessingValue = std::make_unique<PostProcessingValueJSON>(",", ",");*/
}

// Проверить и исправить параметр sudo
bool Sudo::apply() {
    if (this->Sudo::sudoParameter == nullptr){
        this->log("Не задан sudoParameter", logLevel::FATAL);
        return false;
    }

    const std::lock_guard<std::mutex> lock(sudoersMutex);

    SudoersConfigurationOptions configurationOptions;
    std::string resolverError;
    if (!productionSudoersOptions(
            platformConfig_, executables_, configurationOptions, resolverError)) {
        this->log("Не удалось выбрать visudo: " + resolverError, logLevel::ERROR);
        return false;
    }
    SudoersConfiguration configuration(std::move(configurationOptions));
    std::string loadError;
    if (!configuration.load(loadError)) {
        this->log("Не удалось проанализировать sudoers: " + loadError, logLevel::ERROR);
        return false;
    }
    auto valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    std::string valueNew = *valueOpt;
    if(valueNew.empty()){
        this->log("Эталон не задан", logLevel::ERROR);
        return false;
    }

    std::string key;
    std::string renderedLine;
    std::string expectedValue;
    if (const auto* parameter = dynamic_cast<const KeyValueDefaultsSudoersParam*>(
            this->Sudo::sudoParameter.get())) {
        key = parameter->getKey();
        expectedValue = valueNew;
        renderedLine = defaultsPrefix(parameter->getType(), parameter->getGroup(),
                                      parameter->getScope()) +
                       parameter->getKey() + parameter->getOperator() + valueNew;
    } else if (const auto* parameter = dynamic_cast<const SingleDefaultsSudoersParam*>(
                   this->Sudo::sudoParameter.get())) {
        key = parameter->getKey();
        expectedValue = valueNew;
        renderedLine = defaultsPrefix(parameter->getType(), parameter->getGroup(),
                                      parameter->getScope()) +
                       (valueNew == "DISABLE" ? "!" : "") + parameter->getKey();
    } else {
        this->log("Тип sudoParameter не поддерживает managed override", logLevel::ERROR);
        return false;
    }

    const SudoersValueObservation observation = configuration.inspectGlobalDefault(key);
    const std::string valueOld = observation.found ? observation.value : "[NOT SET]";

    if(valueOld == valueNew){
        const std::string source = observation.source.path.empty()
            ? ""
            : " Источник: " + observation.source.path.string() + ":" +
                  std::to_string(observation.source.line);
        this->log("Отклонений не обнаружено." + source, logLevel::INFO);
    } else {
        this->log("Обнаружено отклонение параметра: '" +
                  this->Sudo::sudoParameter->getParamString() + "'", logLevel::WARN);
        this->log("Фактическое:'" + valueOld + "' Ожидаемое:'" + valueNew + "'", logLevel::WARN);
    }

    const SudoersOperationResult operation = configuration.ensureManagedGlobalDefault(
        key, renderedLine, expectedValue);
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

bool Sudo::applyRequireAuthentication() {
    const std::lock_guard<std::mutex> lock(sudoersMutex);
    const auto configuredValue = this->getValue();
    if (!configuredValue || *configuredValue != "ENABLE") {
        this->log("Эталон политики требования аутентификации не равен ENABLE", logLevel::ERROR);
        return false;
    }

    SudoersConfigurationOptions configurationOptions;
    std::string resolverError;
    if (!productionSudoersOptions(
            platformConfig_, executables_, configurationOptions, resolverError)) {
        this->log("Не удалось выбрать visudo: " + resolverError, logLevel::ERROR);
        return false;
    }
    SudoersConfiguration configuration(std::move(configurationOptions));
    std::string loadError;
    if (!configuration.load(loadError)) {
        this->log("Не удалось проанализировать sudoers: " + loadError, logLevel::ERROR);
        return false;
    }

    const SudoersOperationResult operation = configuration.enforceAuthentication();
    for (const std::string& diagnostic : operation.diagnostics) {
        this->log(diagnostic, operation.ok ? logLevel::WARN : logLevel::ERROR);
    }
    this->log(operation.message, operation.ok ? logLevel::INFO : logLevel::ERROR);
    return operation.ok;
}
