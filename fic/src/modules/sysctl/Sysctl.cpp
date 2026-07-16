#include "modules/sysctl/Sysctl.h"
#include "modules/sysctl/SysctlConfiguration.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <mutex>
#include <optional>

namespace {

std::mutex sysctlMutex;

std::string trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char c) {
        return !std::isspace(c);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char c) {
        return !std::isspace(c);
    }).base(), value.end());
    return value;
}

std::optional<std::string> runtimeValue(const std::string& key) {
    std::string relative = key;
    std::replace(relative.begin(), relative.end(), '.', '/');
    std::ifstream stream("/proc/sys/" + relative);
    if (!stream.is_open()) {
        return std::nullopt;
    }
    std::string value;
    std::getline(stream, value);
    if (!stream.good() && !stream.eof()) {
        return std::nullopt;
    }
    return trimCopy(std::move(value));
}

} // namespace

Sysctl::Sysctl()
    :Policy(){
    this->moduleName = "SYSCTL";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}


// Correct the effective persistent configuration for one sysctl parameter.
bool Sysctl::apply (){
    this->log("Запущена проверка политики " + this->policyName, logLevel::INFO);
    if (this->Sysctl::sysctlParameter.empty()){
        this->log("Имя контролируемого параметра пусто", logLevel::ERROR);
        return false;
    }
    const std::string param = this->Sysctl::sysctlParameter;
    std::string value;

    if(dynamic_cast<FixedPolicyTypeValue*>(this->policyTypeValue.get()) != nullptr){
        /*Для FIXED политики берем из класса*/
        value = this->Sysctl::sysctlParameterValue;
    }else if(dynamic_cast<IntPolicyTypeValue*>(this->policyTypeValue.get()) != nullptr ||
            dynamic_cast<PossibleListPolicyTypeValue*>(this->policyTypeValue.get()) != nullptr){
            /*Для IntPolicyTypeValue или PossibleListPolicyTypeValue политики берем из класса*/
            std::optional valueOpt = this->getValue();
            if(!valueOpt){
                this->log("Reference value for policy " + this->policyName + " is empty", logLevel::ERROR);
                return false;
            }
            value = *valueOpt;
    }else{
        this->log("Unsupported policyTypeValue for sysctl policy " + this->policyName, logLevel::ERROR);
        return false;
    }

    const std::lock_guard<std::mutex> lock(sysctlMutex);
    SysctlConfiguration configuration;
    std::string loadError;
    if (!configuration.load(loadError)) {
        this->log("Не удалось проанализировать конфигурацию sysctl: " + loadError,
                  logLevel::ERROR);
        return false;
    }

    const SysctlValueObservation observation = configuration.inspect(param);
    if (!observation.found || observation.value != value) {
        const std::string actual = observation.found ? observation.value : "[NOT SET]";
        const std::string source = observation.found
            ? " Источник: " + observation.source.path.string() + ":" +
                  std::to_string(observation.source.line)
            : "";
        this->log("Обнаружено отклонение '" + param + "'. Фактическое значение: '" +
                  actual + "'. Ожидаемое значение: '" + value + "'." + source,
                  logLevel::WARN);
    }

    const SysctlOperationResult operation = configuration.ensureManagedValue(param, value);
    for (const std::string& diagnostic : operation.diagnostics) {
        this->log(diagnostic, operation.ok ? logLevel::INFO : logLevel::WARN);
    }
    if (!operation.ok) {
        this->log(operation.message, logLevel::ERROR);
        return false;
    }
    if (operation.changed) {
        this->notify("Исправлена конфигурация sysctl для политики: " + this->policyName,
                     notifyLevel::ERROR);
    }
    this->log(operation.message, logLevel::INFO);

    const std::optional<std::string> current = runtimeValue(param);
    if (!current) {
        this->log("Не удалось прочитать текущее значение /proc/sys для " + param,
                  logLevel::DEBUG);
    } else if (*current != value) {
        this->log("Конфигурация " + param + " исправлена на диске, но текущее значение ядра '" +
                  *current + "' отличается от эталона '" + value +
                  "'. Требуется безопасное отдельное применение sysctl.", logLevel::WARN);
    }
    return true;
}
