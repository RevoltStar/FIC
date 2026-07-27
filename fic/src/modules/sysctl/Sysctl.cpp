#include "modules/sysctl/Sysctl.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlRuntime.h"

#include <mutex>
#include <optional>

namespace {

std::mutex sysctlMutex;

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
    SysctlRuntime runtime;
    std::string runtimeBefore;
    std::string runtimeError;
    if (!runtime.readValue(param, runtimeBefore, runtimeError)) {
        this->log("Невозможно применить обязательное runtime-значение sysctl: " +
                      runtimeError,
                  logLevel::ERROR);
        return false;
    }

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
        this->log("Persistent-конфигурация sysctl исправлена; выполняется runtime-применение",
                  logLevel::INFO);
    }
    this->log(operation.message, logLevel::INFO);

    if (runtimeBefore != value) {
        this->log("Обнаружено runtime-отклонение '" + param + "'. Фактическое значение: '" +
                      runtimeBefore + "'. Ожидаемое значение: '" + value + "'.",
                  logLevel::WARN);
    }
    const SysctlRuntimeResult runtimeOperation = runtime.ensureValue(param, value);
    if (!runtimeOperation.ok) {
        this->log(
            "Persistent-конфигурация sysctl подготовлена, но обязательное runtime-применение "
            "не завершено: " + runtimeOperation.message,
            logLevel::ERROR
        );
        return false;
    }
    this->log(runtimeOperation.message, logLevel::INFO);

    if (operation.changed || runtimeOperation.changed) {
        this->notify("Исправлена конфигурация sysctl для политики: " + this->policyName,
                     notifyLevel::ERROR);
    }
    return true;
}
