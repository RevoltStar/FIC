#ifndef POLICY_H
#define POLICY_H

//Логгирование
#include <fic/core/logging/Logger.h>
//Уведомление
#include <fic/core/notification/NotifyUser.h>
//Работа с конфигурационными файлами модулей
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/policy/PolicyDependency.h>
#include <fic/policy/PolicyTypeValue.h>
#include <fic/core/incident/IncidentSeverity.h>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

class PolicyRegistry;

enum class PolicyCapability {
    SessionAware,
    SessionInventoryCompliance,
    GlobalDesktopConfiguration
};

class Policy
{
protected:
    //Конфигурационный файл с настройками модуля
    std::unique_ptr<ModuleConfigFileHandler> moduleConf;

    //Тип значения политики
    std::unique_ptr<PolicyTypeValue> policyTypeValue;
    bool isPolicyTypeValueSet() const {
        if(policyTypeValue == nullptr){
            return false;
        }
        return true;
    }

    void addRequiredDependency(const PolicyRef& policy);
    void addRequiredDependency(
        const PolicyRef& policy,
        const PolicyDependencyCondition& condition);
    void addRecommendedDependency(const PolicyRef& policy);
    void addRecommendedDependency(
        const PolicyRef& policy,
        const PolicyDependencyCondition& condition);
public:
    //Задано ли значение политики в конфигурационном файле
    bool hasConfiguredValue() const {
        return this->moduleConf->hasConfiguredValue(this->policyName);
    }


    const PolicyTypeValue& getPolicyTypeValue() const {
        if(this->isPolicyTypeValueSet()){
            return *this->policyTypeValue;
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
    }

    //Стабильная ссылка на политику (модуль/субмодуль/имя) для общих контрактов
    PolicyRef policyRef() const {
        return PolicyRef{this->moduleName, this->submoduleName, this->policyName};
    }

    //Получаем значение параметра
    //Возвращаем nullopt, если значение не установлено или невалидно
    std::optional<std::string> getValue() {
        if (!this->moduleConf->hasConfiguredValue(this->policyName)) {
            const auto* fixedValue =
                dynamic_cast<const FixedPolicyTypeValue*>(this->policyTypeValue.get());
            if (fixedValue != nullptr) {
                const std::optional<std::string> intrinsicValue =
                    fixedValue->getIntrinsicValue();
                if (intrinsicValue.has_value()) {
                    return intrinsicValue;
                }
            }
            this->log("Значение политики " + this->policyName + " не установлено", logLevel::ERROR);
            return std::nullopt;
        }
        //Получаем значение его в вид для конф. файла утилиты
        std::string value = this->reverse_postprocessingValue(
            this->moduleConf->getValue(this->policyName)
            );

        //Предварительно валидируем значение. Не прошло валидацию - не применяем политику
        if (!this->validate(value)) {
            this->log("Invalid policy value for " + this->policyName + ": " + value, logLevel::ERROR);
            return std::nullopt;
        }

        return value;
    }

    /*
    //Дать значение после postproccessing
    std::string getValueAfterPostProcessing(){

    }
    */

    //Дать значение по умолчанию
    std::string getDefaultValue(){
        if(this->isPolicyTypeValueSet()){
            return policyTypeValue->getDefaultValue();
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
    }

    //Включена ли указанная политика?
    bool isEnabled() const {
        return moduleConf->getPolicyStatus(this->policyName) == "ENABLE";
    }

    // Severity this Policy raises the system incident to when it FAILS.
    //
    // ViolationSeverity::None (the default) means "never react": such a
    // policy contributes nothing to incident state. Every reacting policy
    // declares its OWN severity - there is deliberately no inheritance along
    // the dependency graph. A policy that is blocked by a Required
    // dependency still raises its own severity, because the policy itself
    // ended in Failed.
    ::fic::core::ViolationSeverity getViolationSeverity() const {
        if (moduleConf != nullptr &&
            moduleConf->hasPolicyViolationSeverity(this->policyName)) {
            return moduleConf->getPolicyViolationSeverity(this->policyName);
        }
        return getDefaultViolationSeverity();
    }

    // Compiled-in default used when the module configuration does not carry
    // an explicit <policy>.violation_severity entry.
    virtual ::fic::core::ViolationSeverity getDefaultViolationSeverity() const {
        return ::fic::core::ViolationSeverity::None;
    }
    //Валидация параметра
    bool validate(std::string value){
        if(this->isPolicyTypeValueSet()){
            return policyTypeValue->validate(value);
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
    }
    std::string getPolicyRestriction(){
        if(this->isPolicyTypeValueSet()){
            return policyTypeValue->getPolicyRestrictionInfo() + "\n";
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
    }

    //Постобработка параметра (для записи в конфигурационный файл)
    std::string postprocessingValue(std::string value){
        if(this->isPolicyTypeValueSet()){
            return policyTypeValue->postProcessingValue(value);
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
    }
    //Извлеченное значение, которое должно быть записано из конфигурационного файла модуля -> в конфиг утилиты
    //
    std::string reverse_postprocessingValue(std::string value){
        if(this->isPolicyTypeValueSet()){
            return policyTypeValue->reverse_postProcessingValue(value);
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
    }

    //Имя модуля (DAC,OSS, etc...)
    std::string moduleName="";
    //Имя политики
    std::string policyName="";
    //Название подмодуля
    std::string submoduleName="";

    const std::vector<PolicyDependency>& dependencies() const;

    //Логгировать (через this->logger)
    bool log(std::string message, logLevel logLev);

    //Уведомление для пользователя
    bool notify(std::string message, notifyLevel notifyLev);

    //Конструктор
    Policy();
    //Деструктор
    virtual ~Policy();

    // Применить политику.
    // true означает, что persistent-состояние проверено, а все физически
    // возможные и безопасные без перезагрузки runtime-эффекты применены и
    // проверены. Любое неполное обязательное применение возвращает false.
    // Опасные действия активации (например, remount файловых систем) и эффекты,
    // требующие перезагрузки, намеренно не выполняются.
    virtual bool apply() = 0;
    virtual std::vector<PolicyCapability> capabilities() const { return {}; }

private:
    friend class PolicyRegistry;

    void addDependency(
        const PolicyRef& policy,
        PolicyDependencyStrength strength,
        const PolicyDependencyCondition& condition);
    void freezeDependencies();

    std::vector<PolicyDependency> dependencies_;
    bool dependenciesFrozen_ = false;
};

#endif // POLICY_H
