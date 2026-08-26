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
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

class PolicyRegistry;

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
    bool hasConfiguredValue(){
        return this->moduleConf->hasConfiguredValue(this->policyName);
    }


    const PolicyTypeValue& getPolicyTypeValue() const {
        if(this->isPolicyTypeValueSet()){
            return *this->policyTypeValue;
        }
        throw std::runtime_error("policyTypeValue не был установлен. Требуются правки кода");
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
    bool isEnabled(){
        if(moduleConf->getPolicyStatus(this->policyName) == "ENABLE"){
            return true;
        }
        return false;
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
