#ifndef POLICY_H
#define POLICY_H

//Логгирование
#include "utils/Logger.h"
//Уведомление
#include "utils/NotifyUser.h"
//Работа с конфигурационными файлами модулей
#include "utils/ModuleConfigFileHandler.h"
#include "utils/PolicyTypeValue.h"
#include <memory>
#include <optional>

class Policy
{
protected:
    //Конфигурационный файл с настройками модуля
    std::unique_ptr<ModuleConfigFileHandler> moduleConf;

    //Получить включенное значение из глобального конфига программы (GLOBAL.conf)
    std::optional<std::string> getGlobalConfigValue(const std::string& parameter);

    //Тип значения политики
    std::unique_ptr<PolicyTypeValue> policyTypeValue;
    bool isPolicyTypeValueSet() const {
        if(policyTypeValue == nullptr){
            return false;
        }
        return true;
    }
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

    //Логгировать (через this->logger)
    bool log(std::string message, logLevel logLev);

    //Уведомление для пользователя
    bool notify(std::string message, notifyLevel notifyLev);

    //Конструктор
    Policy();
    //Деструктор
    virtual ~Policy();

    //Применить политику
    //Конкретные действия должны определяться в наследуемых классах
    virtual bool apply() = 0;
};

#endif // POLICY_H
