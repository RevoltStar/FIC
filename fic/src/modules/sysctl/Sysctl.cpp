#include "modules/sysctl/Sysctl.h"
#include <exception>
#include <vector>

namespace {

FileHandlerOptions sysctlFileOptions() {
    FileHandlerOptions options;
    options.writeOptions.createIfMissing = true;
    options.writeOptions.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.writeOptions.fileMode = 0644;
    options.writeOptions.fileOwner = 0;
    options.writeOptions.fileGroup = 0;
    return options;
}

} // namespace

std::string Sysctl::sysctlPath="/etc/sysctl.conf";
std::unique_ptr<ConfigFileHandler> Sysctl::sysctlConfig =
        std::make_unique<ConfigFileHandler>(Sysctl::sysctlPath, "=", sysctlFileOptions());

Sysctl::Sysctl()
    :Policy(){
    this->moduleName = "SYSCTL";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}


// Correct /etc/sysctl.conf according to one sysctl parameter policy.
bool Sysctl::apply (){
    this->log("Запущена проверка политики " + this->policyName, logLevel::INFO);
    if (this->Sysctl::sysctlParameter.empty()){
        this->log("Имя контролируемого параметра пусто", logLevel::ERROR);
        return false;
    }
    if(!this->sysctlConfig->loadConfig()){
        this->log("Не удалось открыть для чтения файл /etc/sysctl.conf", logLevel::ERROR);
        return false;
    }

    std::vector<std::string> errors;

    //Какой параметр контролируем
    auto param = this->Sysctl::sysctlParameter;
    //Какое значение у него должно быть
    //auto value = this->Sysctl::sysctlParameterValue;
    std::string value = ""; 

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

    if(this->sysctlConfig->isParameterExists(param)){
        auto valueFact = this->sysctlConfig->getValue(param);

        if(value != valueFact){
            this->sysctlConfig->setValue(param, value);

            errors.push_back("Обнаружено отклонение '"+param+
                             "'. Фактическое значение: '"+valueFact+"'"+
                             "Ожидаемое значение: '"+value+"'");
            this->log(errors.back(), logLevel::INFO);
        }
    }else{
        errors.push_back("Параметр " + param + " не установлен");
        this->log("Параметр " + param + " не был установлен. Попытка добавления...", logLevel::DEBUG);
        if(!this->sysctlConfig->setValue(param, value)){
            this->log("Произошла ошибка при добавлении параметра " + param, logLevel::ERROR);
        }
    }

    if(!errors.empty()){
        this->log("Некоторые параметры не совпадают с эталоном для политики " + this->policyName, logLevel::WARN);
        this->notify("Некоторые параметры не совпадают с эталоном для политики: " + this->policyName, notifyLevel::ERROR);

        bool isSave = this->sysctlConfig->saveFile();
        if(!isSave){
            this->log("Не удалось применить изменения", logLevel::ERROR);
            return false;
        }else{
            this->log("Отклонение было исправлено", logLevel::INFO);
        }
    }else{
        this->log("Отклонений не обнаружено", logLevel::INFO);
    }
    return true;
}
