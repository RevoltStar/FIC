#include "modules/dac/submodules/Sudo.h"

Sudo::~Sudo() {
    // Реализация деструктора
}

// Путь к sudoers
const std::string Sudo::sudoersPath="/etc/sudoers";
/*const std::string Sudo::sudoersPath="/home/MFC.LOCAL/poroshinmi/sudoers-test.txt";*/
/*const std::unique_ptr<ConfigFileHandler> Sudo::sudoConfig =
        std::make_unique<ConfigFileHandler>(Sudo::sudoersPath);*/

std::unique_ptr<SudoersConfigFileHandler> Sudo::sudoConfig =
        std::make_unique<SudoersConfigFileHandler>(Sudo::sudoersPath);

Sudo::Sudo()
    : DAC(){
    this->submoduleName = "SudoEdit";
    /*this->Check_And_Fix::postProcessingParameter = std::make_unique<PostProcessingParameter>(PostProcessingParameter::ToJsonWithColon);*/
    /*this->Check_And_Fix::postProcessingValue = std::make_unique<PostProcessingValueJSON>(",", ",");*/
}

// Проверить файл sudoers
bool Sudo::checkValid(std::string sudoersPath){
    const std::string request = "visudo -c -f " + sudoersPath;
    int result = system(request.c_str());
    if (result == 0) {
        std::cout << "/etc/sudoers is syntactically valid." << std::endl;
        return true;
    } else {
        std::cerr << "Error: /etc/sudoers is syntactically invalid. Check with visudo." << std::endl;
        return false;
    }
}

// Проверить и исправить параметр sudo
bool Sudo::apply() {
    if (this->Sudo::sudoParameter == nullptr){
        this->log("Не задан sudoParameter", logLevel::FATAL);
        return false;
    }

    if(!this->sudoConfig->loadConfig()){
        this->log("Не удалось проанализировать файл /etc/sudoers", logLevel::ERROR);
        return false;
    }

    const std::string valueOld = this->sudoConfig->getValue(*this->Sudo::sudoParameter);
    auto valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    std::string valueNew = *valueOpt;
    if(valueNew.empty()){
        this->log("Эталон не задан", logLevel::ERROR);
        return false;
    }

    if(valueOld == valueNew){
        this->log("Отклонений не обнаружено", logLevel::INFO);
        return true;
    }

    this->log("Обнаружено отклонение параметра: '" +
              this->Sudo::sudoParameter->getParamString() + "'", logLevel::WARN);
    this->log("Фактическое:'" + valueOld + "' Ожидаемое:'" + valueNew + "'", logLevel::WARN);

    if(!this->sudoConfig->setValue(*this->Sudo::sudoParameter, valueNew)){
        this->log("Не удалось обновить параметр в sudoers", logLevel::ERROR);
        return false;
    }

    if(!this->sudoConfig->saveFile()){
        this->log("Не удалось сохранить файл", logLevel::ERROR);
        return false;
    }

    this->log("Отклонение было исправлено", logLevel::INFO);
    return true;
}
