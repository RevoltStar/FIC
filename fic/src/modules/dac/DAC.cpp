#include "modules/dac/DAC.h"

//Задаем путь к конфигурационному файлу Дискреционного разграничения доступа
DAC::DAC()
    :Policy()
{
    this->moduleName = "DAC";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();

}
