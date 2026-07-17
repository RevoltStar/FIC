#ifndef INFOCOLLECTOR_H
#define INFOCOLLECTOR_H

#include <string>
#include <map>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <fic/core/Logger.h>
#include <unordered_map>
#include <fic/device-db/DB.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;


//Собиратель информации об ОС
class InfoCollector{
protected:
    //Параметры устройство
    //1-Название параметра (передается в конструкторе)
    //2-Значение параметра (вычисляется в process_device_concrete)
    std::map<std::string, std::string> deviceParam;

    //Параметры на контроле (обязательные)
    std::vector<std::string> controlList;

    //Дополнительные параметры для контроля
    //В первую очередь для USB и block
    std::vector<std::string> additionalControlList;


    //Обрезать лишнее
    void trim(std::string& val);
    //Вычисляем boot_time
    std::string get_boot_id();
    std::filesystem::path data_directory() const;

    //Обработка устройства (сохранение)
    bool process_device(
                             const std::string& device_type,
                             const fs::path& list_dir);
public:
    bool log(std::string message, logLevel logLev);
    //Собственно обработка конкретного типа устройства
    //Конкретно - обработка параметров устройства
    virtual bool process_device_concrete() = 0;
    InfoCollector(std::vector<std::string> _controlList);
    //Вычисляем хэш для папки
    std::string create_hash();
    virtual ~InfoCollector() = default;

};


#endif // INFOCOLLECTOR_H
