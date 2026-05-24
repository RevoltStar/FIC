// file name: UDEVInfoCollector.h
#ifndef UDEVINFOCOLLECTOR_H
#define UDEVINFOCOLLECTOR_H

#include <unordered_set>
#include <cstring>
#include "InfoCollector.h"

class UDEVInfoCollector : public InfoCollector {
protected:
    static const std::unordered_set<std::string> EXCLUDE_PARAMS;
    static const std::unordered_set<std::string> EXCLUDED_SUBSYSTEM;

public:
    UDEVInfoCollector(std::vector<std::string> _controlList = {""})
        : InfoCollector(_controlList) {}

    bool process_device_concrete() override {
        return true;
    }

    // Проверяем, что UDEV передал нам ФИЗИЧЕСКОЕ устройство
    bool check_devpath(const char* devpath);

    // Проверяем подсистему
    bool check_excluded_subsystem(const char* subsystem);


    DeviceInfo create_virtual_device_config(const std::string& devpath, const std::string& boot_id);

    // Создаем/обновляем устройство в БД
    bool create_device_config(const std::string& devpath, const std::string& subsystem);

    // Удаляем устройство (сбрасываем boot_id)
    bool safe_remove_device(const std::string& devpath, const std::string& subsystem);

    // Собираем параметры устройства из переменных окружения
    void collect_udev_params();

    // Получаем значение переменной окружения
    std::string get_env_value(const std::string& key);

    std::string getParentDevpath(const std::string& devpath);
};

#endif // UDEVINFOCOLLECTOR_H
