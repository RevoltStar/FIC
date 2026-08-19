// file name: UDEVInfoCollector.h
#ifndef UDEVINFOCOLLECTOR_H
#define UDEVINFOCOLLECTOR_H

#include <unordered_set>
#include <cstring>
#include <map>
#include "InfoCollector.h"

class UDEVInfoCollector : public InfoCollector {
protected:
    static const std::unordered_set<std::string> EXCLUDE_PARAMS;
    std::map<std::string, std::string> udevEnv;

    void set_control_list(const std::vector<std::string>& newControlList);
    virtual std::vector<std::string> control_list_for_current_env() const;
    virtual std::map<std::string, std::string> extra_device_attributes() const;
    virtual std::string device_note_suffix() const;
    void refresh_control_list();

public:
    UDEVInfoCollector(std::vector<std::string> _controlList = {""})
        : InfoCollector(_controlList) {}

    bool process_device_concrete() override {
        return true;
    }

    // Проверяем, что UDEV передал нам ФИЗИЧЕСКОЕ устройство
    bool check_devpath(const char* devpath);

    DeviceInfo create_virtual_device_config(const std::string& devpath, const std::string& boot_id);

    // Создаем/обновляем устройство в БД
    bool create_device_config(const std::string& devpath, const std::string& subsystem);

    // Собираем параметры устройства из переменных окружения
    void collect_udev_params();

    // Задать udev environment явно. Используется daemon mode: helper передает env через socket.
    void set_udev_env(const std::map<std::string, std::string>& env);

    std::map<std::string, std::string> collect_all_udev_attributes();

    // Получаем значение переменной окружения
    std::string get_env_value(const std::string& key) const;

    std::string getParentDevpath(const std::string& devpath);
};

#endif // UDEVINFOCOLLECTOR_H
