// file name: UDEVInfoCollector.cpp
#include "UDEVInfoCollector.h"
#include "device/DevicePaths.h"
#include <functional>
#include <filesystem>

extern char **environ;

const std::unordered_set<std::string> UDEVInfoCollector::EXCLUDE_PARAMS = {
    "_", "ACTION", "PWD", "DRIVER", "USEC_INITIALIZED", "SEQNUM", "SHLVL", "SYNTH_UUID"
};

bool UDEVInfoCollector::check_devpath(const char* devpath) {
    // Проверка на nullptr
    if (devpath == nullptr) {
        return false;
    }

    this->log("Проверяем DEVPATH для устройства: " + std::string(devpath), logLevel::DEBUG);

    // Проверка, что путь начинается с /devices/
    if (strncmp(devpath, "/devices/", 9) != 0) {
        this->log("Устройство исключено: DEVPATH не начинается с /devices/: (" + std::string(devpath) + ")", logLevel::TRACE);
        return false;
    }

    std::filesystem::path sysfsPath = (std::filesystem::path("/sys") / std::string(devpath).substr(1)).lexically_normal();
    const std::filesystem::path sysDevices = std::filesystem::path("/sys/devices");
    std::string normalized = sysfsPath.string();
    if (normalized.rfind(sysDevices.string() + "/", 0) != 0) {
        this->log("Устройство исключено: DEVPATH выходит за пределы /sys/devices: (" + std::string(devpath) + ")", logLevel::TRACE);
        return false;
    }

    // Проверка, что путь НЕ начинается с /devices/virtual, кроме управляемых virtual block устройств.
    if (strncmp(devpath, "/devices/virtual", 16) == 0 &&
        strncmp(devpath, "/devices/virtual/block/", 23) != 0) {
        this->log("Виртуальное устройство исключено: " + std::string(devpath), logLevel::TRACE);
        return false;
    }

    return true;
}

// /devices/some1/some2 -> /devices/some1
std::string UDEVInfoCollector::getParentDevpath(const std::string& devpath){
    size_t pos =  devpath.rfind('/');
       if (pos != std::string::npos && pos > 0) {
           return  devpath.substr(0, pos);
       }
       return  "/devices/unclassified";
}

void UDEVInfoCollector::set_control_list(const std::vector<std::string>& newControlList) {
    this->controlList = newControlList;
    this->deviceParam.clear();
    for (const auto& elem : this->controlList) {
        this->deviceParam[elem] = "";
    }
}

std::vector<std::string> UDEVInfoCollector::control_list_for_current_env() const {
    return this->controlList;
}

std::map<std::string, std::string> UDEVInfoCollector::extra_device_attributes() const {
    return {};
}

std::string UDEVInfoCollector::device_note_suffix() const {
    return "";
}

void UDEVInfoCollector::refresh_control_list() {
    set_control_list(control_list_for_current_env());
}

std::string UDEVInfoCollector::get_env_value(const std::string& key) const {
    auto explicitValue = this->udevEnv.find(key);
    if (explicitValue != this->udevEnv.end()) {
        return explicitValue->second;
    }

    const char* value = std::getenv(key.c_str());
    return value ? std::string(value) : "";
}

void UDEVInfoCollector::set_udev_env(const std::map<std::string, std::string>& env) {
    this->udevEnv = env;
    refresh_control_list();
}

std::map<std::string, std::string> UDEVInfoCollector::collect_all_udev_attributes() {
    std::map<std::string, std::string> attributes;

    if (!this->udevEnv.empty()) {
        for (const auto& [key, value] : this->udevEnv) {
            if (value.empty() || EXCLUDE_PARAMS.find(key) != EXCLUDE_PARAMS.end()) {
                continue;
            }
            attributes[key] = value;
        }
        for (const auto& [key, value] : this->extra_device_attributes()) {
            if (!value.empty()) {
                attributes[key] = value;
            }
        }
        return attributes;
    }

    for (char **env = environ; env != nullptr && *env != nullptr; ++env) {
        std::string entry(*env);
        const std::size_t separator = entry.find('=');
        if (separator == std::string::npos || separator == 0) {
            continue;
        }

        const std::string key = entry.substr(0, separator);
        const std::string value = entry.substr(separator + 1);
        if (value.empty() || EXCLUDE_PARAMS.find(key) != EXCLUDE_PARAMS.end()) {
            continue;
        }

        attributes[key] = value;
    }

    for (const auto& [key, value] : this->extra_device_attributes()) {
        if (!value.empty()) {
            attributes[key] = value;
        }
    }

    return attributes;
}

void UDEVInfoCollector::collect_udev_params() {
    // Сбрасываем все параметры
    for (auto& [key, value] : this->deviceParam) {
        value = "";
    }

    // Собираем значения из переменных окружения
    for (const auto& param : this->controlList) {
        std::string value = get_env_value(param);
        if (!value.empty()) {
            this->deviceParam[param] = value;
        }
    }
}
//Создаем виртуальное дерево (чтобы учесть разный порядок сохранения в БД и то, что родительское устройство может вообще не проходить через правило UDEV)
//Функция должна отрабатывать рекурсивно.
//Чтобы идентифицировать такие устройства, мы будем использовать subsystem=__virtual__
DeviceInfo UDEVInfoCollector::create_virtual_device_config(const std::string& devpath, const std::string& boot_id){
    DB db(fic::device_control::DeviceRuntimePaths::get().databaseOptions());
    //Пытаемся найти родительское устройство (возможно, оно тоже виртуальное)
    std::string parent_devpath = this->getParentDevpath(devpath);
    DeviceInfo parentDevice;
    //Ищем родительское устройство по родительскому пути и времени старта ОС.
    if(parent_devpath == "/devices" || parent_devpath == "/devices/pci0000:00"){
        parentDevice = db.getDeviceByPathAndBootId(parent_devpath, "-1");
    }else{
        parentDevice = db.getDeviceByPathAndBootId(parent_devpath, boot_id);
    }
    if(parentDevice.id==-1){
        //Если не нашли => рекурсивно создаем ещё одно виртуальное
        parentDevice = this->create_virtual_device_config(parent_devpath, boot_id);
        if(parentDevice.id == -1){
            /*Такого быть не должно
             * Бросаем исключение*/
            return DeviceInfo {-1};
        }
    }
    this->log("Нашли родительское устройство для создаваемого виртуального", logLevel::DEBUG);
    this->log("Создаем виртуальное устройство", logLevel::DEBUG);
    DeviceInfo existing_virtual_device = db.getDeviceByDevpathAndSubsystem(devpath, "__virtual__");
    if (existing_virtual_device.id != -1) {
        existing_virtual_device.parent_id = parentDevice.id;
        existing_virtual_device.boot_id = boot_id;
        existing_virtual_device.device_hash = "virtual_hash_for_device[" + devpath + "]";

        if (!db.updateDevice(existing_virtual_device, existing_virtual_device.id)) {
            return DeviceInfo{-1};
        }

        return existing_virtual_device;
    }

    DeviceInfo new_device{
        0,
        "virtual_hash_for_device[" + devpath + "]", //device_hash
        devpath,
        "__virtual__", //subsystem
        "__virtual__",  // device_type = subsystem
        parentDevice.id, //parent_id
        parentDevice.control_level, // control_level
        false, // control_explicit: виртуальный узел наследует родителя
        false,  // ignore_hierarchy = false по умолчанию
        boot_id, //boot_id
        "",  // created_at заполнится автоматически
        "",  // last_event_at заполнится автоматически
        "VIRTUAL UDEV device: " + devpath
    };
    int device_id = db.addDevice(new_device);
    new_device.id = device_id;
    //Получить устройство по id
    return new_device;
}
bool UDEVInfoCollector::create_device_config(const std::string& devpath, const std::string& subsystem) {
    try {
        this->log("Начинаем добавление/обновление устройства: " + devpath, logLevel::DEBUG);

        refresh_control_list();
        if(this->deviceParam.empty()){
            this->log("Не заданы параметры контроля для устройства:" + devpath, logLevel::WARN);
            return false;
        }
        // Собираем параметры из переменных окружения
        collect_udev_params();

        // Получаем время загрузки системы
        std::string boot_id = get_boot_id();
        if (boot_id.empty()) {
            this->log("Не удалось получить время загрузки системы", logLevel::ERROR);
            /* Кидаем исключение */
            return false;
        }

        this->log("boot_id текущей загрузки: " + boot_id, logLevel::TRACE);

        // Генерируем хеш устройства
        std::string current_hash = create_hash();
        this->log("Вычисленный хеш устройства: " + current_hash, logLevel::DEBUG);

        DB db(fic::device_control::DeviceRuntimePaths::get().databaseOptions());

        //devpath родителя
        std::string parent_devpath = this->getParentDevpath(devpath);
        //Получаем родительское устройство

        this->log("devpath устройства: " + devpath, logLevel::TRACE);
        this->log("Родительский devpath: " + parent_devpath, logLevel::TRACE);

        DeviceInfo parent_device;
        if(parent_devpath == "/devices" || parent_devpath == "/devices/pci0000:00"){
            this->log("Ищем среди предустановленных устройств", logLevel::DEBUG);
            parent_device = db.getDeviceByPathAndBootId(parent_devpath, "-1");
            if(parent_device.id == -1){
                /* Так быть не должно => Кидаем исключение */
                return false;
            }
        }else{
            this->log("Ищем среди не предустановленных устройств", logLevel::DEBUG);
            parent_device = db.getDeviceByPathAndBootId(parent_devpath, boot_id);
            if(parent_device.id == -1){
                //Мы не нашли предка (по родительскому пути и времени старта ОС) =>
                //Пытаемся создать иерархию
                parent_device = this->create_virtual_device_config(parent_devpath, boot_id);
                if(parent_device.id == -1){
                    /* Кидаем исключение */
                    return false;
                }else{
                    this->log("Создали виртуального родителя", logLevel::DEBUG);
                }
            }

        }

        /*У нас тут уже точно должен быть какой-то родитель*/
        auto addAttributes = [&](int deviceId) {
            for (const auto& [key, value] : this->collect_all_udev_attributes()) {
                if (!value.empty() && !db.addDeviceAttribute(deviceId, key, value)) {
                    this->log("Ошибка записи атрибута " + key + " для устройства ID: " + std::to_string(deviceId), logLevel::ERROR);
                    return false;
                }
            }
            return true;
        };

        auto rollbackAndFail = [&]() {
            db.rollbackTransaction();
            return false;
        };

        if (!db.beginTransaction()) {
            this->log("Не удалось начать транзакцию записи устройства", logLevel::ERROR);
            return false;
        }

        // 1. Сначала проверяем, существует ли устройство с тем же хешем, подсистемой и родителем
               DeviceInfo existing_device = db.getDeviceByHashAndSubsystemAndParent(current_hash, subsystem, parent_device.id);
               if (existing_device.id != -1) {
                   existing_device.devpath = devpath;
                   existing_device.subsystem = subsystem;
                   existing_device.device_type = subsystem;
                   existing_device.parent_id = parent_device.id;
                   existing_device.boot_id = boot_id;
                   existing_device.notes = "UDEV device updated: " + devpath + device_note_suffix();
                   if (!db.updateDevice(existing_device, existing_device.id)) {
                       return rollbackAndFail();
                   }
                   if (!addAttributes(existing_device.id)) {
                       return rollbackAndFail();
                   }
                   return db.commitTransaction();
               }

               // 2. Проверяем, существует ли виртуальное устройство для этого пути
               DeviceInfo existing_virtual_device = db.getDeviceByDevpathAndSubsystem(devpath, "__virtual__");
               if (existing_virtual_device.id != -1) {
                   this->log("Найдено виртуальное устройство, обновляем его", logLevel::DEBUG);

                   // Обновляем виртуальное устройство на физическое
                   DeviceInfo updated_device{
                       0, //
                       current_hash,              // Меняем на реальный хеш
                       devpath,                   // devpath остается тем же
                       subsystem,                 // Меняем на реальную подсистему
                       subsystem,                 // Меняем на реальный тип
                       parent_device.id,          // Родитель остается тем же
                       existing_virtual_device.control_level,
                       existing_virtual_device.control_explicit,
                       existing_virtual_device.ignore_hierarchy,
                       boot_id,                   // Обновляем boot_id
                       existing_virtual_device.created_at, // Сохраняем время создания
                       "",                        // last_event_at обновится
                       "Обновлено из виртуального: " + devpath + device_note_suffix(),
                       existing_virtual_device.children_control
                   };

                   if (!db.updateDevice(updated_device, existing_virtual_device.id)) {
                       this->log("Ошибка обновления виртуального устройства", logLevel::ERROR);
                       return rollbackAndFail();
                   }

                   if (!addAttributes(existing_virtual_device.id)) {
                       return rollbackAndFail();
                   }
                   return db.commitTransaction();
               }

               // 3. Проверяем устройство без привязки к иерархии
               DeviceInfo existing_device_no_hierarchy = db.getDeviceByHashAndSubsystem(current_hash, subsystem);

               if (existing_device_no_hierarchy.id != -1) {
                   this->log("Устройство с такой идентичностью уже встречалось в другой ветке, создаем новую occurrence", logLevel::DEBUG);

                   DeviceInfo new_device{
                       0,
                       current_hash,
                       devpath,
                       subsystem,
                       subsystem,
                       parent_device.id,
                       parent_device.control_level,
                       false,
                       false,
                       boot_id,
                       "",
                       "",
                       "UDEV device occurrence: " + devpath + device_note_suffix()
                   };

                   int device_id = db.addDevice(new_device);
                   if (device_id == -1) return rollbackAndFail();

                   if (!addAttributes(device_id)) {
                       return rollbackAndFail();
                   }
                   return db.commitTransaction();
               }

               // 4. Устройство не найдено нигде - создаем новое
               this->log("Создаем новое устройство в БД", logLevel::DEBUG);

               DeviceInfo new_device{
                   0,
                   current_hash,
                   devpath,
                   subsystem,
                   subsystem,
                   parent_device.id,
                   parent_device.control_level,
                   false,
                   false,
                   boot_id,
                   "",
                   "",
                   "UDEV device: " + devpath + device_note_suffix()
               };

               int device_id = db.addDevice(new_device);
               if (device_id == -1){
                    this->log("Ошибка создания устройства в БД", logLevel::ERROR);
                    return rollbackAndFail();
               }

               if (!addAttributes(device_id)) {
                   return rollbackAndFail();
               }

               return db.commitTransaction();
    } catch (const std::exception& e) {
        std::cerr << "Ошибка в create_device_config: " << e.what() << std::endl;
        return false;
    }
}
