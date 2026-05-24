// file name: UDEVInfoCollector.cpp
#include "UDEVInfoCollector.h"
#include <functional>

const std::unordered_set<std::string> UDEVInfoCollector::EXCLUDE_PARAMS = {
    "_", "ACTION", "PWD", "DRIVER", "USEC_INITIALIZED", "SEQNUM", "SHLVL", "SYNTH_UUID"
};

const std::unordered_set<std::string> UDEVInfoCollector::EXCLUDED_SUBSYSTEM = {
    "", "acpi", "ac97", "ata_device", "ata_link", "ata_port", "bdi", "bsg", "edac", "clocksource", "clockevents",
    "container", "cpu", "devlink", "dma", "dmi", "drm", "drm_dp_aux_dev", "event_source",
    "graphics", "hdaudio", "hidraw", "hwmon", "i2c", "i2c-dev", "input", "leds", "machinecheck",
    "mdio_bus", "mei", "mem", "memory", "memory_tiering", "misc", "msr", "net", "node",
    "nvmem", "pci_bus", "platform", "parport", "power_supply", "pnp", "powercap", "queues", "regulator", "rtc", "serial-base", "scsi", "scsi_generic",
    "scsi_device", "scsi_disk", "scsi_host", "sound", "tpm", "tpmrm", "thermal", "tty", "vc", "virtio", "virtual",
    "serio", "vtconsole", "watchdog", "wakeup", "wmi", "wmi_bus", "workqueue"
};

bool UDEVInfoCollector::check_devpath(const char* devpath) {
    this->log("Проверяем DEVPATH для устройства: " + std::string(devpath), logLevel::DEBUG);

    // Проверка на nullptr
    if (devpath == nullptr) {
        return false;
    }

    // Проверка, что путь начинается с /devices/
    if (strncmp(devpath, "/devices/", 9) != 0) {
        this->log("Устройство исключено: DEVPATH не начинается с /devices/: (" + std::string(devpath) + ")", logLevel::TRACE);
        return false;
    }

    // Проверка, что путь НЕ начинается с /devices/virtual
    if (strncmp(devpath, "/devices/virtual", 16) == 0) {
        this->log("Виртуальное устройство исключено: " + std::string(devpath), logLevel::TRACE);
        return false;
    }

    return true;
}

bool UDEVInfoCollector::check_excluded_subsystem(const char* subsystem) {
    this->log("Проверяем SUBSYSTEM (" + std::string(subsystem) + ")", logLevel::DEBUG);
    if (subsystem == nullptr) {
        this->log("SUBSYSTEM не задан", logLevel::TRACE);
        return false;
    }

    if (EXCLUDED_SUBSYSTEM.find(subsystem) != EXCLUDED_SUBSYSTEM.end()) {
        this->log("SUBSYSTEM (" + std::string(subsystem) + ") находится в списке исключенных. Пропускаем...", logLevel::TRACE);
        return false;
    } else {
        this->log("SUBSYSTEM (" + std::string(subsystem) + ") не находится в списке исключенных. Обрабатываем дальше...", logLevel::TRACE);
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

std::string UDEVInfoCollector::get_env_value(const std::string& key) {
    const char* value = std::getenv(key.c_str());
    return value ? std::string(value) : "";
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
    DB db = DB("/opt/fic/db/devices.db");
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

        DB db = DB("/opt/fic/db/devices.db");

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

        // 1. Сначала проверяем, существует ли устройство с тем же хешем, подсистемой и родителем
               DeviceInfo existing_device = db.getDeviceByHashAndSubsystemAndParent(current_hash, subsystem, parent_device.id);
               if (existing_device.id != -1) {
                   return db.updateBootId(existing_device.id, boot_id);
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
                       parent_device.control_level, // Наследуем от родителя
                       false,                     // Это физическое устройство
                       boot_id,                   // Обновляем boot_id
                       existing_virtual_device.created_at, // Сохраняем время создания
                       "",                        // last_event_at обновится
                       "Обновлено из виртуального: " + devpath
                   };

                   if (!db.updateDevice(updated_device, existing_virtual_device.id)) {
                       this->log("Ошибка обновления виртуального устройства", logLevel::ERROR);
                       return false;
                   }

                   // Добавляем атрибуты
                   for (const auto& [key, value] : this->deviceParam) {
                       if (!value.empty()) {
                           db.addDeviceAttribute(existing_virtual_device.id, key, value);
                       }
                   }
                   return true;
               }

               // 3. Проверяем устройство без привязки к иерархии
               DeviceInfo existing_device_no_hierarchy = db.getDeviceByHashAndSubsystem(current_hash, subsystem);

               if (existing_device_no_hierarchy.id != -1) {
                   if (existing_device_no_hierarchy.ignore_hierarchy) {
                       //ignore_hierarchy = true
                       this->log("Устройство существует с ignore_hierarchy, создаем копию", logLevel::DEBUG);

                       DeviceInfo new_device{
                           0,
                           current_hash,
                           devpath,
                           subsystem,
                           subsystem,
                           parent_device.id,
                           existing_device_no_hierarchy.control_level,
                           true,
                           boot_id,
                           "",
                           "",
                           "UDEV device: " + devpath
                       };

                       int device_id = db.addDevice(new_device);
                       if (device_id == -1) return false;

                       // Добавляем атрибуты
                       for (const auto& [key, value] : this->deviceParam) {
                           if (!value.empty()) {
                               db.addDeviceAttribute(device_id, key, value);
                           }
                       }
                       return true;
                   } else {
                       // ignore_hierarchy = false
                       this->log("Устройство существует без иерархии, обновляем parent_id", logLevel::DEBUG);

                       existing_device_no_hierarchy.parent_id = parent_device.id;
                       existing_device_no_hierarchy.boot_id = boot_id;

                       if (!db.updateDevice(existing_device_no_hierarchy, existing_device_no_hierarchy.id)) {
                           return false;
                       }

                       // Обновляем атрибуты
                       for (const auto& [key, value] : this->deviceParam) {
                           if (!value.empty()) {
                               db.addDeviceAttribute(existing_device_no_hierarchy.id, key, value);
                           }
                       }
                       return true;
                   }
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
                   boot_id,
                   "",
                   "",
                   "UDEV device: " + devpath
               };

               int device_id = db.addDevice(new_device);
               if (device_id == -1){
                    this->log("Ошибка создания устройства в БД", logLevel::ERROR);
                    return false;
               }

               // Добавляем атрибуты
               for (const auto& [key, value] : this->deviceParam) {
                   if (!value.empty()) {
                       db.addDeviceAttribute(device_id, key, value);
                   }
               }

               return true;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка в create_device_config: " << e.what() << std::endl;
        return false;
    }
}

bool UDEVInfoCollector::safe_remove_device(const std::string& devpath, const std::string& subsystem) {
    try {
        this->log("Начинаем удаление устройства: " + devpath, logLevel::TRACE);

        // Собираем параметры из переменных окружения
        collect_udev_params();

        // Генерируем хеш устройства
        std::string current_hash = create_hash();
        std::string boot_id = get_boot_id();
        if (boot_id.empty()) {
            this->log("Failed to get current boot_id while removing device: " + devpath, logLevel::ERROR);
            return false;
        }

        DB db = DB("/opt/fic/db/devices.db");

        // Получаем родительский контейнер UDEV
        std::string parent_devpath = this->getParentDevpath(devpath);
        DeviceInfo parent_device{-1};
        if (parent_devpath == "/devices") {
            parent_device = db.getDeviceByDevpathSubsystemAndBootId(parent_devpath, "__udev__", "-1");
        } else if (parent_devpath == "/devices/pci0000:00") {
            parent_device = db.getDeviceByDevpathSubsystemAndBootId(parent_devpath, "__pci__", "-1");
        } else {
            parent_device = db.getDeviceByDevpathSubsystemAndBootId(parent_devpath, subsystem, boot_id);
            if (parent_device.id == -1) {
                parent_device = db.getDeviceByDevpathSubsystemAndBootId(parent_devpath, "__virtual__", boot_id);
            }
        }

        int parent_id = parent_device.id;
        if (parent_id == -1) {
            this->log("Не найден родительский контейнер UDEV", logLevel::ERROR);
            return false;
        }

        // Ищем само устройство
        DeviceInfo existing_device = db.getDeviceByHashAndSubsystemAndParent(current_hash, subsystem, parent_id);
        if (existing_device.id == -1) {
            existing_device = db.getDeviceByDevpathSubsystemAndBootId(devpath, subsystem, boot_id);
        }

        if (existing_device.id == -1) {
            this->log("Устройство не найдено в БД", logLevel::WARN);
            return false;
        }

        // Сбрасываем boot_id (устанавливаем пустую строку)
        this->log("Сбрасываем boot_id для устройства ID: " + std::to_string(existing_device.id), logLevel::TRACE);
        std::function<bool(int)> resetSubtreeBootId = [&](int device_id) -> bool {
            bool ok = true;
            std::vector<DeviceInfo> children = db.getChildDevices(device_id);

            for (const DeviceInfo& child : children) {
                ok &= resetSubtreeBootId(child.id);
            }

            this->log("Reset boot_id for removed subtree device ID: " + std::to_string(device_id), logLevel::TRACE);
            return db.updateBootId(device_id, "") && ok;
        };

        auto hasCurrentBootChildren = [&](int device_id) -> bool {
            std::vector<DeviceInfo> children = db.getChildDevices(device_id);

            for (const DeviceInfo& child : children) {
                if (child.boot_id == boot_id) {
                    return true;
                }
            }

            return false;
        };

        if (!resetSubtreeBootId(existing_device.id)) {
            this->log("Failed to reset boot_id for removed device subtree: " + devpath, logLevel::ERROR);
            return false;
        }

        DeviceInfo current_parent = parent_device;
        while (current_parent.id != -1 && current_parent.subsystem == "__virtual__") {
            if (hasCurrentBootChildren(current_parent.id)) {
                break;
            }

            this->log("Reset boot_id for empty virtual parent ID: " + std::to_string(current_parent.id), logLevel::TRACE);
            if (!db.updateBootId(current_parent.id, "")) {
                return false;
            }

            current_parent = db.getDeviceById(current_parent.parent_id);
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Ошибка в safe_remove_device: " << e.what() << std::endl;
        return false;
    }
}
