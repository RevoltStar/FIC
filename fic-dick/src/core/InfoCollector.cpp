#include "InfoCollector.h"


bool InfoCollector::log(std::string message, logLevel logLev){
    if(message.empty()){
       return true;
    }
    return Logger::log(message, logLev, "devices");
}


void InfoCollector::trim(std::string& val){
    //val.erase(0, val.find_first_not_of(" \t"));
    //val.erase(val.find_last_not_of(" \t") + 1);

    // Удаляем начальные пробелы, табы и управляющие символы
    val.erase(0, val.find_first_not_of(" \t\n\r\f\v"));

    // Удаляем конечные пробелы, табы и управляющие символы
    val.erase(val.find_last_not_of(" \t\n\r\f\v") + 1);
}

InfoCollector::InfoCollector(std::vector<std::string> _controlList){
    this->controlList = _controlList;
    //Инициализируем массив пустым значением
    for(auto elem : _controlList){
        this->deviceParam[elem] = "";
    }
}

std::string InfoCollector::create_hash() {
    std::string hash_string;
    for (const auto& [key, value] : this->deviceParam) {
        hash_string += value + "|";
    }

    if (!hash_string.empty() && hash_string.back() == '|') {
        hash_string.pop_back();
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(hash_string.c_str()),
           hash_string.size(),
           hash);

    // Преобразуем в hex напрямую (быстрее чем stringstream)
    const char* hex_chars = "0123456789abcdef";
    std::string hex_hash;
    hex_hash.reserve(SHA256_DIGEST_LENGTH * 2);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        unsigned char c = hash[i];
        hex_hash.push_back(hex_chars[c >> 4]);    // Старшие 4 бита
        hex_hash.push_back(hex_chars[c & 0x0F]);  // Младшие 4 бита
    }

    return hex_hash;
}

std::string InfoCollector::get_boot_id() {
    std::ifstream boot_id_file("/proc/sys/kernel/random/boot_id");
    std::string boot_id;
    std::getline(boot_id_file, boot_id);
    boot_id_file.close();

    while (!boot_id.empty() &&
           (boot_id.back() == '\n' || boot_id.back() == '\r')) {
        boot_id.pop_back();
    }

    return boot_id;
}


/*Обрабатываем устройство*/
bool InfoCollector::process_device(
        const std::string &device_type,
        const std::filesystem::__cxx11::path &list_dir){

    this->log("Обрабатываем устройство типа " + device_type, logLevel::DEBUG);
    //Вычисляем хэш для текущего устройства
    std::string current_hash = create_hash();
    std::string boot_id = this->get_boot_id();

    if(device_type == "cpu" || device_type == "board" || device_type=="memory"){
        //devpath родителя
        std::string devpath_parent = "/" + device_type + "_list";
        //devpath текущего устройства
        std::string devpath = devpath_parent + "/" + current_hash;

        this->log("Ждём блокировку БД", logLevel::TRACE);
        DB db = DB("/opt/fic/db/devices.db");
        this->log("Получили блокировку БД", logLevel::TRACE);
        //Существующее устройство
        DeviceInfo existing_device = db.getDeviceByHashAndSubsystem(current_hash,device_type);
        if(existing_device.id != -1){
            this->log("Устройство уже существует. Обновляем boot_id", logLevel::DEBUG);
            //Это устройство уже есть => Обновляем boot_id.
            if(!db.updateBootId(existing_device.id, boot_id)){
                this->log("Ошибка при обновлении boot_id для", logLevel::FATAL);
            }
        }else{
            DeviceInfo parent_device = db.getDeviceByPath(devpath_parent);
            //Генерируем экземпляр класса для вставки
            DeviceInfo di{
                0,
                current_hash,
                devpath,
                device_type,
                device_type,
                parent_device.id,
                parent_device.control_level,
                false, //Унаследовано от контейнера, администратор явно не назначал
                1, //Для статических устройств значение ignore_hierarchy неважно
                this->get_boot_id(), //Подвязываем устройство к текущему boot_id
                "0", //Заглушка для даты добавления
                "0", //Заглушка для даты добавления
                device_type + "_concrete"
            };
            //Сгенерированный device_id
            if (!db.beginTransaction()) {
                this->log("Ошибка начала транзакции для " + device_type, logLevel::FATAL);
                return false;
            }
            int device_id = db.addDevice(di);
            if(device_id != -1){
                for(auto it = this->deviceParam.begin(); it != this->deviceParam.end(); ++it) {
                      if (!db.addDeviceAttribute(device_id, it->first,  it->second)) {
                          db.rollbackTransaction();
                          this->log("Ошибка записи атрибута для " + device_type, logLevel::FATAL);
                          return false;
                      }
                  }
                if (!db.commitTransaction()) {
                    this->log("Ошибка фиксации транзакции для " + device_type, logLevel::FATAL);
                    return false;
                }
            } else {
                db.rollbackTransaction();
                this->log("Ошибка создания устройства для " + device_type, logLevel::FATAL);
                return false;
            }
        }
    }else{
        //Ничего другого быть не должно
    }

    return true;
}
