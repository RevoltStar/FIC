#include "MemoryInfoCollector.h"

#include <fic/core/VerifiedProcessExecutor.h>

#include <sstream>
#include <unordered_map>

MemoryInfoCollector::MemoryInfoCollector()
    :InfoCollector({"Manufacturer", "Part Number", "Serial Number", "Size", "Speed", "Type", "Locator"}){

}

bool MemoryInfoCollector::process_device_concrete(){
    std::cout << "Собираем информацию об оперативной памяти..." << std::endl;
    std::string memory_list_dir = this->dbPath + "/memory_list";

    auto collectFromProcMeminfo = [&]() -> bool {
        std::ifstream meminfo("/proc/meminfo");
        if (!meminfo.is_open()) {
            this->log("Failed to open /proc/meminfo", logLevel::ERROR);
            return false;
        }

        std::string memTotal;
        std::string line;
        while (std::getline(meminfo, line)) {
            size_t colonPos = line.find(':');
            if (colonPos == std::string::npos) {
                continue;
            }

            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            this->trim(key);
            this->trim(value);

            if (key == "MemTotal") {
                memTotal = value;
                break;
            }
        }

        if (memTotal.empty()) {
            this->log("MemTotal not found in /proc/meminfo", logLevel::ERROR);
            return false;
        }

        for (auto& [key, value] : this->deviceParam) {
            value = "not found";
        }

        this->deviceParam["Manufacturer"] = "Linux kernel";
        this->deviceParam["Part Number"] = "system-memory";
        this->deviceParam["Serial Number"] = "system-memory";
        this->deviceParam["Size"] = memTotal;
        this->deviceParam["Speed"] = "not found";
        this->deviceParam["Type"] = "System RAM";
        this->deviceParam["Locator"] = "system";

        this->log("dmidecode did not provide usable memory modules; using /proc/meminfo fallback", logLevel::WARN);
        return this->process_device("memory", memory_list_dir);
    };

    // Выполняем команду dmidecode -t 17 (информация о памяти)
    ProcessResult result = VerifiedProcessExecutor::execute("/usr/sbin/dmidecode", {"-t", "17"});
    if (!result.success()) {
        std::string error = result.error.empty() ? result.standardError : result.error;
        this->log("Verified dmidecode execution failed; creating unknown memory placeholder: " + error, logLevel::WARN);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Manufacturer"] = "unknown";
        this->deviceParam["Part Number"] = "[Неизвестная оперативная память]";
        this->deviceParam["Serial Number"] = "unknown";
        this->deviceParam["Size"] = "unknown";
        this->deviceParam["Speed"] = "unknown";
        this->deviceParam["Type"] = "unknown";
        this->deviceParam["Locator"] = "unknown";
        return process_device("memory", memory_list_dir);
    }

    bool inMemorySection = false;
    std::unordered_map<std::string, std::string> currentModule;
    int moduleCount = 0;

    // Функция для обработки собранных данных одного модуля памяти
    auto processCurrentModule = [&]() {
        if (!inMemorySection || currentModule.empty()) {
            return;
        }

        // Проверяем, является ли модуль физическим
        auto sizeIt = currentModule.find("Size");
        auto formFactorIt = currentModule.find("Form Factor");

        if (sizeIt != currentModule.end() && formFactorIt != currentModule.end()) {
            std::string size = sizeIt->second;
            std::string formFactor = formFactorIt->second;

            // Используем trim() для очистки
            this->trim(size);
            this->trim(formFactor);

            // Пропускаем виртуальные модули
            if (size != "0" &&
                size.find("No Module Installed") == std::string::npos &&
                (formFactor == "DIMM" || formFactor == "SO-DIMM" || formFactor == "SODIMM")) {

                // Инициализируем deviceParam значениями по умолчанию "not found"
                for (auto& [key, value] : this->deviceParam) {
                    value = "not found";
                }

                // Заполняем параметры текущей плашки ОЗУ
                for (auto& [key, value] : currentModule) {
                    // Используем trim() для очистки значения
                    this->trim(value);

                    // Если параметр есть в controlList, сохраняем его
                    if (this->deviceParam.find(key) != this->deviceParam.end()) {
                        this->deviceParam[key] = value;
                    }
                }

                // Обрабатываем устройство
                if (this->process_device("memory", memory_list_dir)) {
                    moduleCount++;
                    //std::cout << "Модуль успешно добавлен в БД" << std::endl;
                } else {
                    //std::cerr << "Ошибка добавления модуля в БД" << std::endl;
                }
            } else {
                //std::cout << "Пропущен модуль (Size: " << size << ", Form Factor: " << formFactor << ")" << std::endl;
            }
        }

        // Очищаем для следующего модуля
        currentModule.clear();
        inMemorySection = false;
    };

    std::istringstream output(result.standardOutput);
    std::string line;
    while (std::getline(output, line)) {
        // Проверяем начало секции Memory Device
        if (line.find("Memory Device") != std::string::npos) {
            // Обрабатываем предыдущий модуль (если есть)
            processCurrentModule();

            // Начинаем новый модуль
            inMemorySection = true;
            //std::cout << "Найдена новая секция Memory Device" << std::endl;
            continue;
        }

        // Если внутри секции памяти, обрабатываем строку
        if (inMemorySection) {
            // Проверяем конец секции (пустая строка или табуляция)
            if (line.find_first_not_of(" \t\r\n") == std::string::npos) {
                // Пустая строка - продолжаем собирать данные
                continue;
            }

            // Проверяем, не началась ли следующая секция
            if (line.find("Handle ") == 0) {
                processCurrentModule();
                continue;
            }

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);

                // Используем trim() для очистки
                this->trim(key);
                this->trim(value);

                // Сохраняем в текущий модуль
                currentModule[key] = value;
            }
        }
    }

    // Обрабатываем последний модуль (после окончания чтения)
    processCurrentModule();

    //std::cout << "Обработка завершена. Всего обработано модулей памяти: " << moduleCount << std::endl;

    if (moduleCount > 0) {
        return true;
    }

    return collectFromProcMeminfo();
}
