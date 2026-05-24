// file name: main.cpp
#include <iostream>
#include "utils/DB.h"
#include "modules/UDEVInfoCollector.h"
#include "modules/USBInfoCollector.h"
#include "modules/PCIInfoCollector.h"
#include "modules/BlockInfoCollector.h"
#include "modules/BoardInfoCollector.h"
#include "modules/CPUInfoCollector.h"
#include "modules/MemoryInfoCollector.h"
#include "modules/NetInfoCollector.h"

using namespace std;

// Фабрика для создания коллектора в зависимости от подсистемы
UDEVInfoCollector* create_collector_for_subsystem(const std::string& subsystem) {
    if (subsystem == "usb") {
        return new USBInfoCollector();
    } else if (subsystem == "block") {
        return new BlockInfoCollector();
    } else if(subsystem == "pci"){
        return new PCIInfoCollector();
    }/*else if(subsystem=="net"){
        return new NetInfoCollector();
    }*/
    // Для других подсистем создаем базовый коллектор со стабильными udev-полями
    return new UDEVInfoCollector({"DEVPATH", "SUBSYSTEM", "DEVTYPE", "MODALIAS"});
}

bool log(std::string message, logLevel logLev){
    if(message.empty()){
       return true;
    }
    return Logger::log(message, logLev, "devices");
}

int main(int argc, char* argv[], char* envp[]) {
    if (argc > 1) {
        // Инициализируем БД (бесконечно ждем инициализации)
        {
            DB db = DB("/opt/fic/db/devices.db");
            if (!db.initializeDatabase()) {
                log("Ошибка инициализации базы данных", logLevel::FATAL);
                return 1;
            }
        }

        std::string mode(argv[1]);

        // Собираем устройства через UDEV
        if (mode == "udev") {
            const char* action = std::getenv("ACTION");
            const char* devpath = std::getenv("DEVPATH");
            const char* subsystem = std::getenv("SUBSYSTEM");
            std::ofstream debug("/opt/fic/log/fic-debug.log", std::ios::app);
            debug << "PID: " << getpid()
                  << " | ACTION: " << (action ? action : "NULL")
                  << " | DEVPATH: " << (devpath ? devpath : "NULL")
                  << " | SUBSYSTEM: " << (subsystem ? subsystem : "NULL")
                  << std::endl;
            log("Обрабатываем устройство: " + std::string(devpath), logLevel::DEBUG);
            if (action == nullptr ||devpath == nullptr || subsystem == nullptr) {
                log("Недостаточно переменных окружения UDEV. Прерываем обработку данного устройства", logLevel::DEBUG);
                return 1;
            }
            // Создаем базовый коллектор для проверок
            UDEVInfoCollector base_collector;

            std::string action_str = "";
            if(action == nullptr){
                action_str = "";
            }else{
                action_str = std::string(action);
            }
            if (action_str == "add" || action_str == "change") {
                // Проверяем devpath
                if (!base_collector.check_devpath(devpath)) {
                    return 1;
                }

                // Проверяем подсистему
                if (!base_collector.check_excluded_subsystem(subsystem)) {
                    return 1;
                }

                // Создаем соответствующий коллектор
                std::unique_ptr<UDEVInfoCollector> collector(create_collector_for_subsystem(subsystem));

                // Пытаемся создать/обновить устройство
                log("Пытаемся добавить/обновить udev-устройство", logLevel::DEBUG);
                if (!collector->create_device_config(devpath, subsystem)) {
                    log("Ошибка добавления/удаления устройства: " + std::string(devpath), logLevel::DEBUG);
                    return 1;
                }

                return 0;

            } else if (action_str == "remove") {
                log("Извлечено устройство: " + std::string(devpath), logLevel::INFO);
                // Проверяем devpath
                if (!base_collector.check_devpath(devpath)) {
                    return 1;
                }

                // Проверяем подсистему
                if (!base_collector.check_excluded_subsystem(subsystem)) {
                    return 1;
                }

                // Создаем соответствующий коллектор
                std::unique_ptr<UDEVInfoCollector> collector(create_collector_for_subsystem(subsystem));

                // Пытаемся удалить устройство
                if (!collector->safe_remove_device(devpath, subsystem)) {
                    log("Ошибка удаления устройства из БД: " + std::string(devpath), logLevel::DEBUG);
                    return 1;
                }

                return 0;
            } else {
                log("Неизвестное действие: ", logLevel::DEBUG);
                return 1;
            }
        }
        // Собираем информацию о ЦПУ, м/плате, ОЗУ
        else if (mode == "cpu_board_memory") {
            CPUInfoCollector cic;
            BoardInfoCollector bic;
            MemoryInfoCollector mic;

            if (!cic.process_device_concrete() || !bic.process_device_concrete() || !mic.process_device_concrete()) {
                log("Ошибка сбора информации о ЦПУ, ОЗУ и материнской плате", logLevel::FATAL);
                return 1;
            }
            return 0;
        }
        else {
            std::cerr << "Unknown mode: " << mode << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Неверный синтаксис. Используйте: " << argv[0] << " [udev|cpu_board_memory]" << std::endl;
        return 1;
    }

    return 0;
}
