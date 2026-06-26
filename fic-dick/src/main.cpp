// file name: main.cpp
#include <iostream>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <fic/device-db/DB.h>
#include "core/DeviceControlDaemon.h"
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
std::unique_ptr<UDEVInfoCollector> create_collector_for_subsystem(const std::string& subsystem) {
    if (subsystem == "usb") {
        return std::make_unique<USBInfoCollector>();
    } else if (subsystem == "block") {
        return std::make_unique<BlockInfoCollector>();
    } else if(subsystem == "pci"){
        return std::make_unique<PCIInfoCollector>();
    }/*else if(subsystem=="net"){
        return std::make_unique<NetInfoCollector>();
    }*/
    // Для других подсистем создаем базовый коллектор со стабильными udev-полями
    return std::make_unique<UDEVInfoCollector>(
        std::vector<std::string>{"DEVPATH", "SUBSYSTEM", "DEVTYPE", "MODALIAS"}
    );
}

bool log(std::string message, logLevel logLev){
    if(message.empty()){
       return true;
    }
    return Logger::log(message, logLev, "devices");
}

std::map<std::string, std::string> env_to_map(char* envp[]) {
    std::map<std::string, std::string> result;
    if (envp == nullptr) {
        return result;
    }

    for (char** env = envp; *env != nullptr; ++env) {
        std::string entry(*env);
        std::size_t separator = entry.find('=');
        if (separator == std::string::npos || separator == 0) {
            continue;
        }
        result[entry.substr(0, separator)] = entry.substr(separator + 1);
    }
    return result;
}

int main(int argc, char* argv[], char* envp[]) {
    if (argc > 1) {
        std::string mode(argv[1]);

        if (mode == "--daemon" || mode == "daemon") {
            std::string socketPath;
            for (int i = 2; i + 1 < argc; ++i) {
                if (std::string(argv[i]) == "--socket") {
                    socketPath = argv[i + 1];
                }
            }
            return fic::device_control::run_daemon(socketPath);
        }

        // Собираем устройства через UDEV
        if (mode == "udev") {
            return fic::device_control::forward_udev_event_to_daemon(env_to_map(envp));
        }
        else if (mode == "check-permanent") {
            return fic::device_control::request_permanent_check();
        }
        else if (mode == "wait-daemon") {
            int timeoutSeconds = 10;
            if (argc > 2) {
                try {
                    timeoutSeconds = std::stoi(argv[2]);
                } catch (const std::exception&) {
                    std::cerr << "Invalid wait-daemon timeout: " << argv[2] << std::endl;
                    return 1;
                }
            }
            return fic::device_control::wait_for_daemon(timeoutSeconds);
        }
        // Собираем информацию о ЦПУ, м/плате, ОЗУ
        else if (mode == "cpu_board_memory") {
            DB db = DB("/opt/fic/db/devices.db");
            if (!db.initializeDatabase()) {
                log("Ошибка инициализации базы данных", logLevel::FATAL);
                return 1;
            }

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
        std::cerr << "Неверный синтаксис. Используйте: " << argv[0] << " [--daemon|udev|check-permanent|wait-daemon|cpu_board_memory]" << std::endl;
        return 1;
    }

    return 0;
}
