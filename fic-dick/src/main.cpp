// file name: main.cpp
#include <iostream>
#include <exception>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <fic/core/FicRuntimePaths.h>
#include <fic/core/UpgradeManager.h>
#include <fic/device-db/DB.h>
#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>
#include "core/DeviceControlDaemon.h"
#include "core/DevicePaths.h"
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
    } else if (subsystem == "usbmisc") {
        return std::make_unique<UDEVInfoCollector>(
            std::vector<std::string>{"DEVNAME", "DEVPATH", "MAJOR", "MINOR"}
        );
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
        const std::string mode(argv[1]);
        if (mode == "--version") {
            std::cout << "fic-dick " << fic::version::PRODUCT_VERSION
                      << " ipc-api=" << fic::version::IPC_API_VERSION
                      << " db-schema=" << fic::version::DEVICE_DB_SCHEMA_VERSION
                      << std::endl;
            return 0;
        }
        if (mode == "--build-info") {
            fic::version::writeBuildInfo(std::cout, "fic-dick");
            return 0;
        }
    }

    std::string pathError;
    if (!fic::core::FicRuntimePaths::initializeProduction(pathError)) {
        std::cerr << "failed to initialize FIC runtime paths: " << pathError << std::endl;
        return 1;
    }
    if (!fic::device_control::DeviceRuntimePaths::initialize(
            fic::device_control::DevicePaths::fromProductPaths(
                fic::core::FicRuntimePaths::get()),
            pathError)) {
        std::cerr << "failed to initialize device paths: " << pathError << std::endl;
        return 1;
    }

    if (argc > 1) {
        std::string mode(argv[1]);

        if (mode == "--maintenance") {
            if (argc < 3) {
                std::cerr << "maintenance command is required" << std::endl;
                return 1;
            }
            const std::string command(argv[2]);
            try {
                DB db(fic::device_control::DeviceRuntimePaths::get().databaseOptions());
                std::string error;
                if (command == "check-db") {
                    if (!db.verifyDatabaseSchema(error)) {
                        std::cerr << "device database check failed: " << error << std::endl;
                        return 1;
                    }
                    std::cout << "device database schema is current: "
                              << fic::version::DEVICE_DB_SCHEMA_VERSION << std::endl;
                    return 0;
                }
                if (command == "migrate-db") {
                    DBMigrationResult result;
                    const std::filesystem::path backupDirectory =
                        fic::device_control::DeviceRuntimePaths::get().stateDir /
                        "db-backups";
                    const auto backupReady = [&](
                        const std::filesystem::path& backup,
                        std::string& callbackError) {
                        return fic::core::UpgradeManager::recordDatabaseBackupIfActive(
                            fic::device_control::DeviceRuntimePaths::get().stateDir,
                            backup,
                            callbackError);
                    };
                    if (!db.migrateDatabase(
                            backupDirectory, result, error, backupReady)) {
                        std::cerr << "device database migration failed: " << error << std::endl;
                        return 1;
                    }
                    if (!fic::core::UpgradeManager::markDatabaseMigratedIfActive(
                            fic::device_control::DeviceRuntimePaths::get().stateDir,
                            result.backupFile,
                            error)) {
                        std::cerr << "could not advance upgrade journal: "
                                  << error << std::endl;
                        return 1;
                    }
                    std::cout << "device database schema " << result.fromVersion
                              << " -> " << result.toVersion;
                    if (!result.backupFile.empty()) {
                        std::cout << ", backup=" << result.backupFile.string();
                    } else if (result.migrated) {
                        std::cout << ", initialized new database";
                    } else {
                        std::cout << ", already current";
                    }
                    std::cout << std::endl;
                    return 0;
                }
                std::cerr << "unknown maintenance command: " << command << std::endl;
                return 1;
            } catch (const std::exception& exception) {
                std::cerr << "device database maintenance failed: "
                          << exception.what() << std::endl;
                return 1;
            }
        }

        std::string upgradeError;
        if (!fic::core::UpgradeManager::requireNoIncompleteUpgrade(
                fic::device_control::DeviceRuntimePaths::get().stateDir,
                upgradeError)) {
            std::cerr << "refusing to start during incomplete product upgrade: "
                      << upgradeError << std::endl;
            return 1;
        }
        if (!fic::core::UpgradeManager::verifyConfigs(
                fic::core::FicRuntimePaths::get().configDir,
                upgradeError)) {
            std::cerr << "refusing to start with incompatible configuration: "
                      << upgradeError << std::endl;
            return 1;
        }

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
            return fic::device_control::
                forward_udev_event_to_daemon(
                env_to_map(envp));
            
        }
        else if (mode == "reconcile") {
            return fic::device_control::
            request_reconciliation();
        }
        else if (mode == "check-permanent") {
            return fic::device_control::
                request_permanent_check();
        }
        else if (mode == "wait-daemon") {
            int timeoutSeconds = 10;

            if (argc > 2) {
                try {
                    timeoutSeconds =
                        std::stoi(argv[2]);
                } catch (const std::exception&) {
                    std::cerr
                        << "Invalid wait-daemon timeout: "
                        << argv[2]
                        << std::endl;

                    return 1;
                }
            }

            return fic::device_control::
                wait_for_daemon(timeoutSeconds);
        }
        // Собираем информацию о ЦПУ, м/плате, ОЗУ
        else if (mode == "cpu_board_memory") {
            DB db(fic::device_control::DeviceRuntimePaths::get().databaseOptions());
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
