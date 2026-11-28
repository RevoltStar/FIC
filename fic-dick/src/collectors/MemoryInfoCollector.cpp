#include "MemoryInfoCollector.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <sstream>

MemoryInfoCollector::MemoryInfoCollector()
    :InfoCollector({"Manufacturer", "Part Number", "Serial Number", "Size", "Speed", "Type", "Locator"}){

}

std::vector<MemoryModuleRecord> MemoryInfoCollector::parse_dmidecode_modules(
    const std::string& output) const {
    std::vector<MemoryModuleRecord> modules;
    std::map<std::string, std::string> currentModule;
    bool inMemorySection = false;

    auto finishSection = [&]() {
        if (!inMemorySection) {
            return;
        }
        inMemorySection = false;
        if (currentModule.empty()) {
            return;
        }

        MemoryModuleRecord record;
        for (const std::string& key : this->controlList) {
            record.values[key] = "";
        }
        // Только контролируемые атрибуты попадают в запись устройства.
        for (auto& [key, value] : currentModule) {
            this->trim(value);
            const auto target = record.values.find(key);
            if (target != record.values.end()) {
                target->second = value;
            }
        }

        const auto sizeIt = currentModule.find("Size");
        const auto formFactorIt = currentModule.find("Form Factor");
        std::string size = sizeIt != currentModule.end() ? sizeIt->second : "";
        std::string formFactor =
            formFactorIt != currentModule.end() ? formFactorIt->second : "";
        this->trim(size);
        this->trim(formFactor);

        // Пустой слот: размер нулевой либо модуль не установлен.
        const bool emptySlot =
            size == "0" || size.rfind("0 ", 0) == 0 ||
            size.find("No Module Installed") != std::string::npos;
        const bool physicalFormFactor = formFactor == "DIMM" ||
            formFactor == "SO-DIMM" || formFactor == "SODIMM";

        if (!physicalFormFactor) {
            // Форм-фактор вне модели идентификации: запись не создаётся и
            // достоверность инвентаризации не затрагивается.
            record.kind = MemoryModuleKind::NotPhysical;
        } else if (emptySlot) {
            record.kind = MemoryModuleKind::NotPhysical;
        } else if (size.empty() || size == "Unknown") {
            // Модуль установлен, но размер не сообщён: идентифицировать его
            // нельзя, значит инвентаризация неполна.
            record.kind = MemoryModuleKind::Incomplete;
            record.diagnostic = "memory module section has no usable size";
        } else if (record.values["Locator"].empty()) {
            record.kind = MemoryModuleKind::Incomplete;
            record.diagnostic = "memory module section has no slot locator";
        } else {
            record.kind = MemoryModuleKind::Physical;
        }

        modules.push_back(std::move(record));
        currentModule.clear();
    };

    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        // Проверяем начало секции Memory Device
        if (line.find("Memory Device") != std::string::npos) {
            finishSection();
            inMemorySection = true;
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
                finishSection();
                continue;
            }

            const size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);

                this->trim(key);
                this->trim(value);
                currentModule[key] = value;
            }
        }
    }

    // Обрабатываем последний модуль (после окончания чтения)
    finishSection();
    return modules;
}

bool MemoryInfoCollector::process_device_concrete(){
    std::cout << "Собираем информацию об оперативной памяти..." << std::endl;
    std::string memory_list_dir = (this->data_directory() / "memory_list").string();

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

        // /proc/meminfo only reports the total amount: it cannot prove the
        // identity of any individual module, so the subsystem stays unproven
        // while the fallback record keeps the inventory visible.
        this->inventoryProven_ = false;
        this->log("dmidecode did not provide usable memory modules; using /proc/meminfo fallback", logLevel::ERROR);
        return this->process_device("memory", memory_list_dir);
    };

    // Выполняем команду dmidecode -t 17 (информация о памяти)
    ProcessResult result = VerifiedProcessExecutor::execute("/usr/sbin/dmidecode", {"-t", "17"});
    if (!result.success()) {
        std::string error = result.error.empty() ? result.standardError : result.error;
        // Placeholder only: no module identity could be established.
        this->inventoryProven_ = false;
        this->log("Verified dmidecode execution failed; creating unknown memory placeholder: " + error, logLevel::ERROR);
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

    // A successful command is NOT proof of a complete module inventory.
    const std::vector<MemoryModuleRecord> modules =
        parse_dmidecode_modules(result.standardOutput);
    std::size_t storedModules = 0;
    std::size_t failedModules = 0;
    std::size_t incompleteModules = 0;
    for (const MemoryModuleRecord& module : modules) {
        if (module.kind == MemoryModuleKind::Incomplete) {
            ++incompleteModules;
            this->log("Memory module inventory is incomplete: " +
                          module.diagnostic,
                      logLevel::ERROR);
            continue;
        }
        if (module.kind != MemoryModuleKind::Physical) {
            continue;
        }
        this->deviceParam = module.values;
        if (this->process_device("memory", memory_list_dir)) {
            ++storedModules;
        } else {
            ++failedModules;
        }
    }

    if (storedModules == 0) {
        // No identifiable module was reported at all: keep the inventory
        // visible through the existing fallback, which stays unproven.
        return collectFromProcMeminfo();
    }

    if (failedModules > 0 || incompleteModules > 0) {
        // A module that could not be stored or identified makes the whole
        // module inventory unproven: a partial set must never be read as the
        // complete memory configuration. A storage failure is also a failure of
        // the collection itself.
        this->inventoryProven_ = false;
        this->log("Memory module inventory is incomplete: " +
                      std::to_string(failedModules) +
                      " module(s) failed and " +
                      std::to_string(incompleteModules) +
                      " module(s) could not be identified",
                  logLevel::ERROR);
        return failedModules == 0;
    }

    return true;
}
