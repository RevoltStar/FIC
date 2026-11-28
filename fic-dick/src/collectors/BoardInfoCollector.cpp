#include "BoardInfoCollector.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <sstream>
#include <stdexcept>

BoardInfoCollector::BoardInfoCollector()
    :InfoCollector({"Manufacturer", "Product Name", "Serial Number", "Version"}){

}


StaticInventoryParse BoardInfoCollector::parse_dmidecode_output(
    const std::string& output) const {
    StaticInventoryParse parsed;
    for (const std::string& key : this->controlList) {
        parsed.values[key] = "";
    }

    bool inBaseBoardSection = false;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        // Проверяем начало секции Base Board Information
        if (line.find("Base Board Information") != std::string::npos) {
            inBaseBoardSection = true;
            continue;
        }

        if (inBaseBoardSection) {
            // Проверяем конец секции
            if (line.empty()) {
                break;
            }

            const size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);

                this->trim(key);
                this->trim(value);

                const auto target = parsed.values.find(key);
                if (target != parsed.values.end()) {
                    target->second = value;
                }
            }
        }
    }

    // Identity: the board is identified by its manufacturer and product name.
    // Both are mandatory DMI type 2 attributes; serial number and version are
    // frequently "Not Specified" or "To be filled by O.E.M." and are therefore
    // never required for a proven inventory.
    const std::string manufacturer = parsed.values.count("Manufacturer")
        ? parsed.values["Manufacturer"]
        : "";
    const std::string productName = parsed.values.count("Product Name")
        ? parsed.values["Product Name"]
        : "";
    if (!inBaseBoardSection) {
        parsed.diagnostic = "dmidecode output has no Base Board Information section";
    } else if (manufacturer.empty()) {
        parsed.diagnostic = "dmidecode base board section has no manufacturer";
    } else if (productName.empty()) {
        parsed.diagnostic = "dmidecode base board section has no product name";
    } else {
        parsed.usable = true;
    }
    return parsed;
}

bool BoardInfoCollector::process_device_concrete(){
    std::cout << "Собираем информацию о материнской плате" << std::endl;
    std::string board_list_dir = (this->data_directory() / "board_list").string();

    // Выполняем команду dmidecode -t 2 (информация о системной плате)
    ProcessResult result = VerifiedProcessExecutor::execute("/usr/sbin/dmidecode", {"-t", "2"});
    if (!result.success()) {
        std::string error = result.error.empty() ? result.standardError : result.error;
        // Placeholder only: without DMI data no concrete board identity exists,
        // so the subsystem stays unproven.
        this->inventoryProven_ = false;
        this->log("Verified dmidecode execution failed; creating unknown board placeholder: " + error, logLevel::ERROR);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Manufacturer"] = "unknown";
        this->deviceParam["Product Name"] = "[Неизвестная материнская плата]";
        this->deviceParam["Serial Number"] = "unknown";
        this->deviceParam["Version"] = "unknown";
        return process_device("board", board_list_dir);
    }

    // A successful command is NOT proof that the base board was reported.
    const StaticInventoryParse parsed = parse_dmidecode_output(result.standardOutput);
    if (!parsed.usable) {
        this->inventoryProven_ = false;
        this->log("dmidecode output is unusable; creating unknown board placeholder: " +
                      parsed.diagnostic,
                  logLevel::ERROR);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Manufacturer"] = "unknown";
        this->deviceParam["Product Name"] = "[Неизвестная материнская плата]";
        this->deviceParam["Serial Number"] = "unknown";
        this->deviceParam["Version"] = "unknown";
        return process_device("board", board_list_dir);
    }

    this->deviceParam = parsed.values;
    return process_device("board", board_list_dir);
}
