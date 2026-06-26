#include "BoardInfoCollector.h"

#include <fic/core/VerifiedProcessExecutor.h>

#include <sstream>
#include <stdexcept>

BoardInfoCollector::BoardInfoCollector()
    :InfoCollector({"Manufacturer", "Product Name", "Serial Number", "Version"}){

}


bool BoardInfoCollector::process_device_concrete(){
    std::cout << "Собираем информацию о материнской плате" << std::endl;
    std::string board_list_dir = this->dbPath + "/board_list";

    // Выполняем команду dmidecode -t 2 (информация о системной плате)
    ProcessResult result = VerifiedProcessExecutor::execute("/usr/sbin/dmidecode", {"-t", "2"});
    if (!result.success()) {
        std::string error = result.error.empty() ? result.standardError : result.error;
        this->log("Verified dmidecode execution failed; creating unknown board placeholder: " + error, logLevel::WARN);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Manufacturer"] = "unknown";
        this->deviceParam["Product Name"] = "[Неизвестная материнская плата]";
        this->deviceParam["Serial Number"] = "unknown";
        this->deviceParam["Version"] = "unknown";
        return process_device("board", board_list_dir);
    }

    bool inBaseBoardSection = false;
    std::istringstream output(result.standardOutput);
    std::string line;
    while (std::getline(output, line)) {
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

            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);

                this->trim(key);
                this->trim(value);

                if(this->deviceParam.find(key) != this->deviceParam.end()){
                    this->deviceParam[key] = value;
                }
            }
        }
    }

    return process_device("board", board_list_dir);
}
