#include "CPUInfoCollector.h"

#include <fic/core/VerifiedProcessExecutor.h>

#include <sstream>
#include <stdexcept>

//Передаем параметры на контроле в конструктор
CPUInfoCollector::CPUInfoCollector()
    :InfoCollector({"Architecture","CPU op-mode(s)","Vendor ID","Model name","CPU family","Model","CPU(s)"}){

}

bool CPUInfoCollector::process_device_concrete(){
    this->log("Собираем информацию о процессоре...", logLevel::DEBUG);
    //Папка со списком процессоров
    std::string cpu_list_dir = (this->data_directory() / "cpu_list").string();

    ProcessOptions options;
    options.environment.emplace_back("LC_ALL", "C");

    // Устанавливаем локаль C (английскую) для команды lscpu
    ProcessResult result = VerifiedProcessExecutor::execute("/usr/bin/lscpu", {}, options);
    if (!result.success()) {
        std::string error = result.error.empty() ? result.standardError : result.error;
        this->log("Verified lscpu execution failed; creating unknown CPU placeholder: " + error, logLevel::WARN);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Model name"] = "[Неизвестный процессор]";
        this->deviceParam["Vendor ID"] = "unknown";
        this->deviceParam["CPU(s)"] = "unknown";
        return process_device("cpu", cpu_list_dir);
    }

    std::istringstream output(result.standardOutput);
    std::string line;
    while (std::getline(output, line)) {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);

            // Удаляем лишние пробелы и символы перевода строк
            this->trim(key);
            this->trim(value);

            if(this->deviceParam.find(key) != this->deviceParam.end()){
                this->deviceParam[key] = value;
            }
        }
    }

    return process_device("cpu", cpu_list_dir);
}
