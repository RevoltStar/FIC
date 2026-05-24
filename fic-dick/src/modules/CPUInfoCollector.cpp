#include "CPUInfoCollector.h"

//Передаем параметры на контроле в конструктор
CPUInfoCollector::CPUInfoCollector()
    :InfoCollector({"Architecture","CPU op-mode(s)","Vendor ID","Model name","CPU family","Model","CPU(s)"}){

}

bool CPUInfoCollector::process_device_concrete(){
    this->log("Собираем информацию о процессоре...", logLevel::DEBUG);
    //Папка со списком процессоров
    std::string cpu_list_dir = this->dbPath + "/cpu_list";

    std::vector<std::string> cpu_values(this->controlList.size(), "not found");

        // Устанавливаем локаль C (английскую) для команды lscpu
        const char* command = "LC_ALL=C lscpu";
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command, "r"), pclose);
        if (!pipe) {
            throw std::runtime_error("Failed to execute lscpu command");
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
            std::string line(buffer);
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
