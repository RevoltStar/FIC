#include "BoardInfoCollector.h"

BoardInfoCollector::BoardInfoCollector()
    :InfoCollector({"Manufacturer", "Product Name", "Serial Number", "Version"}){

}


bool BoardInfoCollector::process_device_concrete(){
    std::cout << "Собираем информацию о материнской плате" << std::endl;
    std::vector<std::string> board_values(this->controlList.size(), "not found");
    std::string board_list_dir = this->dbPath + "/board_list";
            // Выполняем команду dmidecode -t 2 (информация о системной плате)
            const char* command = "dmidecode -t 2";
            std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command, "r"), pclose);
            if (!pipe) {
                throw std::runtime_error("Failed to execute dmidecode command");
            }

            char buffer[256];
            bool inBaseBoardSection = false;
            /*std::unordered_map<std::string, std::string> boardData;*/

            while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
                std::string line(buffer);

                // Проверяем начало секции Base Board Information
                if (line.find("Base Board Information") != std::string::npos) {
                    inBaseBoardSection = true;
                    continue;
                }

                if (inBaseBoardSection) {
                    // Проверяем конец секции
                    if (line.find("\n") == 0 || line.find("\r\n") == 0) {
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

                        /*boardData[key] = value;*/
                    }
                }
            }

            /*
            // Заполняем результаты в порядке BOARD_CONTROL
            for (size_t i = 0; i < BOARD_CONTROL.size(); ++i) {
                const auto& param = BOARD_CONTROL[i];
                auto it = boardData.find(param);
                if (it != boardData.end()) {
                    board_values[i] = it->second;
                }
            }
            */

    return process_device("board", board_list_dir);
}
