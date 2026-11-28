#include "CPUInfoCollector.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <sstream>
#include <stdexcept>

//Передаем параметры на контроле в конструктор
CPUInfoCollector::CPUInfoCollector()
    :InfoCollector({"Architecture","CPU op-mode(s)","Vendor ID","Model name","CPU family","Model","CPU(s)"}){

}

StaticInventoryParse CPUInfoCollector::parse_lscpu_output(
    const std::string& output) const {
    StaticInventoryParse parsed;
    for (const std::string& key : this->controlList) {
        parsed.values[key] = "";
    }

    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        const size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, colonPos);
        std::string value = line.substr(colonPos + 1);

        // Удаляем лишние пробелы и символы перевода строки
        this->trim(key);
        this->trim(value);

        const auto target = parsed.values.find(key);
        if (target != parsed.values.end()) {
            target->second = value;
        }
    }

    // Identity: `Model name` names the concrete CPU model; completeness: the
    // `CPU(s)` count is part of the identity hash and proves that the socket /
    // core layout was reported at all. Both lines are emitted by lscpu on every
    // supported distribution, so a missing one means the output cannot be
    // trusted, not that the value is optional.
    const std::string model =
        parsed.values.count("Model name") ? parsed.values["Model name"] : "";
    const std::string cpuCount =
        parsed.values.count("CPU(s)") ? parsed.values["CPU(s)"] : "";
    if (output.empty()) {
        parsed.diagnostic = "lscpu produced no output";
    } else if (model.empty()) {
        parsed.diagnostic = "lscpu output has no CPU model";
    } else if (cpuCount.empty()) {
        parsed.diagnostic = "lscpu output has no CPU count";
    } else {
        parsed.usable = true;
    }
    return parsed;
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
        // The placeholder keeps the inventory visible, but it cannot prove the
        // identity of any concrete CPU, so the subsystem stays unproven.
        this->inventoryProven_ = false;
        this->log("Verified lscpu execution failed; creating unknown CPU placeholder: " + error, logLevel::ERROR);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Model name"] = "[Неизвестный процессор]";
        this->deviceParam["Vendor ID"] = "unknown";
        this->deviceParam["CPU(s)"] = "unknown";
        return process_device("cpu", cpu_list_dir);
    }

    // A successful command is NOT proof of usable data.
    const StaticInventoryParse parsed = parse_lscpu_output(result.standardOutput);
    if (!parsed.usable) {
        // Placeholder only: the tool ran, but its output cannot identify a CPU.
        this->inventoryProven_ = false;
        this->log("lscpu output is unusable; creating unknown CPU placeholder: " +
                      parsed.diagnostic,
                  logLevel::ERROR);
        for (auto& [key, value] : this->deviceParam) {
            value = "unknown";
        }
        this->deviceParam["Model name"] = "[Неизвестный процессор]";
        this->deviceParam["Vendor ID"] = "unknown";
        this->deviceParam["CPU(s)"] = "unknown";
        return process_device("cpu", cpu_list_dir);
    }

    this->deviceParam = parsed.values;
    return process_device("cpu", cpu_list_dir);
}
