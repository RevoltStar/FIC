#ifndef CPUINFOCOLLECTOR_H
#define CPUINFOCOLLECTOR_H

#include "InfoCollector.h"

//Обработка процессора
class CPUInfoCollector : public InfoCollector{
public:
    CPUInfoCollector();

    bool process_device_concrete() override;

    // Parses `lscpu` output into the controlled CPU attributes.
    //
    // A successful `lscpu` exit does not prove that its output identifies a
    // CPU: empty or unusable output must leave the subsystem unproven instead
    // of producing a false "the expected CPU is absent/present" conclusion.
    StaticInventoryParse parse_lscpu_output(const std::string& output) const;
};


#endif // CPUINFOCOLLECTOR_H

