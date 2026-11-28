#ifndef BOARDINFOCOLLECTOR_H
#define BOARDINFOCOLLECTOR_H

#include "InfoCollector.h"

//Обработка процессора
class BoardInfoCollector : public InfoCollector{
public:
    BoardInfoCollector();

    bool process_device_concrete() override;

    // Parses `dmidecode -t 2` output into the controlled board attributes.
    //
    // A successful `dmidecode` exit does not prove that the base board section
    // was reported: without that section, or without the manufacturer/product
    // identity, the subsystem stays unproven. `Serial Number` and `Version` are
    // optional on real hardware and are never required.
    StaticInventoryParse parse_dmidecode_output(const std::string& output) const;
};

#endif // BOARDINFOCOLLECTOR_H
