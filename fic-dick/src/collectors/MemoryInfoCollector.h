#ifndef MEMORYINFOCOLLECTOR_H
#define MEMORYINFOCOLLECTOR_H

#include "InfoCollector.h"

#include <vector>

// What one `Memory Device` DMI section turned out to be.
enum class MemoryModuleKind {
    // An empty slot or a form factor outside this identity model: it is
    // deliberately not inventoried and proves nothing about the inventory.
    NotPhysical,
    // A physical module with the attributes this identity model needs.
    Physical,
    // A section that looks physical but cannot be identified (missing size or
    // slot locator): the module inventory is INCOMPLETE.
    Incomplete
};

struct MemoryModuleRecord {
    std::map<std::string, std::string> values;
    MemoryModuleKind kind = MemoryModuleKind::NotPhysical;
    std::string diagnostic;
};

//Обработка процессора
class MemoryInfoCollector : public InfoCollector{
public:
    MemoryInfoCollector();

    bool process_device_concrete()override;

    // Parses `dmidecode -t 17` output into per-module records.
    //
    // A successful `dmidecode` exit does not prove a complete module
    // inventory: a module section that cannot be identified makes the whole
    // module inventory unproven instead of being silently skipped.
    std::vector<MemoryModuleRecord> parse_dmidecode_modules(
        const std::string& output) const;


};


#endif // CPUINFOCOLLECTOR_H


