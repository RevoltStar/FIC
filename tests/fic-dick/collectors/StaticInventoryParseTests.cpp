// Regression tests for the trustworthiness of the static hardware inventory.
//
// A successful `lscpu` / `dmidecode` exit only proves that the tool ran. The
// device daemon derives "the expected CPU/board/memory is present/absent" from
// the published proof, so empty, sectionless, unusable or partially usable tool
// output must leave the subsystem UNPROVEN - while a genuine device with
// missing OPTIONAL attributes must stay proven.
#include "collectors/BoardInfoCollector.h"
#include "collectors/CPUInfoCollector.h"
#include "collectors/MemoryInfoCollector.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

// Representative x86_64 `lscpu` output (util-linux, LC_ALL=C).
const char* kLscpuOutput =
    "Architecture:            x86_64\n"
    "  CPU op-mode(s):        32-bit, 64-bit\n"
    "  Address sizes:         46 bits physical, 48 bits virtual\n"
    "  Byte Order:            Little Endian\n"
    "CPU(s):                  8\n"
    "  On-line CPU(s) list:   0-7\n"
    "Vendor ID:               GenuineIntel\n"
    "  BIOS Vendor ID:        Intel\n"
    "Model name:              Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz\n"
    "  BIOS Model name:       Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz\n"
    "    CPU family:          6\n"
    "    Model:               158\n"
    "    Thread(s) per core:  1\n";

// A successful `lscpu` run with only non-identity lines (no model, no count).
const char* kLscpuWithoutIdentity =
    "Architecture:            x86_64\n"
    "  Byte Order:            Little Endian\n"
    "  On-line CPU(s) list:   0-7\n";

// Representative `dmidecode -t 2` output with optional attributes that real
// firmware frequently leaves unset.
const char* kDmidecodeBoard =
    "# dmidecode 3.6\n"
    "Getting SMBIOS data from sysfs.\n"
    "SMBIOS 3.3.0 present.\n"
    "\n"
    "Handle 0x0002, DMI type 2, 15 bytes\n"
    "Base Board Information\n"
    "\tManufacturer: ASUSTeK COMPUTER INC.\n"
    "\tProduct Name: PRIME B450M-A\n"
    "\tVersion: Rev X.0x\n"
    "\tSerial Number: To be filled by O.E.M.\n"
    "\tAsset Tag: To be filled by O.E.M.\n"
    "\tFeatures:\n"
    "\t\tBoard is a hosting board\n"
    "\tLocation In Chassis: To be filled by O.E.M.\n"
    "\tChassis Handle: 0x0003\n"
    "\tType: Motherboard\n"
    "\tContained Object Handles: 0\n"
    "\n";

// A successful `dmidecode` run that reports another DMI type only.
const char* kDmidecodeWithoutBoardSection =
    "# dmidecode 3.6\n"
    "\n"
    "Handle 0x0000, DMI type 0, 26 bytes\n"
    "BIOS Information\n"
    "\tVendor: American Megatrends Inc.\n"
    "\tVersion: 3202\n"
    "\n";

// A base board section without the product identity.
const char* kDmidecodeBoardWithoutProductName =
    "Handle 0x0002, DMI type 2, 15 bytes\n"
    "Base Board Information\n"
    "\tManufacturer: ASUSTeK COMPUTER INC.\n"
    "\tVersion: Rev X.0x\n"
    "\tSerial Number: 210496172800123\n"
    "\n";

// Two installed DIMMs, one empty slot, and one soldered module outside the
// identity model.
const char* kDmidecodeMemory =
    "# dmidecode 3.6\n"
    "\n"
    "Handle 0x000B, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tArray Handle: 0x000A\n"
    "\tTotal Width: 64 bits\n"
    "\tSize: 8 GB\n"
    "\tForm Factor: DIMM\n"
    "\tLocator: DIMM_A1\n"
    "\tBank Locator: BANK 0\n"
    "\tType: DDR4\n"
    "\tSpeed: 3200 MT/s\n"
    "\tManufacturer: Kingston\n"
    "\tSerial Number: 0A1B2C3D\n"
    "\tPart Number: KHX3200C16D4/8GX\n"
    "\n"
    "Handle 0x000C, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tSize: No Module Installed\n"
    "\tForm Factor: DIMM\n"
    "\tLocator: DIMM_A2\n"
    "\tBank Locator: BANK 1\n"
    "\n"
    "Handle 0x000D, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tSize: 8 GB\n"
    "\tForm Factor: DIMM\n"
    "\tLocator: DIMM_B1\n"
    "\tType: DDR4\n"
    "\tManufacturer: Kingston\n"
    "\tPart Number: KHX3200C16D4/8GX\n"
    "\n";

// A second physical module whose size could not be read: the module inventory
// is incomplete even though the first module was identified.
const char* kDmidecodeMemoryPartial =
    "Handle 0x000B, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tSize: 8 GB\n"
    "\tForm Factor: DIMM\n"
    "\tLocator: DIMM_A1\n"
    "\tManufacturer: Kingston\n"
    "\n"
    "Handle 0x000C, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tSize: Unknown\n"
    "\tForm Factor: DIMM\n"
    "\tLocator: DIMM_A2\n"
    "\tManufacturer: Kingston\n"
    "\n";

// An installed module without its slot locator.
const char* kDmidecodeMemoryWithoutLocator =
    "Handle 0x000B, DMI type 17, 40 bytes\n"
    "Memory Device\n"
    "\tSize: 8 GB\n"
    "\tForm Factor: DIMM\n"
    "\tType: DDR4\n"
    "\tManufacturer: Kingston\n"
    "\n";

std::size_t countKind(
    const std::vector<MemoryModuleRecord>& modules, MemoryModuleKind kind) {
    std::size_t count = 0;
    for (const MemoryModuleRecord& module : modules) {
        if (module.kind == kind) ++count;
    }
    return count;
}

} // namespace

int main() {
    // ---- CPU -------------------------------------------------------------
    {
        CPUInfoCollector cpu;
        const StaticInventoryParse parsed = cpu.parse_lscpu_output(kLscpuOutput);
        require(parsed.usable, "a complete lscpu output must be usable: " +
                                   parsed.diagnostic);
        require(parsed.values.at("Model name") ==
                    "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
                "the CPU model must be parsed");
        require(parsed.values.at("CPU(s)") == "8",
                "the CPU count must be parsed");
        require(parsed.values.at("Vendor ID") == "GenuineIntel",
                "the vendor must be parsed");
    }
    {
        CPUInfoCollector cpu;
        const StaticInventoryParse parsed = cpu.parse_lscpu_output("");
        require(!parsed.usable,
                "an empty lscpu output must not prove the CPU inventory");
        require(!parsed.diagnostic.empty(),
                "an empty lscpu output must be diagnosed");
    }
    {
        CPUInfoCollector cpu;
        const StaticInventoryParse parsed =
            cpu.parse_lscpu_output(kLscpuWithoutIdentity);
        require(!parsed.usable,
                "an lscpu output without the CPU identity must not be usable");
        require(!parsed.diagnostic.empty(),
                "a model-less lscpu output must be diagnosed");
    }
    {
        // A model without the CPU count is incomplete: the count is part of the
        // identity hash.
        CPUInfoCollector cpu;
        const StaticInventoryParse parsed = cpu.parse_lscpu_output(
            "Architecture:            x86_64\n"
            "Vendor ID:               GenuineIntel\n"
            "Model name:              Some CPU\n");
        require(!parsed.usable,
                "an lscpu output without the CPU count must not be usable");
    }
    // ---- Board -----------------------------------------------------------
    {
        BoardInfoCollector board;
        const StaticInventoryParse parsed =
            board.parse_dmidecode_output(kDmidecodeBoard);
        require(parsed.usable,
                "a complete base board section must be usable: " +
                    parsed.diagnostic);
        require(parsed.values.at("Manufacturer") == "ASUSTeK COMPUTER INC.",
                "the manufacturer must be parsed");
        require(parsed.values.at("Product Name") == "PRIME B450M-A",
                "the product name must be parsed");
        require(parsed.values.at("Serial Number") == "To be filled by O.E.M.",
                "an optional serial number must still be carried");
    }
    {
        BoardInfoCollector board;
        const StaticInventoryParse parsed = board.parse_dmidecode_output("");
        require(!parsed.usable,
                "an empty dmidecode output must not prove the board");
        require(!parsed.diagnostic.empty(),
                "an empty dmidecode output must be diagnosed");
    }
    {
        BoardInfoCollector board;
        const StaticInventoryParse parsed =
            board.parse_dmidecode_output(kDmidecodeWithoutBoardSection);
        require(!parsed.usable,
                "an output without Base Board Information must not prove the "
                "board");
    }
    {
        BoardInfoCollector board;
        const StaticInventoryParse parsed =
            board.parse_dmidecode_output(kDmidecodeBoardWithoutProductName);
        require(!parsed.usable,
                "a base board section without the product name must not be "
                "usable");
    }
    {
        // Serial number and version are optional: their absence must not make a
        // real board unproven.
        BoardInfoCollector board;
        const StaticInventoryParse parsed = board.parse_dmidecode_output(
            "Base Board Information\n"
            "\tManufacturer: Intel Corporation\n"
            "\tProduct Name: H61M\n"
            "\n");
        require(parsed.usable,
                "a real board without optional attributes must stay usable: " +
                    parsed.diagnostic);
        require(parsed.values.at("Serial Number").empty(),
                "an absent optional attribute must stay empty");
    }

    // ---- Memory ----------------------------------------------------------
    {
        MemoryInfoCollector memory;
        const std::vector<MemoryModuleRecord> modules =
            memory.parse_dmidecode_modules(kDmidecodeMemory);
        require(modules.size() == 3,
                "every Memory Device section must be classified");
        require(countKind(modules, MemoryModuleKind::Physical) == 2,
                "both installed DIMMs must be identified");
        require(countKind(modules, MemoryModuleKind::NotPhysical) == 1,
                "the empty slot must not be inventoried as a module");
        require(countKind(modules, MemoryModuleKind::Incomplete) == 0,
                "a complete inventory must not report incomplete modules");
        bool foundFirst = false;
        for (const MemoryModuleRecord& module : modules) {
            if (module.kind != MemoryModuleKind::Physical) continue;
            if (module.values.at("Locator") == "DIMM_A1") {
                foundFirst = module.values.at("Size") == "8 GB" &&
                    module.values.at("Manufacturer") == "Kingston";
            }
        }
        require(foundFirst,
                "the module attributes must be parsed into the record");
    }
    {
        MemoryInfoCollector memory;
        const std::vector<MemoryModuleRecord> modules =
            memory.parse_dmidecode_modules("");
        require(modules.empty(),
                "an empty dmidecode output must report no module");
    }
    {
        MemoryInfoCollector memory;
        const std::vector<MemoryModuleRecord> modules =
            memory.parse_dmidecode_modules(kDmidecodeMemoryPartial);
        require(countKind(modules, MemoryModuleKind::Physical) == 1,
                "the identified module must still be reported");
        require(countKind(modules, MemoryModuleKind::Incomplete) == 1,
                "a module without a usable size must make the inventory "
                "incomplete");
    }
    {
        MemoryInfoCollector memory;
        const std::vector<MemoryModuleRecord> modules =
            memory.parse_dmidecode_modules(kDmidecodeMemoryWithoutLocator);
        require(countKind(modules, MemoryModuleKind::Incomplete) == 1,
                "a module without a slot locator must make the inventory "
                "incomplete");
        require(countKind(modules, MemoryModuleKind::Physical) == 0,
                "an unidentifiable module must not be stored as physical");
    }

    std::cout << "Static inventory parse contract proven\n";
    return 0;
}

