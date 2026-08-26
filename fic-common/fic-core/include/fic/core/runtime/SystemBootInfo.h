#ifndef SYSTEMBOOTINFO_H
#define SYSTEMBOOTINFO_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <unistd.h>
#include <mutex>

class SystemBootInfo {
public:
static std::string get_boot_id() {
        static std::string boot_id_cache;
        static std::once_flag boot_id_flag;

        std::call_once(boot_id_flag, []() {
            std::ifstream boot_id_file("/proc/sys/kernel/random/boot_id");
            std::getline(boot_id_file, boot_id_cache);
            boot_id_file.close();

            while (!boot_id_cache.empty() &&
                   (boot_id_cache.back() == '\n' || boot_id_cache.back() == '\r')) {
                boot_id_cache.pop_back();
            }
        });

        return boot_id_cache;
    }
};


#endif // SYSTEMBOOTINFO_H
