#ifndef FIC_PACKAGE_WRITER_PROCESSES_H
#define FIC_PACKAGE_WRITER_PROCESSES_H
#include "daemon/DaemonInstanceLock.h"
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
namespace fic::daemon {
struct LegacyWriterImage {
    std::uint64_t device=0,inode=0,size=0;
    std::string digest;
};
// Capture current installed executable identities for the bounded process
// census before package infrastructure is detached. No persistent inventory.
bool captureLegacyWriterImage(const std::filesystem::path&,LegacyWriterImage&,std::string& error,
    bool requireExecutable=true);
// No process termination. Refuses recognized FIC executables (including renamed
// byte-for-byte copies), unknown canonical writer names, or unprovable process identity.
// Deployment must prohibit independent legacy launches: this scan is not fencing.
bool proveNoPackageWriterProcesses(const std::vector<LegacyWriterImage>&,
    std::chrono::steady_clock::time_point deadline,std::string& error);
}
#endif
