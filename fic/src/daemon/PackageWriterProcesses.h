#ifndef FIC_PACKAGE_WRITER_PROCESSES_H
#define FIC_PACKAGE_WRITER_PROCESSES_H
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
// Capture installed legacy executables BEFORE unpack, while their identities
// are still available. Persist these with lifecycle provenance before stopping.
bool captureLegacyWriterImage(const std::filesystem::path&,LegacyWriterImage&,std::string& error);
// No process termination. Refuses recognized FIC executables (including renamed
// byte-for-byte copies), unknown canonical writer names, or unprovable inventory.
// Deployment must prohibit independent legacy launches: this scan is not fencing.
bool proveNoPackageWriterProcesses(const std::vector<LegacyWriterImage>&,
    std::chrono::steady_clock::time_point deadline,std::string& error);
}
#endif
