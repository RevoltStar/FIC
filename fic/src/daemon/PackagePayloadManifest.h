#ifndef FIC_PACKAGE_PAYLOAD_MANIFEST_H
#define FIC_PACKAGE_PAYLOAD_MANIFEST_H
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>
#include <sys/types.h>
namespace fic::daemon {
enum class PackagePayloadKind { Regular, Symlink, ManagedPamSlot, ManagedPamProvider };
struct PackagePayloadEntry {
    std::filesystem::path path;
    PackagePayloadKind kind;
    mode_t mode;
    bool ficGroup;
    std::string identity; // SHA256, exact symlink target, or empty for managed slot
};
// Read-only payload evidence, NOT policy ownership or lifecycle authority.
// Completeness against native package file lists and lifecycle provenance is
// a separate prerequisite; a caller cannot infer it from an arbitrary manifest.
class PackagePayloadManifest {
public:
    static bool load(const std::filesystem::path&,const std::string& package,
        const std::string& version,PackagePayloadManifest&,std::string& error);
    // Requires a fresh native file list read under package-manager locks by
    // the caller. Directories are checked physically; no missing payload entry
    // or undeclared symlink/file can be hidden behind a directory declaration.
    bool proveComplete(const std::vector<std::filesystem::path>& ownedPaths,
        std::chrono::steady_clock::time_point deadline,std::string& error) const;
    bool proveInstalled(gid_t ficGroup,std::chrono::steady_clock::time_point deadline,std::string& error) const;
    bool proveRemoved(std::chrono::steady_clock::time_point deadline,std::string& error) const;
    const std::vector<PackagePayloadEntry>& entries() const {return entries_;}
private:
    std::vector<PackagePayloadEntry> entries_;
};
}
#endif
