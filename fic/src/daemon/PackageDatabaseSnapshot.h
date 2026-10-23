#ifndef FIC_PACKAGE_DATABASE_SNAPSHOT_H
#define FIC_PACKAGE_DATABASE_SNAPSHOT_H
#include "daemon/PackageManagerTransactionLock.h"
#include "platform/PlatformExecutableResolver.h"
#include <chrono>
#include <map>
#include <vector>
namespace fic::daemon {
enum class PackageInstallState { Absent, ConfigFiles, Incomplete, Installed };
struct PackageDatabaseEntry {
    PackageInstallState state=PackageInstallState::Absent;
    std::string version,architecture;
};
struct PackageDatabaseSnapshot {
    std::map<std::string,PackageDatabaseEntry> packages;
};
// These are observations, NOT lifecycle completion proofs. DB absence alone
// never authorizes runtime removal. The controller must additionally prove
// manifest, domain state, provenance and transaction completion.
bool parseFicPackageOwnedPaths(const std::string& output,
    std::vector<std::filesystem::path>&,std::string& error);
bool parseFicPackageDatabase(fic::platform::PackageManagerKind,const std::string& output,
    PackageDatabaseSnapshot&,std::string& error);
// Exact prerequisite identity only; never authorizes clearing a lifecycle fence.
bool proveRuntimePackagePrerequisite(const PackageDatabaseSnapshot&,const std::string& expectedVersion,
    std::string& error);
class PackageDatabaseReader {
public:
    PackageDatabaseReader(const fic::platform::PlatformExecutableResolver& executables,
        fic::platform::PackageManagerKind kind):executables_(executables),kind_(kind) {}
    bool read(const PackageManagerTransactionLock&,std::chrono::steady_clock::time_point deadline,
        std::size_t& remainingOutputBytes,PackageDatabaseSnapshot&,std::string& error) const;
    bool readOwnedPaths(const PackageManagerTransactionLock&,const std::string& package,
        std::chrono::steady_clock::time_point deadline,std::size_t& remainingOutputBytes,
        std::vector<std::filesystem::path>&,std::string& error) const;
    // Package-manager child pre-script: parent owns transaction locks, so this
    // is an observation, NOT transaction completion/finalizer authority.
    bool observeRuntimePrerequisite(const std::string& expectedVersion,
        std::chrono::steady_clock::time_point deadline,std::size_t& remainingOutputBytes,
        std::string& error) const;
private:
    bool executeQuery(const std::string& ownedPackage,std::chrono::steady_clock::time_point,
        std::size_t&,std::string& output,std::string& error) const;
    bool query(std::chrono::steady_clock::time_point,std::size_t&,PackageDatabaseSnapshot&,std::string&) const;
    const fic::platform::PlatformExecutableResolver& executables_;
    fic::platform::PackageManagerKind kind_;
};
}
#endif
