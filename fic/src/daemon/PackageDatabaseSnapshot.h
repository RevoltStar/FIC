#ifndef FIC_PACKAGE_DATABASE_SNAPSHOT_H
#define FIC_PACKAGE_DATABASE_SNAPSHOT_H
#include "daemon/PackageManagerTransactionLock.h"
#include "platform/PlatformExecutableResolver.h"
#include <chrono>
#include <map>
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
bool parseFicPackageDatabase(fic::platform::PackageManagerKind,const std::string& output,
    PackageDatabaseSnapshot&,std::string& error);
class PackageDatabaseReader {
public:
    PackageDatabaseReader(const fic::platform::PlatformExecutableResolver& executables,
        fic::platform::PackageManagerKind kind):executables_(executables),kind_(kind) {}
    bool read(const PackageManagerTransactionLock&,std::chrono::steady_clock::time_point deadline,
        std::size_t& remainingOutputBytes,PackageDatabaseSnapshot&,std::string& error) const;
private:
    const fic::platform::PlatformExecutableResolver& executables_;
    fic::platform::PackageManagerKind kind_;
};
}
#endif
