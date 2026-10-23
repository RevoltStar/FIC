#include "daemon/PackageRuntimePrerequisite.h"
#include "daemon/PackageRuntimeIdentityGenerated.h"
#include "daemon/PackageLifecycleState.h"
#include "daemon/PackageWriterProcesses.h"
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
bool proveExecutingPackageRuntime(const fic::platform::PlatformProfile& platform,const std::string& requestedPackageVersion,
    unsigned requestedAbi,std::string& error) {
    const auto deadline=std::chrono::steady_clock::now()+FINALIZER_ATTEMPT_TIMEOUT;
    if(::geteuid()!=0||!LifecycleRuntimePackageVersion[0]||
        requestedPackageVersion!=LifecycleRuntimePackageVersion||requestedAbi!=LifecycleRuntimeAbi) {
        error="package lifecycle requires root and matching compiled runtime version/ABI";return false;
    }
    LegacyWriterImage runtime;
    if(!captureLegacyWriterImage("/usr/libexec/fic/fic-runtime",runtime,error))return false;
    struct stat executing{};
    if(::stat("/proc/self/exe",&executing)||!S_ISREG(executing.st_mode)||
       runtime.device!=static_cast<std::uint64_t>(executing.st_dev)||
       runtime.inode!=static_cast<std::uint64_t>(executing.st_ino)||
       runtime.size!=static_cast<std::uint64_t>(executing.st_size)) {
        error="executing engine differs from the trusted installed lifecycle runtime";return false;
    }
    fic::platform::PlatformExecutableResolver executables(platform.executables);
    PackageDatabaseReader database(executables,platform.packageManager.kind);
    std::size_t budget=FINALIZER_OUTPUT_LIMIT;
    return database.observeRuntimePrerequisite(LifecycleRuntimePackageVersion,
        deadline,budget,error);
}
}
