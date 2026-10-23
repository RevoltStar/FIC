#include "daemon/PackageLifecycleCoordinator.h"
#include <cstdlib>
#include <iostream>
#include <unistd.h>
int main(int argc,char** argv) {
    const auto* opt=std::getenv("FIC_MAINTENANCE_NATIVE");
    if(::geteuid()!=0||!opt||std::string(opt)!="1")return 77;
    if(argc!=2||std::string(argv[1])!="prepare")return 2;
    fic::platform::PlatformProfile platform;
    platform.executables.entries.push_back({fic::platform::ExecutableId::Systemctl,{"/usr/bin/systemctl","/bin/systemctl"},true,{},{}});
    fic::core::FicProductPaths paths;
    paths.privateBinDir="/var/lib/m1-native-coordinator/bin";
    paths.commandHashFile="/var/lib/m1-native-coordinator/hash/commandhash.txt";
    paths.lockDebugLogFile="/var/lib/m1-native-coordinator/lock.log";
    paths.mutationJournalFile="/var/lib/m1-native-coordinator/journal.json";
    fic::daemon::PackageLifecycleLocations locations{
        "/var/lib/m1-native-coordinator/state","/etc/systemd/system",
        "/var/lib/m1-native-coordinator/runtime"};
    fic::daemon::PackageLifecycleCoordinator coordinator(platform,paths,locations);
    std::string error;
    if(!coordinator.requestStopBeforeAdmission(error)){std::cerr<<error<<'\n';return 1;}
    fic::daemon::DaemonInstanceLock guard;
    if(!guard.tryAcquire("/run/fic",error)){std::cerr<<error<<'\n';return 1;}
    fic::daemon::PackageLifecycleState prepared;
    if(!coordinator.prepare(guard,fic::daemon::PackageOperation::Install,"native-prepare-1",prepared,error)) {
        std::cerr<<error<<'\n';return 1;
    }
    std::cout<<prepared.operationId<<'\n';return 0;
}
