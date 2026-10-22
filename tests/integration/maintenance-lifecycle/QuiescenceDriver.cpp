#include "daemon/PackageWritersQuiescence.h"
#include <cstdlib>
#include <iostream>
#include <unistd.h>
int main(int argc,char** argv) {
    const auto* opt=std::getenv("FIC_MAINTENANCE_NATIVE");
    if(::geteuid()!=0||!opt||std::string(opt)!="1")return 77;
    if(argc!=2)return 2;
    fic::platform::PlatformExecutables paths;
    paths.entries.push_back({fic::platform::ExecutableId::Systemctl,{"/usr/bin/systemctl","/bin/systemctl"},true,{},{}});
    fic::platform::PlatformExecutableResolver executables(paths);
    fic::daemon::PackageWritersQuiescence writers(executables);
    std::string error;const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(30);
    if(std::string(argv[1])=="pre-stop") {
        if(writers.requestStopBeforeAdmission(deadline,error))return 0;
    } else if(std::string(argv[1])=="stop-prove"||std::string(argv[1])=="prove") {
        fic::daemon::DaemonInstanceLock guard;
        if(!guard.tryAcquire("/run/fic",error)){std::cerr<<error;return 1;}
        fic::daemon::PackageUnitMasks masks("/var/lib/m1-native-masks","/etc/systemd/system");
        const bool stopped=std::string(argv[1])=="stop-prove";
        if(stopped?writers.stopAndProve(guard,masks,std::string(32,'a'),{},deadline,error):
            writers.prove(guard,masks,std::string(32,'a'),{},deadline,error))return 0;
    } else return 2;
    std::cerr<<error<<'\n';return 1;
}
