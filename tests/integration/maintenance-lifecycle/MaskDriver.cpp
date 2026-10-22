#include "daemon/PackageUnitMasks.h"
#include <cstdlib>
#include <iostream>
#include <unistd.h>
int main(int argc,char** argv) {
    if(::geteuid()!=0 || !std::getenv("FIC_MAINTENANCE_NATIVE") ||
        std::string(std::getenv("FIC_MAINTENANCE_NATIVE"))!="1")return 77;
    if(argc!=2)return 2;
    fic::daemon::DaemonInstanceLock guard;std::string error;
    if(!guard.tryAcquire("/run/fic",error)){std::cerr<<error;return 1;}
    fic::daemon::PackageUnitMasks masks("/var/lib/m1-native-masks","/etc/systemd/system");
    const std::string id(32,'a'),action=argv[1];bool ok=false;
    if(action=="prepare")ok=masks.prepare(guard,id,error);
    else if(action=="publish")ok=masks.publish(guard,id,error);
    else if(action=="prove")ok=masks.provePublished(id,error);
    else if(action=="restore")ok=masks.restore(guard,id,error);
    else return 2;
    if(!ok)std::cerr<<error<<'\n';
    return ok?0:1;
}
