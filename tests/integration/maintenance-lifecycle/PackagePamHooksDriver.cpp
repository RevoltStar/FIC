// Disposable native component probe; no production CLI or bypass.
#include "daemon/PackagePamHooks.h"
#include "incident/AltIncidentAccessGateTopology.h"
#include "incident/PamIncidentAccessGateVerifier.h"
#include <cstdlib>
#include <iostream>
#include <unistd.h>
int main(int argc,char** argv) {
    const auto* allowed=std::getenv("FIC_MAINTENANCE_NATIVE");
    if(!allowed||std::string(allowed)!="1"||::geteuid()!=0)return 77;
    if(argc!=2)return 2;
    auto platform=fic::platform::makeBuildPlatformProfile();std::string error;
    const std::string action=argv[1];bool ok=false;
    if(action=="attached")ok=fic::incident::PamIncidentAccessGateVerifier::prove(platform.pam,error);
    else if(action=="attach-alt-fixture"&&!platform.pam.incidentAccessGate.packageTopologyTarget.empty())
        ok=fic::incident::AltIncidentAccessGateTopology::attach(platform.pam.incidentAccessGate.packageTopologyTarget,error);
    else {
        fic::daemon::PackagePamHooks hooks(platform);
        if(action=="proof")ok=hooks.proveDetached(error);
        else if(action=="detach") {
            fic::daemon::DaemonInstanceLock guard;
            if(!guard.tryAcquire("/run/fic",error)){std::cerr<<error<<'\n';return 1;}
            ok=hooks.detach(guard,std::chrono::steady_clock::now()+std::chrono::seconds(30),error);
        } else return 2;
    }
    std::cout<<(ok?"PASS: ":"REFUSED: ")<<error<<'\n';return ok?0:1;
}
