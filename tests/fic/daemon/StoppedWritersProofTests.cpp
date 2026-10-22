#include "daemon/StoppedWritersProof.h"
#include <iostream>
#include <string>
int main() {
    const std::string base = "Id=fic.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\n";
    std::string error;
    if (!fic::daemon::proveStoppedUnit("fic.service", base, error)) return 1;
    for (const std::string state : {"active", "activating", "deactivating", "unknown"}) {
        auto text = base; text.replace(text.find("ActiveState=inactive"), 20, "ActiveState=" + state);
        if (fic::daemon::proveStoppedUnit("fic.service", text, error)) return 2;
    }
    for (const std::string extra : {"MainPID=42\n", "ControlPID=43\n", "Job=7\n", "Unknown\n"})
        if (fic::daemon::proveStoppedUnit("fic.service", base + extra, error)) return 3;
    if (fic::daemon::proveStoppedUnit("fic.service", "", error) ||
        fic::daemon::proveStoppedUnit("fic-device.service", base, error)) return 4;
    auto masked=base;masked.replace(masked.find("LoadState=loaded"),16,"LoadState=masked");
    if (!fic::daemon::proveStoppedUnit("fic.service",masked,error)) return 6;
    // Mask alone is not quiescence: an already running masked unit still fails.
    masked.replace(masked.find("MainPID=0"),9,"MainPID=42");
    if (fic::daemon::proveStoppedUnit("fic.service",masked,error)) return 7;
    auto absent = base; absent.replace(absent.find("LoadState=loaded"), 16, "LoadState=not-found");
    if (!fic::daemon::proveStoppedUnit("fic.service", absent, error)) { std::cerr << error; return 5; }
    fic::daemon::WriterUnitFacts facts;
    auto active=base;active.replace(active.find("ActiveState=inactive"),20,"ActiveState=active");
    active.replace(active.find("SubState=dead"),13,"SubState=running");
    active.replace(active.find("MainPID=0"),9,"MainPID=42");
    if(!fic::daemon::inspectWriterUnit("fic.service",active,facts,error)||facts.mainPid!="42"||
        fic::daemon::proveStoppedUnit("fic.service",active,error))return 8;
    for(const auto* value:{"-1","01","2147483648","1 garbage",""}) {
        auto malformed=base;malformed.replace(malformed.find("MainPID=0"),9,std::string("MainPID=")+value);
        if(fic::daemon::inspectWriterUnit("fic.service",malformed,facts,error))return 9;
    }
    if(fic::daemon::inspectWriterUnit("fic.service",base+"Unexpected=value\n",facts,error))return 10;
}
