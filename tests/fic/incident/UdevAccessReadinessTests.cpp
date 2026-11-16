#include "incident/UdevAccessReadiness.h"
#include "incident/IncidentAccessGateCore.h"
#include "incident/DaemonReadiness.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <unistd.h>

using namespace fic::incident;
namespace {
void require(bool b) { if (!b) throw std::runtime_error("udev access readiness invariant"); }
fic::ipc::AccessGateStatus allowed() {
    fic::ipc::AccessGateStatus s;
    s.state="READY";s.mode="ACTIVE";s.modeProven=true;s.stateProven=true;
    s.severity="UNLOCKED";s.provenance="PROVEN";s.loginAllowed=true;return s;
}
void wire(const fic::ipc::AccessGateStatus& s) {
    fic::ipc::AccessGateStatus parsed;std::string error;
    auto j=fic::ipc::serializeAccessGateStatus(s);require(j.size()==10);
    require(fic::ipc::parseAccessGateStatus(j,parsed,error)&&parsed.loginAllowed==s.loginAllowed);
    fic::ipc::PreLoginStatus p;p.access=s;p.started=p.completed=p.applyOk=p.lifecycleCompleted=true;
    p.bootId="11111111-1111-1111-1111-111111111111";p.daemonPid=1;
    fic::ipc::PreLoginStatus copy;require(fic::ipc::parsePreLoginStatus(fic::ipc::serializePreLoginStatus(p),copy,error));
    require(fic::ipc::mayAutoHandoff(copy,p.bootId)==s.loginAllowed);
}
void recovery(const fic::ipc::AccessGateStatus& denied) {
    auto config=fic::platform::makeBuildPlatformProfile().pam.incidentAccessGate;
    config.controlledServices={"login"};config.trustedLocalRootServices={"login"};config.recoveryGroup="fic";
    unsigned requests=0;bool member=false,exempt=false;
    AccessGateDependencies deps{
        [](const std::string& n,auto& id,std::string&){id.uid=n=="root"?0:1000;return true;},
        [&](std::string&){return exempt;},
        [&](const auto&,const auto&,bool& result,std::string&){result=member;return true;},
        [&]{++requests;return IncidentAccessReply{denied.loginAllowed,"udev denied"};},
        []{return IncidentResponseModeResult{IncidentResponseMode::Active,true,"fixture"};}};
    require(decideIncidentAccess({"user","login",""},config,deps).disposition==AccessGateDisposition::Deny);
    require(requests==1);
    require(decideIncidentAccess({"root","login",""},config,deps).disposition==AccessGateDisposition::Pass&&requests==1);
    member=exempt=true;
    require(decideIncidentAccess({"user","login",""},config,deps).disposition==AccessGateDisposition::Pass&&requests==1);
}
}
int main(int argc,char** argv) {
    const auto profile=fic::platform::makeBuildPlatformProfile();
    if(argc==2 && std::string(argv[1])=="--native") {
        // Explicit disposable fixture only. No ordinary CTest can run real udev.
        require(::geteuid()==0 && std::filesystem::exists("/.dockerenv") &&
            std::filesystem::exists("/run/fic-udev-access-native"));
        fic::platform::PlatformExecutableResolver resolver(profile.executables);
        auto paths=fic::core::FicProductPaths::production();
        paths.commandHashFile="/run/fic-udev-access-native/hashes";
        std::string error;require(fic::core::FicRuntimePaths::initialize(paths,error));
        std::filesystem::path exe;require(resolver.resolve(fic::platform::ExecutableId::Udevadm,exe,error));
        require(CommandHashStore::saveHash(exe,error));
        UdevAccessReadiness check;
        const auto start=UdevAccessReadiness::Clock::now();
        const auto status=check.apply(allowed(),resolver);wire(status);
        std::cout<<fic::ipc::serializeAccessGateStatus(status).dump()<<"\n"<<check.diagnostic()<<"\n";
        std::cout<<"elapsed_ms="<<std::chrono::duration_cast<std::chrono::milliseconds>(UdevAccessReadiness::Clock::now()-start).count()<<std::endl;
        return status.loginAllowed?0:10;
    }
    require(argc==1);
    // Existing resolver is exercised, but unit tests never need or execute udev.
    fic::platform::PlatformExecutableResolver resolver({{{fic::platform::ExecutableId::Udevadm,{"/usr/bin/true","/bin/true"}}}});
    using Clock=UdevAccessReadiness::Clock;auto now=Clock::time_point{};
    unsigned calls=0;ProcessResult result;result.started=true;result.exitCode=0;bool throws=false;
    UdevAccessReadiness check([&](const auto&,const auto& args,const ProcessOptions& options){
        ++calls;require(args==std::vector<std::string>({"control","--ping","--timeout=1"}));
        require(options.timeout==std::chrono::milliseconds(1250)&&options.clearEnvironment&&options.maxOutputBytes==4096);
        if(throws)throw std::runtime_error("fixture");return result;
    },[&]{return now;});
    require(check.apply(allowed(),resolver).loginAllowed&&calls==1);
    for(unsigned i=0;i<1000;++i)require(check.apply(allowed(),resolver).loginAllowed);
    require(calls==1);now+=std::chrono::milliseconds(1999);
    require(check.apply(allowed(),resolver).loginAllowed&&calls==1);
    now+=std::chrono::milliseconds(1);result.exitCode=1;
    auto denied=check.apply(allowed(),resolver);require(!denied.loginAllowed&&denied.state=="DEGRADED"&&calls==2);wire(denied);recovery(denied);
    DaemonReadiness readiness;
    for(unsigned i=0;i<1000;++i){readiness.set(DaemonReadinessState::Ready);auto s=allowed();s.state=daemonReadinessToken(readiness.state());require(!check.apply(s,resolver).loginAllowed);}
    require(calls==2);
    now+=std::chrono::seconds(2);result.exitCode=0;require(check.apply(allowed(),resolver).loginAllowed&&calls==3);
    for(const auto& state:{"INITIALIZING","APPLYING","DEGRADED","STOPPING"}){auto s=allowed();s.state=state;require(!check.apply(s,resolver).loginAllowed);}
    for(const auto& severity:{"STANDARD","HARD","ISOLATE"}){auto s=allowed();s.severity=severity;require(!check.apply(s,resolver).loginAllowed);}
    {auto s=allowed();s.modeProven=false;require(!check.apply(s,resolver).loginAllowed);s=allowed();s.stateProven=false;require(!check.apply(s,resolver).loginAllowed);}
    for(unsigned failure=0;failure<4;++failure){
        now+=std::chrono::seconds(2);result={};result.started=true;result.exitCode=1;
        if(failure==0)result.timedOut=true;
        if(failure==1)result.started=false;
        if(failure==2)result.outputLimitExceeded=true;
        throws=failure==3;denied=check.apply(allowed(),resolver);require(!denied.loginAllowed&&!check.diagnostic().empty());wire(denied);
    }
    const auto before=calls;
    for(const auto& mode:{"OFF","PASSIVE"}){auto s=allowed();s.mode=mode;require(check.apply(s,resolver).loginAllowed);require(calls==before);}
    throws=false;result={};result.started=true;result.exitCode=0;
    require(check.apply(allowed(),resolver).loginAllowed&&calls==before+1); // No reuse across mode transitions.
    fic::platform::PlatformExecutableResolver absent({{{fic::platform::ExecutableId::Udevadm,{"/nonexistent/fic-udevadm"}}}});
    UdevAccessReadiness missing([&](const auto&,const auto&,const auto&){throw std::runtime_error("must not launch");return result;});
    require(!missing.apply(allowed(),absent).loginAllowed&&missing.diagnostic().find("unavailable")!=std::string::npos);
    // An abnormally late successful process cannot provide a stale positive.
    UdevAccessReadiness late([&](const auto&,const auto&,const auto&){now+=std::chrono::seconds(2);return result;},[&]{return now;});
    require(!late.apply(allowed(),resolver).loginAllowed);
    std::cout<<"PASS udev ACTIVE/OFF/PASSIVE, deadlines, cache/expiry, recovery, READY overlay, other denials, wire/prelogin, root/fic recovery\n";
}
