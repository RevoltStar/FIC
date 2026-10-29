#include "service/sssd/SssdVerifiedInputClosure.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <stdexcept>
using J=nlohmann::json;
namespace s=fic::service::sssd;
namespace d=fic::service::detail;
void require(bool x,const std::string& text){if(!x)throw std::runtime_error(text);}
template<class F> void refused(F f){bool no=false;try{f();}catch(const d::Failure&){no=true;}require(no,"unsupported input accepted");}
void put(d::LaunchContract& c,const std::string& k,const std::string& sig,J v){c["launch."+k]=J{{"signature",sig},{"value",v}}.dump();}
int main(int argc,char**argv){try {
    require(argc==2,"fixture argument required");std::ifstream f(argv[1]);J fixtures;f>>fixtures;
    require(fixtures.size()==5,"five measured native contracts required");
    for(const auto& [platform,item]:fixtures.items()) {
        const auto profile=s::launchProfile(platform);const auto c=item.get<d::LaunchContract>();
        s::validateLaunchProfile(c,profile);
        auto badSource=c;auto source=J::parse(c.at("launch.file:"+profile.fragment));source["file"][10]=std::string(64,'0');badSource["launch.file:"+profile.fragment]=source.dump();refused([&]{s::validateLaunchProfile(badSource,profile);});
        auto ready=c;put(ready,"ActiveState","s","active");put(ready,"SubState","s","running");put(ready,"MainPID","u",123u);put(ready,"Job","(uo)",J::array({0u,"/"}));
        require(s::classifyService(ready)==s::AdmissionState::Candidate,"active candidate");
        auto changed=ready;put(changed,"Job","(uo)",J::array({123u,"/job/123"}));require(s::classifyService(changed)==s::AdmissionState::Transitioning,"pending Job");
        changed=ready;put(changed,"ActiveState","s","failed");require(s::classifyService(changed)==s::AdmissionState::Failed,"failed service");
        changed=ready;put(changed,"ActiveState","s","inactive");put(changed,"SubState","s","dead");require(s::classifyService(changed)==s::AdmissionState::Stopped,"stopped service");
        changed=ready;put(changed,"ActiveState","s","mystery");require(s::classifyService(changed)==s::AdmissionState::Unknown,"unknown service");
        for(const auto& key:{"launch.Type","launch.ExecStartEx","launch.RootImage","launch.EnvironmentFiles","launch.User","launch.TriggeredBy","launch.ManagerEnvironment"}) {
            changed=c;changed.erase(key);refused([&]{s::validateLaunchProfile(changed,profile);});
        }
        for(const auto& key:{"Type","FragmentPath","User","PIDFile"}) {changed=c;put(changed,key,"b",false);refused([&]{s::validateLaunchProfile(changed,profile);});}
        changed=c;put(changed,"ExecStartPreEx","a(sasasttttuii)",J::array({J::array({"/bin/evil",J::array({"/bin/evil"}),J::array()})}));refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;auto cmd=J::parse(changed.at("launch.ExecStartEx"));cmd["value"][0][1].push_back("-c");cmd["value"][0][1].push_back("/tmp/custom");changed["launch.ExecStartEx"]=cmd.dump();refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;put(changed,"DropInPaths","as",J::array({"/etc/systemd/system/sssd.service.d/override.conf"}));refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;put(changed,"NeedDaemonReload","b",true);refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;put(changed,"EnvironmentFiles","a(sb)",J::array({J::array({"/etc/unknown",true})}));refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;put(changed,"Environment","as",J::array({"DEBUG_LOGGER=-c /etc/other"}));refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;put(changed,"RootDirectory","s","/srv/root");refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;changed["launch.ManagerEnvironment"]=J::array({"LD_PRELOAD=/untrusted"}).dump();refused([&]{s::validateLaunchProfile(changed,profile);});
        changed=c;put(changed,"PrivateMounts","b",true);refused([&]{s::validateLaunchProfile(changed,profile);});
        if(!profile.pidFile.empty()) {
            std::vector<fic::service::ControlledPath> env{{profile.environment,fic::service::ControlledPathKind::File,std::string(64,'0'),{}}};
            refused([&]{d::validateLaunchContract(c,&env);}); // Generic restrictions unchanged.
        }
    }
    refused([]{s::launchProfile("unknown");});
    const std::vector<std::string> order{"main","10.conf","90.conf"};
    const std::map<std::string,std::string> bytes{{"main","[pam]\noffline_credentials_expiration=1\n"},{"10.conf","[pam]\noffline_credentials_expiration=2\n"},{"90.conf","[pam]\noffline_credentials_expiration=3\noffline_credentials_expiration=4\n"}};
    auto p=s::detail_i1::project(order,bytes);require(p.at("pam").at("offline_credentials_expiration").value=="4"&&p.at("pam").at("offline_credentials_expiration").source=="90.conf","ordered duplicate projection");
    for(const auto& text:{"[pam]\nkey=first\n continued\n","[pam]\nkey=\"quoted\"\n","[pam]\nkey=1 # inline\n","orphan=1\n","[invalid section]\nx=1\n","[pam]\nx=\n"})refused([&]{s::detail_i1::project({"x"},{{"x",text}});});
    for(const auto& file:{".hidden.conf","foo.conf.bak","FOO.CONF","conf.d/sub.conf","x"})require(!s::detail_i1::loadedSnippet(file),"ignored file loaded");
    for(const auto& file:{"10.conf","zzzzz.conf"})require(s::detail_i1::loadedSnippet(file),"snippet omitted");
    for(const auto& platform:{"debian-12","debian-13","ubuntu-24.04","ubuntu-26.04","alt-p11"}) {
        auto missing=s::detail_i1::project({"main"},{{"main","[sssd]\ndomains=test\n"}});
        if(std::string(platform)=="alt-p11")refused([&]{s::detail_i1::validateConsumerIdentity(missing,platform);});
        else s::detail_i1::validateConsumerIdentity(missing,platform);
    }
    for(const auto& services:{"", "services=nss,pam\n"}) {
        for(const auto& user:{"root","unknown","_sssd"}) {
            const auto ini=s::detail_i1::project({"main","10.conf","90.conf"},
                {{"main",std::string("[sssd]\n")+services+"user=_sssd\n"},
                 {"10.conf","[sssd]\nuser=root\n"},{"90.conf",std::string("[sssd]\nuser=")+user+"\n"}});
            if(std::string(user)=="_sssd")s::detail_i1::validateConsumerIdentity(ini,"alt-p11");
            else refused([&]{s::detail_i1::validateConsumerIdentity(ini,"alt-p11");});
        }
    }
    std::cout<<"SSSD I1 closed launch/profile/projection tests PASS\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
