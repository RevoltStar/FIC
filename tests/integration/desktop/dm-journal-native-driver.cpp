#include "modules/oss/display_manager/DisplayManagerConfigTransaction.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
namespace fs=std::filesystem;
using fic::platform::ExecutableId;
void require(bool ok,const std::string& message){if(!ok)throw std::runtime_error(message);}
void put(const fs::path& path,const std::string& value){fs::create_directories(path.parent_path());std::ofstream(path)<<value;}
std::string get(const fs::path& path){std::ifstream in(path);return {std::istreambuf_iterator<char>(in),{}};}
int main(){
    if(geteuid()!=0 || !fs::exists("/.dockerenv") || !getenv("FIC_NATIVE_DM_PROBE") || std::string(getenv("FIC_NATIVE_DM_PROBE"))!="container-only"){
        std::cerr<<"Native DM probe is restricted to explicit disposable root containers\n";return 77;
    }
    try {
        // This test intentionally replaces only container /etc fixtures.
        fic::platform::DisplayManagerPlatformConfig config;
        const bool rpm=fs::exists("/usr/bin/rpm")&&!fs::exists("/usr/bin/dpkg-query");
        config.packageManagerKind=rpm?fic::platform::PackageManagerKind::Rpm:fic::platform::PackageManagerKind::Dpkg;
        const std::string gdmExecutable=fs::exists("/usr/sbin/gdm3")?"/usr/sbin/gdm3":"/usr/sbin/gdm";
        config.sddmConfigPath="/etc/sddm.conf";config.sddmConfigDirectories={"/usr/lib/sddm/sddm.conf.d","/etc/sddm.conf.d"};
        config.lightDmConfigPath="/etc/lightdm/lightdm.conf";config.lightDmConfigDirectories={"/usr/share/lightdm/lightdm.conf.d","/usr/local/share/lightdm/lightdm.conf.d","/etc/xdg/lightdm/lightdm.conf.d","/etc/lightdm/lightdm.conf.d"};
        const auto sddmConstants=ProcessExecutor::execute("/usr/bin/strings",{"/usr/bin/sddm"});
        const auto sddmWideConstants=ProcessExecutor::execute("/usr/bin/strings",{"-el","/usr/bin/sddm"});
        require(sddmConstants.success()&&sddmWideConstants.success(),"cannot inspect SDDM compiled resource contract");
        const auto sddmPaths=sddmConstants.standardOutput+"\n"+sddmWideConstants.standardOutput;
        std::set<std::string> sddmCompiled;std::istringstream sddmLines(sddmPaths);std::string sddmLine;
        while(std::getline(sddmLines,sddmLine))sddmCompiled.insert(sddmLine);
        config.sddmConfigPath.clear();config.sddmConfigDirectories[0].clear();
        for(const auto* main:{"/etc/sddm.conf","/etc/X11/sddm/sddm.conf"})if(sddmCompiled.count(main)) {
            require(config.sddmConfigPath.empty(),"ambiguous SDDM native main path");config.sddmConfigPath=main;
        }
        for(const auto* dir:{"/usr/lib/sddm/sddm.conf.d","/usr/lib64/sddm/sddm.conf.d","/usr/share/sddm/conf.d"})if(sddmCompiled.count(dir)) {
            require(config.sddmConfigDirectories[0].empty(),"ambiguous SDDM native system directory");config.sddmConfigDirectories[0]=dir;
        }
        require(!config.sddmConfigPath.empty()&&!config.sddmConfigDirectories[0].empty(),"SDDM compiled resource contract unverified");
        require(sddmCompiled.count("/etc/sddm.conf.d"),"SDDM compiled site directory unverified");
        std::cout<<"SDDM native main="<<config.sddmConfigPath<<" system directory="<<config.sddmConfigDirectories[0]<<'\n';
        const auto constants=ProcessExecutor::execute("/usr/bin/strings",{gdmExecutable});
        require(constants.success(),"cannot inspect installed GDM compiled resource contract");
        std::set<std::string> compiled;std::istringstream constantsIn(constants.standardOutput);std::string line;
        while(std::getline(constantsIn,line))compiled.insert(line);
        for(const auto* primary:{"/etc/gdm3/daemon.conf","/etc/gdm3/custom.conf","/etc/gdm/custom.conf"})
            if(compiled.count(primary))config.gdmConfigCandidates.emplace_back(primary);
        require(config.gdmConfigCandidates.size()==1,"GDM compiled primary path is ambiguous/unverified");
        for(const auto* runtime:{"/run/gdm3/custom.conf","/run/gdm/custom.conf","/var/run/gdm/custom.conf"})if(compiled.count(runtime)) {
            require(config.gdmRuntimeConfigPath.empty(),"GDM compiled runtime path is ambiguous");config.gdmRuntimeConfigPath=runtime;
        }
        require(!config.gdmRuntimeConfigPath.empty(),"GDM compiled runtime path is unverified");
        std::cout<<"GDM native primary="<<config.gdmConfigCandidates[0]<<" runtime="<<config.gdmRuntimeConfigPath<<'\n';
        const auto run=[&](ExecutableId id,const std::vector<std::string>& args){
            const std::string executable=id==ExecutableId::PackageQuery?(rpm?"/usr/bin/rpm":"/usr/bin/dpkg-query"):id==ExecutableId::Sddm?"/usr/bin/sddm":id==ExecutableId::Gdm?gdmExecutable:"/usr/sbin/lightdm";
            ProcessOptions options;options.clearEnvironment=true;options.environment={{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
            return ProcessExecutor::execute(executable,args,options);
        };
        fs::create_directories("/run/fic-dm-probe");
        std::string error;fic::rollback::MutationJournal journal("/run/fic-dm-probe/journal.json");require(journal.initializeOrLoad(error),error);
        DisplayManagerConfigTransaction backend(run,config,"/run/fic-dm-probe/config.lock");
        const std::string sddm="[Autologin]\nUser=admin # inline\nSession=plasma\nRelogin=true\n[Autologin]\nUser=second\n";
        const std::string gdm="[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=admin\nTimedLoginEnable=true\nTimedLogin=second\n";
        const std::string lightdm="[Seat:*]\nautologin-user=admin\nautologin-guest=true\nautologin-session=xfce\n[Seat:seat0]\nautologin-user=second\n[Seat:seat*]\nautologin-guest=true\n";
        const auto nativeSddm=[&](const std::string& expected){
            if(!fs::exists("/run/fic-dm-probe/sddm-native-reader"))throw std::runtime_error("native SDDM ConfigReader witness missing");
            const auto result=ProcessExecutor::execute("/run/fic-dm-probe/sddm-native-reader",{config.sddmConfigPath.string(),
                config.sddmConfigDirectories[1].string(),config.sddmConfigDirectories[0].string()});
            require(result.success()&&result.standardOutput==expected+"\n","independent SDDM native ConfigReader disagrees: "+result.standardError+result.standardOutput);
        };
        put(config.sddmConfigPath,sddm);put(config.gdmConfigCandidates[0],gdm);put(config.lightDmConfigPath,lightdm);
        put(config.sddmConfigDirectories[1]/"90-autologin.conf","[Autologin]\nUser=dropin\n");
        put(config.lightDmConfigDirectories.back()/"90-autologin.conf","[Seat:seat1]\nautologin-user=dropin\nautologin-guest=true\n");
        if(config.gdmRuntimeConfigPath.string().compare(0,9,"/var/run/")==0) {
            const fs::path saved="/var/fic-dm-probe-var-run";
            require(!fs::exists(saved),"runtime alias recovery fixture already exists");
            fs::rename("/var/run",saved);bool refused=false;
            try {
                fs::create_directory_symlink("/tmp","/var/run");
                refused=!backend.preflight("GDM",true,journal,error);
            } catch(...) {fs::remove("/var/run");fs::rename(saved,"/var/run");throw;}
            fs::remove("/var/run");fs::rename(saved,"/var/run");
            require(refused&&get(config.gdmConfigCandidates[0])==gdm,"unproven runtime alias accepted or primary changed");
        }
        nativeSddm("second");
        // No sddm --version/--test-mode, GDM daemon or LightDM daemon is started.
        for(const auto* dm:{"SDDM","GDM","LIGHTDM"}){const bool ok=backend.preflight(dm,true,journal,error);
            if(!ok && std::string(dm)=="LIGHTDM") {
                const auto diagnostic=run(ExecutableId::LightDm,{"--show-config","--config="+config.lightDmConfigPath.string()});
                std::cerr<<"Native fixture stdout:\n"<<diagnostic.standardOutput<<"\nNative fixture stderr:\n"<<diagnostic.standardError;
            }
            require(ok,std::string(dm)+": "+error);
        }
        for(const auto* dm:{"SDDM","GDM","LIGHTDM"}){require(backend.reconcile(dm,true,journal,error),std::string(dm)+": "+error);require(backend.verifyApplied(dm,journal,error),error);}
        nativeSddm("");
        put(config.gdmRuntimeConfigPath,"[daemon]\nTimedLoginEnable=true\n");
        require(!backend.verifyApplied("GDM",journal,error),"native runtime override falsely verified");fs::remove(config.gdmRuntimeConfigPath);
        put(config.sddmConfigPath,get(config.sddmConfigPath)+"[Theme]\nCurrent=foreign\n");
        fic::rollback::MutationJournal restart("/run/fic-dm-probe/journal.json");require(restart.load(error),error);
        require(backend.reconcile("GDM",false,restart,error),error);require(get(config.gdmConfigCandidates[0])==gdm,"GDM release did not preserve native originals");
        require(backend.verifyApplied("SDDM",restart,error),"retained SDDM failed: "+error);
        require(backend.reconcile("GDM",true,restart,error),error);
        require(backend.releaseAll(restart,error),error);
        nativeSddm("second");
        require(get(config.sddmConfigPath)==sddm+"[Theme]\nCurrent=foreign\n","SDDM foreign state changed");
        require(get(config.lightDmConfigPath)==lightdm,"LightDM foreign state changed");
        require(get(config.gdmConfigCandidates[0])==gdm,"GDM foreign state changed");
        // Creation is proven separately from block ownership; last release
        // must delete a truly created empty primary, not a foreign file.
        fs::remove(config.lightDmConfigPath);
        require(backend.reconcile("LIGHTDM",true,restart,error),error);
        require(backend.reconcile("LIGHTDM",false,restart,error),error);
        require(!fs::exists(config.lightDmConfigPath),"created LightDM primary survived release");
        std::cout<<"PASS: native GDM GKeyFile/runtime flags, LightDM wildcard/specific/guest/drop-in inspection, SDDM independent native ConfigReader, restart and release\n";
        std::cout<<"NOT VERIFIED: live DM sessions\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
