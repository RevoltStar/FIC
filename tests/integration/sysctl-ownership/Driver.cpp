#include "modules/sysctl/SysctlTransaction.h"
#include "modules/sysctl/SysctlSystemd.h"
#include "platform/PlatformCompatibility.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <cstdlib>

namespace fs=std::filesystem;
using namespace fic::rollback;
void check(bool ok,const std::string& why){if(!ok)throw std::runtime_error(why);}
void write(const fs::path& path,const std::string& text){std::ofstream f(path);f<<text;check(f.good(),"native fixture write failed: "+path.string());}
std::string read(const fs::path& path){std::ifstream f(path);return {std::istreambuf_iterator<char>(f),{}};}
int main(){try{
    check(std::getenv("FIC_SYSCTL_NATIVE")&&fs::exists("/.dockerenv")&&read("/proc/1/comm")=="systemd\n","isolated systemd native fixture required");
    auto paths=fic::core::FicProductPaths::production();
    paths.configDir="/run/fic-sysctl/config";paths.logDir="/run/fic-sysctl/log";
    paths.dataDir="/run/fic-sysctl/state";paths.commandHashFile="/run/fic-sysctl/hashes";paths.runtimeDir="/run/fic";
    for(const auto& path:{paths.configDir,paths.logDir,paths.dataDir})fs::create_directories(path);
    std::string error;check(fic::core::FicRuntimePaths::initialize(paths,error),error);
    auto profile=fic::platform::makeBuildPlatformProfile();
    check(fic::platform::validatePlatformProfile(profile,error),error);
    check(fic::platform::validateHostCompatibility(profile,"/etc/os-release",error),error);
    fic::platform::PlatformExecutableResolver resolver(profile.executables);fs::path binary;
    check(resolver.resolve(fic::platform::ExecutableId::SystemdSysctl,binary,error),error);
    check(CommandHashStore::saveHash(binary.string(),error),error); // explicit fixture provisioning
    SysctlConfigurationOptions options;options.platform=profile.sysctl;std::set<fs::path> visited;
    for(const auto& directory:options.directories)if(fs::exists(directory)&&visited.insert(fs::canonical(directory)).second)
        for(auto& entry:fs::directory_iterator(directory))if(entry.path().extension()==".conf")fs::remove(entry.path());
    fs::create_directories("/etc/sysctl.d");fs::create_directories("/run/sysctl.d");
    const auto admission=[&](std::string& why){return sysctlLoaderAdmission(resolver,why);};check(admission(error),error);
    MutationJournal journal(paths.dataDir/"journal.json");check(journal.initializeOrLoad(error),error);
    const PolicyRef first{"SYSCTL","Global","native_first"},second{"SYSCTL","Global","native_second"};
    const std::string key="net.ipv4.ip_forward",other="net.ipv4.ip_forward_use_pmtu";
    write("/proc/sys/net/ipv4/ip_forward","1");write("/proc/sys/net/ipv4/ip_forward_use_pmtu","0");
    write("/etc/sysctl.d/10-foreign.conf",key+"=1\n"+other+"=1\n");
    auto result=applySysctlOwned(journal,first,key,"1",options,{},admission);check(result.ok,result.message);
    auto id=journal.activeRecords(first).front().id;
    auto before=read(options.platform.managedConfigPath),document=read(paths.dataDir/"journal.json");
    result=applySysctlOwned(journal,first,key,"1",options,{},admission);
    check(result.ok&&!result.changed&&before==read(options.platform.managedConfigPath)&&document==read(paths.dataDir/"journal.json"),"native no-op changed persistent state");
    result=applySysctlOwned(journal,first,key,"0",options,{},admission);
    check(result.ok&&read("/proc/sys/net/ipv4/ip_forward")=="0\n",result.message);
    auto callback=[&](const std::string& released,std::string& why){
        for(const auto& row:journal.records())if(row.id==id)check(row.status==MutationStatus::RolledBack,"native reapply preceded durable release");
        return reapplySysctlPrefix(resolver,released,why);
    };
    auto release=[&]{std::lock_guard<std::mutex> lock(SysctlConfiguration::mutationMutex());return releaseSysctlOwned(journal,id,options,callback);};
    result=release();check(result.ok&&result.diagnostics.empty(),result.message);
    check(read("/proc/sys/net/ipv4/ip_forward")=="1\n"&&read("/proc/sys/net/ipv4/ip_forward_use_pmtu")=="0\n","native prefix failed foreign value or changed unrelated leaf");
    fs::remove("/etc/sysctl.d/10-foreign.conf");
    result=applySysctlOwned(journal,first,key,"0",options,{},admission);check(result.ok,result.message);id=journal.activeRecords(first).front().id;
    result=release();check(result.ok&&read("/proc/sys/net/ipv4/ip_forward")=="0\n","release reconstructed a missing foreign value");
    write("/run/sysctl.d/zzzzz-late.conf","# no controlled key\n");document=read(paths.dataDir/"journal.json");
    result=applySysctlOwned(journal,first,key,"1",options,{},admission);
    check(!result.ok&&document==read(paths.dataDir/"journal.json")&&!fs::exists(options.platform.managedConfigPath),"late unrelated file did not refuse before mutation");
    fs::create_symlink("/dev/null","/etc/sysctl.d/zzzzz-late.conf");
    result=applySysctlOwned(journal,first,key,"1",options,{},admission);check(result.ok,result.message);id=journal.activeRecords(first).front().id;
    fs::rename(paths.commandHashFile,paths.commandHashFile.string()+".saved");
    result=release();
    check(result.ok&&!result.diagnostics.empty()&&journal.activeRecords(first).empty()&&!fs::exists(options.platform.managedConfigPath),"native execution refusal cancelled released ownership");
    fs::rename(paths.commandHashFile.string()+".saved",paths.commandHashFile);
    result=applySysctlOwned(journal,first,key,"0",options,{},admission);check(result.ok,result.message);id=journal.activeRecords(first).front().id;
    result=applySysctlOwned(journal,second,other,"0",options,{},admission);check(result.ok,result.message);
    result=release();check(result.ok&&fs::exists(options.platform.managedConfigPath)&&read(options.platform.managedConfigPath).find("ip_forward_use_pmtu")!=std::string::npos,"native single release lost sibling");
    id=journal.activeRecords(second).front().id;result=release();check(result.ok&&!fs::exists(options.platform.managedConfigPath),"native last creator did not delete container");
    result=release();check(result.ok&&result.targetMissing,"native repeated release not idempotent");
    fs::path systemctl;check(resolver.resolve(fic::platform::ExecutableId::Systemctl,systemctl,error),error);
    check(CommandHashStore::saveHash(systemctl.string(),error),error);
    auto reload=[&]{check(VerifiedProcessExecutor::execute(systemctl.string(),{"daemon-reload"}).success(),"fixture daemon-reload failed");};
    const fs::path unit="/etc/systemd/system/systemd-sysctl.service";
    check(!fs::exists(unit)&&!fs::is_symlink(unit),"unexpected fixture unit override");
    fs::create_symlink("/dev/null",unit);reload();document=read(paths.dataDir/"journal.json");
    result=applySysctlOwned(journal,first,key,"1",options,{},admission);
    check(!result.ok&&!fs::exists(options.platform.managedConfigPath)&&document==read(paths.dataDir/"journal.json"),"masked loader mutated state");
    fs::remove(unit);reload();check(admission(error),error);
    const fs::path dropin="/etc/systemd/system/systemd-sysctl.service.d/fic-native-test.conf";
    fs::create_directories(dropin.parent_path());
    write(dropin,"[Service]\nExecStart=\nExecStart="+binary.string()+" --prefix=/net/ipv4\n");reload();
    result=applySysctlOwned(journal,first,key,"1",options,{},admission);
    check(!result.ok&&!fs::exists(options.platform.managedConfigPath)&&document==read(paths.dataDir/"journal.json"),"custom loader arguments bypassed admission");
    fs::remove(dropin);reload();check(admission(error),error);
    write("/proc/sys/net/ipv4/conf/fic.test/forwarding","0");
    write("/proc/sys/net/ipv4/conf/lo/forwarding","0");
    write("/etc/sysctl.d/30-dotted.conf","net.ipv4.conf.fic/test.forwarding=1\nnet.ipv4.conf.lo.forwarding=1\n");
    check(reapplySysctlPrefix(resolver,"net/ipv4/conf/fic.test/forwarding",error),error);
    check(read("/proc/sys/net/ipv4/conf/fic.test/forwarding")=="1\n"&&read("/proc/sys/net/ipv4/conf/lo/forwarding")=="0\n","native helper lost literal interface dot or wrote another interface");
    std::cout<<nlohmann::json{{"platform",profile.id},{"status","PASS"},{"binary",binary.string()},
        {"owned_compliant_apply",true},{"runtime_refresh",true},{"no_op",true},{"prefix_runtime_no_unrelated_write",true},
        {"no_source_runtime_kept",true},{"late_file_refusal",true},{"same_name_null_mask",true},
        {"native_failure_warning_after_release",true},{"sibling_and_last_owner_release",true},{"repeated_release",true},{"masked_and_custom_loader_refused_before_mutation",true},{"dotted_interface_native_helper",true}}.dump()<<'\n';
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
