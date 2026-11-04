#include "modules/sysctl/SysctlSystemd.h"
#include "modules/sysctl/SysctlKey.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <systemd/sd-bus.h>
#include <sys/stat.h>
#include <memory>
#include <stdexcept>
#include <cstdlib>
namespace {
using Bus=std::unique_ptr<sd_bus,decltype(&sd_bus_unref)>;
using Message=std::unique_ptr<sd_bus_message,decltype(&sd_bus_message_unref)>;
constexpr auto name="org.freedesktop.systemd1";
constexpr auto service="org.freedesktop.systemd1.Service";
void need(bool ok,const std::string& why){if(!ok)throw std::runtime_error(why);}
Message property(sd_bus* bus,const char* object,const char* interface,const char* field,const char* type) {
    sd_bus_message* raw=nullptr;
    need(sd_bus_call_method(bus,name,object,"org.freedesktop.DBus.Properties","Get",nullptr,&raw,"ss",interface,field)>=0,"SYSCTL unit property unavailable");
    Message reply(raw,sd_bus_message_unref);char kind;const char* contents=nullptr;
    need(sd_bus_message_peek_type(reply.get(),&kind,&contents)>0&&kind=='v'&&(!type||std::string(contents)==type),"SYSCTL unit property type mismatch");
    need(sd_bus_message_enter_container(reply.get(),'v',contents)>0,"SYSCTL property variant unavailable");
    return reply;
}
void emptyString(sd_bus* bus,const char* object,const char* field) {
    auto reply=property(bus,object,service,field,"s");const char* value=nullptr;
    need(sd_bus_message_read(reply.get(),"s",&value)>0&&value&&!*value,"SYSCTL custom root unsupported");
}
void emptyArray(sd_bus* bus,const char* object,const char* field) {
    auto reply=property(bus,object,service,field,nullptr);char type;const char* contents=nullptr;
    need(sd_bus_message_peek_type(reply.get(),&type,&contents)>0&&type=='a',"SYSCTL unit array unproven");
    need(sd_bus_message_enter_container(reply.get(),'a',contents)>0&&sd_bus_message_at_end(reply.get(),0)>0,"SYSCTL unit remap/extra command unsupported");
}
}
std::string sysctlNativePrefix(const std::string& key) {
    const auto canonical=fic::sysctl::internalKeyToCanonicalPath(key);
    if(canonical.empty()||canonical.size()>4096||canonical.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")!=std::string::npos)throw std::runtime_error("invalid SYSCTL prefix");
    for(const auto& part:fic::sysctl::splitKey(canonical,'/'))if(part.empty()||part=="."||part=="..")throw std::runtime_error("invalid SYSCTL prefix component");
    return "/"+canonical; // first slash protects literal dots from systemd normalization
}
bool sysctlLoaderAdmission(const fic::platform::PlatformExecutableResolver& resolver,std::string& error) {
    try {
        std::filesystem::path executable;need(resolver.resolve(fic::platform::ExecutableId::SystemdSysctl,executable,error),error);
        need(CommandHashStore::verifyHash(executable.string(),error),error);
        struct stat self{},manager{};
        need(::stat("/proc/self/ns/mnt",&self)==0&&::stat("/proc/1/ns/mnt",&manager)==0&&self.st_dev==manager.st_dev&&self.st_ino==manager.st_ino,"SYSCTL manager mount namespace differs");
        sd_bus* raw=nullptr;need(sd_bus_open_system(&raw)>=0,"SYSCTL system bus unavailable");Bus bus(raw,sd_bus_unref);
        sd_bus_message* loaded=nullptr;
        need(sd_bus_call_method(bus.get(),name,"/org/freedesktop/systemd1","org.freedesktop.systemd1.Manager","LoadUnit",nullptr,&loaded,"s","systemd-sysctl.service")>=0,"SYSCTL native loader unit unavailable");
        Message load(loaded,sd_bus_message_unref);const char* object=nullptr;need(sd_bus_message_read(load.get(),"o",&object)>0,"SYSCTL unit identity unavailable");
        auto state=property(bus.get(),object,"org.freedesktop.systemd1.Unit","LoadState","s");const char* value=nullptr;
        need(sd_bus_message_read(state.get(),"s",&value)>0&&std::string(value)=="loaded","SYSCTL loader masked/unloaded");
        emptyString(bus.get(),object,"RootDirectory");emptyString(bus.get(),object,"RootImage");
        for(const auto* field:{"BindPaths","BindReadOnlyPaths","TemporaryFileSystem","InaccessiblePaths","MountImages","ExtensionImages","ExtensionDirectories","ExecStartPre","ExecStartPost"})emptyArray(bus.get(),object,field);
        auto command=property(bus.get(),object,service,"ExecStart","a(sasbttttuii)");
        need(sd_bus_message_enter_container(command.get(),'a',"(sasbttttuii)")>0&&sd_bus_message_enter_container(command.get(),'r',"sasbttttuii")>0,"SYSCTL native ExecStart unavailable");
        const char* path=nullptr;need(sd_bus_message_read(command.get(),"s",&path)>0,"SYSCTL executable unavailable");
        std::error_code ec;const auto canonical=std::filesystem::canonical(path,ec);need(!ec&&canonical==executable,"SYSCTL loader executable differs from platform");
        need(sd_bus_message_enter_container(command.get(),'a',"s")>0,"SYSCTL argv unavailable");const char* argument=nullptr;
        need(sd_bus_message_read(command.get(),"s",&argument)>0&&std::string(argument)==path&&sd_bus_message_at_end(command.get(),0)>0,"SYSCTL loader must read default sysctl.d graph without custom arguments");
        need(sd_bus_message_exit_container(command.get())>=0&&sd_bus_message_skip(command.get(),"bttttuii")>=0&&sd_bus_message_exit_container(command.get())>=0&&sd_bus_message_at_end(command.get(),0)>0,"multiple SYSCTL loader commands unsupported");
        return true;
    } catch(const std::exception& e){error=e.what();return false;}
}
bool reapplySysctlPrefix(const fic::platform::PlatformExecutableResolver& resolver,const std::string& key,std::string& error) {
    try {
        const auto prefix=sysctlNativePrefix(key);struct stat st{};
        // Metadata only: never read runtime values on ownership release. A
        // directory prefix could mutate unrelated keys, so only leaf files run.
        need(::lstat(("/proc/sys"+prefix).c_str(),&st)==0&&S_ISREG(st.st_mode),"released SYSCTL key is not a present leaf; native reapply skipped");
        std::filesystem::path executable;if(!resolver.resolve(fic::platform::ExecutableId::SystemdSysctl,executable,error))return false;
        ProcessOptions options;options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"}};
        options.timeout=std::chrono::seconds(15);options.maxOutputBytes=65536;
        const auto result=VerifiedProcessExecutor::execute(executable.string(),{"--prefix="+prefix},options);
        if(!result.success()){error=result.error+result.standardError+result.standardOutput+"; exit="+std::to_string(result.exitCode);return false;}
        return true;
    } catch(const std::exception& e){error=e.what();return false;}
}
