#include "daemon/PackageWritersQuiescence.h"
#include "daemon/PackageWriterUnits.h"
#include "daemon/StoppedWritersProof.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/process/ProcessExecutor.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
constexpr auto units=PackageWriterUnits;
bool fail(std::string& error,const std::string& text){error=text;return false;}
bool sameNamespace(const char* name) {
    struct stat a{},b{};
    const auto self=std::string("/proc/self/ns/")+name,manager=std::string("/proc/1/ns/")+name;
    return ::stat(self.c_str(),&a)==0&&::stat(manager.c_str(),&b)==0&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino;
}
bool managerEnvironment(std::string& error) {
    if(::geteuid()!=0)return fail(error,"writer proof requires root");
    std::ifstream comm("/proc/1/comm");std::string name;std::getline(comm,name);
    struct statfs fs{};
    if(name!="systemd" || !sameNamespace("mnt") || !sameNamespace("cgroup") ||
        ::statfs("/sys/fs/cgroup",&fs) || fs.f_type!=CGROUP2_SUPER_MAGIC)
        return fail(error,"lifecycle requires systemd PID1, shared manager namespaces and cgroup v2");
    return true;
}
bool run(const fic::platform::PlatformExecutableResolver& executables,const std::vector<std::string>& args,
         std::chrono::steady_clock::time_point deadline,std::string& output,std::string& error) {
    std::filesystem::path executable;
    if(!executables.resolve(fic::platform::ExecutableId::Systemctl,executable,error))return false;
    const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
    if(remaining.count()<=0)return fail(error,"writer proof deadline exceeded");
    ProcessOptions options;options.timeout=std::min(remaining,std::chrono::milliseconds(5000));
    options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
    options.maxOutputBytes=65536;
    const auto result=ProcessExecutor::execute(executable,args,options);
    if(!result.success())return fail(error,"systemd writer operation failed: "+result.error+" "+result.standardError);
    output=result.standardOutput;error.clear();return true;
}
bool emptyWriterCgroups(std::chrono::steady_clock::time_point deadline,std::string& error) {
    // Inspect actual cgroup trees, not only systemd ActiveState/MainPID. A
    // stopped KillMode=process unit can leave helpers behind in its cgroup.
    const std::filesystem::path root="/sys/fs/cgroup";
    struct stat rootInfo{};if(::stat(root.c_str(),&rootInfo))return fail(error,"cannot inspect cgroup root");
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(root,std::filesystem::directory_options::none,ec),end;
    if(ec)return fail(error,"cannot enumerate cgroup hierarchy");
    std::size_t count=0,directories=0;
    for(;it!=end;it.increment(ec)) {
        if(ec || ++count>262144 || std::chrono::steady_clock::now()>=deadline)return fail(error,"cgroup inventory incomplete/budget exceeded");
        const auto status=it->symlink_status(ec);if(ec)return fail(error,"cgroup metadata unprovable");
        if(std::filesystem::is_symlink(status))return fail(error,"unexpected cgroup symlink");
        if(!std::filesystem::is_directory(status))continue;
        if(++directories>4096 || it.depth()>64)return fail(error,"cgroup hierarchy depth exceeded");
        struct stat info{};struct statfs fs{};
        if(::lstat(it->path().c_str(),&info)||::statfs(it->path().c_str(),&fs)||
            fs.f_type!=CGROUP2_SUPER_MAGIC||info.st_dev!=rootInfo.st_dev)return fail(error,"cgroup mount identity changed");
        const auto name=it->path().filename().string();
        if(std::find(units.begin(),units.end(),name)==units.end())continue;
        std::ifstream events(it->path()/"cgroup.events");std::array<char,4097> bytes{};
        events.read(bytes.data(),bytes.size());
        if(events.bad()||events.gcount()>=static_cast<std::streamsize>(bytes.size()))return fail(error,"cgroup events unreadable/oversized");
        std::istringstream fields(std::string(bytes.data(),events.gcount()));std::string key;unsigned value;bool populated=false,found=false;
        while(fields>>key>>value) {
            if(key=="populated") {if(found||value>1)return fail(error,"invalid cgroup populated proof");found=true;populated=value!=0;}
        }
        if(!fields.eof() || !found || populated)return fail(error,"FIC writer cgroup is populated/unprovable: "+it->path().string());
    }
    if(ec)return fail(error,"cgroup enumeration failed");
    return true;
}
}
bool PackageWritersQuiescence::validateEnvironment(std::string& error) const {
    return managerEnvironment(error);
}
bool PackageWritersQuiescence::requestStopBeforeAdmission(std::chrono::steady_clock::time_point deadline,std::string& error) const {
    if(!managerEnvironment(error))return false;
    std::vector<std::string> args{"stop"};
    for(const auto* unit:units) {
        std::string output;WriterUnitFacts facts;
        if(!run(executables_,{"show",unit,"--no-pager","--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job"},deadline,output,error)||
           !inspectWriterUnit(unit,output,facts,error))return false;
        if(proveStoppedUnit(unit,output,error))continue;
        args.push_back(unit);
    }
    if(args.size()==1){error.clear();return true;}
    std::string output;return run(executables_,args,deadline,output,error);
}
bool PackageWritersQuiescence::stopAndProve(const DaemonInstanceLock& guard,const PackageUnitMasks& masks,
    const std::string& id,const std::vector<LegacyWriterImage>& images,
    std::chrono::steady_clock::time_point deadline,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"writer stop lacks daemon admission");
    if(!managerEnvironment(error)||!masks.provePublished(id,error))return false;
    std::string output;
    if(!run(executables_,{"daemon-reload"},deadline,output,error) ||
       !requestStopBeforeAdmission(deadline,error))return false;
    return prove(guard,masks,id,images,deadline,error);
}
bool PackageWritersQuiescence::prove(const DaemonInstanceLock& guard,const PackageUnitMasks& masks,
    const std::string& id,const std::vector<LegacyWriterImage>& images,
    std::chrono::steady_clock::time_point deadline,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"writer proof lacks daemon admission");
    if(!managerEnvironment(error)||!masks.provePublished(id,error))return false;
    for(const auto* unit:units) {
        std::string output;
        if(!run(executables_,{"show",unit,"--no-pager","--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job"},deadline,output,error)||
            !proveStoppedUnit(unit,output,error))return false;
    }
    if(!emptyWriterCgroups(deadline,error)||!proveNoPackageWriterProcesses(images,deadline,error))return false;
    error.clear();return true;
}
}
