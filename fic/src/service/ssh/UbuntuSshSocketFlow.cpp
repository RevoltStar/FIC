#include "service/ssh/UbuntuSshSocketFlow.h"
#include "service/ssh/SshListenerProof.h"
#include "service/ssh/SshVerifiedInputClosure.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <memory>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>

namespace fic::service::ssh::detail {
namespace {
using namespace listener;
namespace d=fic::service::detail;
using J=nlohmann::json;
[[noreturn]] void fail(const std::string& why,ActivationStatus status=ActivationStatus::UnsupportedConfiguration) {throw d::Failure(status,why);}
J value(const d::LaunchContract& c,const std::string& key) {return J::parse(c.at("launch."+key)).at("value");}
std::chrono::milliseconds remaining(std::chrono::steady_clock::time_point deadline) {
    const auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
    if(ms.count()<=0)fail("Ubuntu socket proof deadline exceeded",ActivationStatus::TimedOut);return ms;
}
std::string generator() {
    std::string error;const auto profile=fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver resolver(profile.executables);std::filesystem::path executable;
    if(!resolver.resolve(fic::platform::ExecutableId::SshSocketGenerator,executable,error)||
       executable!="/usr/lib/systemd/system-generators/sshd-socket-generator"||!CommandHashStore::verifyHash(executable,error))
        fail("Ubuntu socket generator executable trust unproven");
    for(const auto* parent:{"/run/systemd/system-generators","/etc/systemd/system-generators","/usr/local/lib/systemd/system-generators"}) {
        struct stat st{};const auto override=std::filesystem::path(parent)/"sshd-socket-generator";
        if(::lstat(override.c_str(),&st)==0||errno!=ENOENT)fail("Ubuntu socket generator override/mask unsupported");
    }
    auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=1024*1024;
    return d::fingerprintUnitSource(root.get(),executable.string(),budget);
}
void descriptionDropIn(const std::string& path) {
    auto file=d::openAbsolute(path,O_RDONLY);std::uint64_t budget=65536;auto tree=d::readTree(file.get(),ControlledPathKind::File,budget);
    std::istringstream input(tree.files.at(""));std::string line,section;
    while(std::getline(input,line)) {
        auto first=line.find_first_not_of(" \t");if(first==std::string::npos||line[first]=='#'||line[first]==';')continue;
        line=line.substr(first);
        if(line=="[Unit]"){section="Unit";continue;}
        if(section!="Unit"||line.rfind("Description=",0)!=0||line.find_first_of("\\%\r")!=std::string::npos)
            fail("unsupported administrative SSH socket drop-in");
    }
}
void validateSocket(const d::LaunchContract& c) {
    if(value(c,"Id")!="ssh.socket"||value(c,"LoadState")!="loaded"||value(c,"UnitFileState")!="enabled"||
       value(c,"NeedDaemonReload")!=false||value(c,"Transient")!=false||value(c,"SourcePath")!=""||
       value(c,"Triggers")!=J::array({"ssh.service"}))fail("Ubuntu socket admission unsupported/disabled/stale");
    const auto fragment=value(c,"FragmentPath").get<std::string>();
    if(fragment!="/usr/lib/systemd/system/ssh.socket"&&fragment!="/lib/systemd/system/ssh.socket")fail("vendor SSH socket required");
    if(value(c,"Accept")!=false||value(c,"FreeBind")!=true||value(c,"BindIPv6Only")!="ipv6-only"||value(c,"ReusePort")!=false||
       value(c,"SocketProtocol")!=0||value(c,"BindToDevice")!=""||!value(c,"Symlinks").empty()||value(c,"FileDescriptorName")!="ssh.socket")
        fail("Ubuntu socket delivery/bind profile unsupported");
    for(const auto* command:{"ExecStartPre","ExecStartPost","ExecStopPre","ExecStopPost"})if(!value(c,command).empty())fail("socket execution hooks unsupported");
    const auto drops=value(c,"DropInPaths");
    for(const auto& item:drops) {
        const auto path=item.get<std::string>();
        if(path=="/run/systemd/generator/ssh.socket.d/addresses.conf")continue;
        if(path.rfind("/etc/systemd/system/ssh.socket.d/",0)!=0||std::filesystem::path(path).extension()!=".conf")fail("unknown generated/administrative socket source");
        descriptionDropIn(path);
        auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=1024*1024;
        if(d::fingerprintUnitSource(root.get(),path,budget)!=c.at("launch.file:"+path))fail("socket drop-in changed",ActivationStatus::InterferenceDetected);
    }
    struct stat marker{};if(::lstat("/etc/ssh/sshd_not_to_be_run",&marker)==0||errno!=ENOENT)fail("SSH activation condition is disabled/unknown");
    struct stat self{},manager{};
    if(::stat("/proc/self/ns/net",&self)||::stat("/proc/1/ns/net",&manager)||self.st_dev!=manager.st_dev||self.st_ino!=manager.st_ino)
        fail("activator/manager network namespace mismatch");
}
std::vector<std::string> loadedEndpoints(const d::LaunchContract& c) {
    std::vector<std::string> result;
    for(const auto& entry:value(c,"Listen")) {
        if(!entry.is_array()||entry.size()!=2||entry[0]!="Stream"||!entry[1].is_string())fail("only typed TCP Stream listeners are supported");
        result.push_back(UbuntuSshSocketFlow::parseEndpoint(entry[1].get<std::string>()));
    }
    if(result.empty()||result.size()>16)fail("listener count outside supported bound");
    std::sort(result.begin(),result.end());if(std::adjacent_find(result.begin(),result.end())!=result.end())fail("duplicate loaded listener");return result;
}
d::LaunchContract stableSocket(d::LaunchContract contract,bool regeneration=false) {
    contract.erase("launch.Job");contract.erase("launch.SubState");
    if(regeneration) {
        contract.erase("launch.Listen");contract.erase("launch.InvocationID");
        contract.erase("launch.file:/run/systemd/generator/ssh.socket.d/addresses.conf");
        auto paths=value(contract,"DropInPaths");
        paths.erase(std::remove(paths.begin(),paths.end(),J("/run/systemd/generator/ssh.socket.d/addresses.conf")),paths.end());
        auto prop=J::parse(contract.at("launch.DropInPaths"));prop["value"]=paths;contract["launch.DropInPaths"]=prop.dump();
    }
    return contract;
}
void inherited(const d::ServiceState& service,const std::map<std::string,std::uint64_t>& expected) {
    const auto pid=std::stoul(service.at("MainPID"));if(!pid)fail("SSH runtime PID absent",ActivationStatus::ReadinessUnconfirmed);
    const auto fds=descriptors(pid);const auto kernel=kernelListeners();std::set<std::uint64_t> wanted,actual;
    for(const auto& [_,inode]:expected)wanted.insert(inode);
    for(const auto& [_,inodes]:kernel)for(auto inode:inodes)if(fds.count(inode))actual.insert(inode);
    if(actual!=wanted)fail("SSH listener FD inheritance mismatch/extra listener",ActivationStatus::InterferenceDetected);
}
void generatedMatches(const d::LaunchContract& c,const std::vector<std::string>& desired) {
    const std::string path="/run/systemd/generator/ssh.socket.d/addresses.conf";
    if(desired==std::vector<std::string>{"0.0.0.0:22","[::]:22"}) {
        struct stat st{};if(::lstat(path.c_str(),&st)==0||errno!=ENOENT)fail("unexpected default generator output");return;
    }
    auto file=d::openAbsolute(path,O_RDONLY);std::uint64_t budget=65536;const auto tree=d::readTree(file.get(),ControlledPathKind::File,budget);
    const std::string header="# Automatically generated by sshd-socket-generator\n\n[Socket]\nListenStream=\n";
    const auto bytes=tree.files.at("");if(bytes.rfind(header,0)!=0)fail("unsupported native generator output grammar");
    std::istringstream input(bytes.substr(header.size()));std::string line;std::vector<std::string> actual;
    while(std::getline(input,line)) {
        if(line.rfind("ListenStream=",0)!=0)fail("unexpected generated directive");
        actual.push_back(UbuntuSshSocketFlow::parseEndpoint(line.substr(13)));
    }
    std::sort(actual.begin(),actual.end());
    if(actual!=desired)fail("native generator output differs from protected SSH endpoints",ActivationStatus::InterferenceDetected);
    auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);budget=1024*1024;
    if(c.at("launch.file:"+path)!=d::fingerprintUnitSource(root.get(),path,budget))fail("loaded/generated socket source mismatch",ActivationStatus::InterferenceDetected);
}
}
std::string UbuntuSshSocketFlow::parseEndpoint(const std::string& text) {return encode(decode(text));}
UbuntuSshSocketFlow::Snapshot UbuntuSshSocketFlow::observe(std::chrono::steady_clock::time_point deadline) {
    while(true) {
        auto c=d::readSshSocketContract(deadline);validateSocket(c);
        const auto active=value(c,"ActiveState").get<std::string>(),sub=value(c,"SubState").get<std::string>();
        const auto job=value(c,"Job");
        if(active=="activating"||active=="deactivating"||job.at(0)!=0) {std::this_thread::sleep_for(std::min(remaining(deadline),std::chrono::milliseconds(50)));continue;}
        if(active!="active"||(sub!="listening"&&sub!="running"))fail("Ubuntu socket not active/listening",ActivationStatus::ReadinessUnconfirmed);
        const auto endpoints=loadedEndpoints(c);const auto kernel=kernelListeners();const auto manager=descriptors(1);
        Snapshot out;out.unit=std::move(c);out.generator=generator();
        for(const auto& endpoint:endpoints) {
            const auto found=kernel.find(endpoint);
            if(found==kernel.end()||found->second.size()!=1||!manager.count(found->second.front()))fail("controlled socket kernel inode/owner not proven",ActivationStatus::ReadinessUnconfirmed);
            out.listeners.emplace(endpoint,found->second.front());
        }
        if(out.unit!=d::readSshSocketContract(deadline))fail("socket changed during kernel proof",ActivationStatus::InterferenceDetected);
        return out;
    }
}
UbuntuSshSocketFlow::UbuntuSshSocketFlow(std::chrono::steady_clock::time_point deadline):deadline_(deadline),original_(observe(deadline)) {}
void UbuntuSshSocketFlow::prepareRuntimeDirectory() {
    const auto launch=d::readLaunchContract("ssh.service",std::chrono::steady_clock::now()+std::chrono::seconds(10));
    if(value(launch,"RuntimeDirectory")!=J::array({"sshd"})||value(launch,"RuntimeDirectoryMode")!=0755||value(launch,"User")!=""||value(launch,"Group")!="")
        fail("unsupported SSH runtime directory contract");
    auto parent=d::openAbsolute("/run",O_RDONLY|O_DIRECTORY);
    const bool created=::mkdirat(parent.get(),"sshd",0755)==0;
    if(!created&&errno!=EEXIST)fail("cannot prepare stock SSH runtime directory");
    d::Fd fd(::openat(parent.get(),"sshd",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    if(!fd)fail("SSH runtime directory symlink/unavailable");
    if(created&&(::fchown(fd.get(),0,0)||::fchmod(fd.get(),0755)))fail("cannot initialize created SSH runtime directory");
    const auto id=d::identity(fd.get());if(id.uid!=0||id.gid!=0||(id.mode&07777)!=0755)fail("unsafe existing SSH runtime directory; not repaired");
}
std::vector<std::string> UbuntuSshSocketFlow::effectiveEndpoints(SshRuntime& runtime) {return listener::effectiveEndpoints(runtime);}
std::map<std::string,std::string> UbuntuSshSocketFlow::combined(const d::ServiceState& state) const {
    const auto current=observe(deadline_);if(state.at("ActiveState")=="active")inherited(state,current.listeners);
    auto proof=state.properties;
    for(const auto& [key,text]:current.unit)proof.emplace("socket:"+key,text);
    proof["socket:kernel"]=J(current.listeners).dump();proof["socket:generator"]=current.generator;return proof;
}
void UbuntuSshSocketFlow::command(const std::vector<std::string>& args) const {
    const auto profile=fic::platform::makeBuildPlatformProfile();fic::platform::PlatformExecutableResolver resolver(profile.executables);
    std::filesystem::path ctl;std::string error;if(!resolver.resolve(fic::platform::ExecutableId::Systemctl,ctl,error))fail("systemctl unavailable");
    ProcessOptions options;options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"}};options.timeout=remaining(deadline_);options.maxOutputBytes=65536;
    const auto result=VerifiedProcessExecutor::execute(ctl,args,options);
    if(!result.success())fail("Ubuntu SSH fixed lifecycle action failed",result.timedOut?ActivationStatus::TimedOut:ActivationStatus::RestartFailed);
}
void UbuntuSshSocketFlow::activate(SshRuntime& runtime,d::SystemdActivation& service,const d::ServiceState& originalService) {
    if(service.current().properties!=originalService.properties||!(observe(deadline_)==original_))fail("Ubuntu service/socket changed before activation",ActivationStatus::InterferenceDetected);
    const auto desired=effectiveEndpoints(runtime);std::vector<std::string> loaded;for(const auto& [key,_]:original_.listeners)loaded.push_back(key);
    const bool changed=desired!=loaded;
    if(changed) {
        command({"--no-ask-password","--job-mode=fail","stop","ssh.service"});
        command({"--no-ask-password","daemon-reload"});
        const auto regenerated=d::readSshSocketContract(deadline_);validateSocket(regenerated);generatedMatches(regenerated,desired);
        if(stableSocket(regenerated,true)!=stableSocket(original_.unit,true))fail("socket launch/source changed during generator reload",ActivationStatus::InterferenceDetected);
        if(loadedEndpoints(regenerated)!=desired||generator()!=original_.generator)fail("generator/loaded socket mismatch",ActivationStatus::InterferenceDetected);
        command({"--no-ask-password","--job-mode=fail","restart","ssh.socket"});
    } else generatedMatches(original_.unit,desired);
    const auto next=observe(deadline_);std::vector<std::string> current;for(const auto& [key,_]:next.listeners)current.push_back(key);
    if(current!=desired)fail("old/extra kernel listener after socket activation",ActivationStatus::ReadinessUnconfirmed);
    if(changed) {
        const auto all=kernelListeners();for(const auto& [_,old]:original_.listeners)for(const auto& [__,inodes]:all)
            if(std::find(inodes.begin(),inodes.end(),old)!=inodes.end())fail("old controlled listening inode survived",ActivationStatus::InterferenceDetected);
    }
    activated_=next;
    const auto state=service.current();
    if(!changed&&state.at("ActiveState")=="active") {service.restart();return;}
    // Actual socket activation via a normal local client, never StartUnit.
    const auto endpoint=decode(desired.front());
    connection_=d::Fd(::socket(endpoint.family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0));if(!connection_)fail("local socket trigger unavailable");
    sockaddr_storage storage{};socklen_t length;
    if(endpoint.family==AF_INET) {auto& a=reinterpret_cast<sockaddr_in&>(storage);a.sin_family=AF_INET;a.sin_port=htons(endpoint.port);::inet_pton(AF_INET,endpoint.ip=="0.0.0.0"?"127.0.0.1":endpoint.ip.c_str(),&a.sin_addr);length=sizeof a;}
    else {auto& a=reinterpret_cast<sockaddr_in6&>(storage);a.sin6_family=AF_INET6;a.sin6_port=htons(endpoint.port);::inet_pton(AF_INET6,endpoint.ip=="::"?"::1":endpoint.ip.c_str(),&a.sin6_addr);length=sizeof a;}
    if(::connect(connection_.get(),reinterpret_cast<sockaddr*>(&storage),length)&&errno!=EINPROGRESS)fail("normal Ubuntu socket activation trigger failed",ActivationStatus::RestartFailed);
    pollfd poll{connection_.get(),POLLOUT,0};if(::poll(&poll,1,int(remaining(deadline_).count()))<=0)fail("socket trigger deadline",ActivationStatus::TimedOut);
    int error=0;socklen_t size=sizeof error;if(::getsockopt(connection_.get(),SOL_SOCKET,SO_ERROR,&error,&size)||error)fail("socket trigger connection unproven",ActivationStatus::RestartFailed);
}
void UbuntuSshSocketFlow::ready(const d::ServiceState& state) {
    promoted_=observe(deadline_);
    if(stableSocket(promoted_.unit)!=stableSocket(activated_.unit)||promoted_.listeners!=activated_.listeners||promoted_.generator!=activated_.generator)
        fail("controlled socket changed between activation and readiness",ActivationStatus::InterferenceDetected);
    inherited(state,promoted_.listeners);promotedKnown_=true;
}
void UbuntuSshSocketFlow::confirm(const d::ServiceState& state) {
    if(!promotedKnown_||!(observe(deadline_)==promoted_))fail("socket/generator identity changed after readiness/cleanup",ActivationStatus::InterferenceDetected);
    inherited(state,promoted_.listeners);
}
void UbuntuSshSocketFlow::requireOffline(std::chrono::steady_clock::time_point deadline) {
    const auto socket=d::readSshSocketContract(deadline);
    if(value(socket,"ActiveState")!="inactive"||value(socket,"Job").at(0)!=0)
        fail("Ubuntu active/pending socket rollback unsupported; ownership retained");
    const auto profile=fic::platform::makeBuildPlatformProfile();fic::platform::PlatformExecutableResolver resolver(profile.executables);
    std::filesystem::path ctl;std::string error;if(!resolver.resolve(fic::platform::ExecutableId::Systemctl,ctl,error))fail("systemctl unavailable");
    ProcessOptions options;options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"}};options.timeout=remaining(deadline);options.maxOutputBytes=65536;
    const auto result=VerifiedProcessExecutor::execute(ctl,{"--system","--no-pager","--no-ask-password","show","--property=Id,ActiveState,SubState,MainPID,Job","--","ssh.service"},options);
    if(!result.success())fail("offline SSH service proof unavailable");
    std::istringstream input(result.standardOutput);std::map<std::string,std::string> fields;std::string line;
    while(std::getline(input,line)) {const auto pos=line.find('=');if(pos==std::string::npos||!fields.emplace(line.substr(0,pos),line.substr(pos+1)).second)fail("ambiguous offline service proof");}
    if(fields.size()!=5||fields.at("Id")!="ssh.service"||fields.at("ActiveState")!="inactive"||fields.at("SubState")!="dead"||fields.at("MainPID")!="0"||!fields.at("Job").empty())
        fail("Ubuntu rollback requires inactive service AND socket; ownership retained");
}
}
