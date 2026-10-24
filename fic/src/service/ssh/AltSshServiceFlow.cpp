#include "service/ssh/AltSshServiceFlow.h"
#include "service/ssh/SshListenerProof.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
namespace fic::service::ssh::detail {
namespace {
namespace d=fic::service::detail;
using J=nlohmann::json;
[[noreturn]] void fail(const std::string& text,ActivationStatus status=ActivationStatus::InterferenceDetected) {throw d::Failure(status,text);}
std::string keygenToken() {
    const auto profile=fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver resolver(profile.executables);std::filesystem::path path;std::string error;
    if(profile.id!="alt-p11"||!resolver.resolve(fic::platform::ExecutableId::SshKeygen,path,error)||path!="/usr/bin/ssh-keygen"||!CommandHashStore::verifyHash(path,error))
        fail("ALT stock ssh-keygen executable trust unproven",ActivationStatus::UnsupportedConfiguration);
    auto root=d::openAbsolute("/",O_PATH|O_DIRECTORY);std::uint64_t budget=16*1024*1024;
    return d::fingerprintUnitSource(root.get(),path,budget);
}
bool executable(const d::ServiceState& state) {
    std::string error;if(!CommandHashStore::verifyHash("/usr/sbin/sshd",error))fail("ALT sshd executable trust unproven",ActivationStatus::UnsupportedConfiguration);
    auto disk=d::openAbsolute("/usr/sbin/sshd",O_RDONLY);struct stat expected{},actual{};
    return !::fstat(disk.get(),&expected)&&!::stat(("/proc/"+state.at("MainPID")+"/exe").c_str(),&actual)&&expected.st_dev==actual.st_dev&&expected.st_ino==actual.st_ino;
}
std::map<std::string,std::uint64_t> owned(const d::ServiceState& state) {
    return listener::ownedListeners(std::stoul(state.at("MainPID")));
}
std::vector<std::string> endpoints(const std::map<std::string,std::uint64_t>& values) {
    std::vector<std::string> out;for(const auto& [key,_]:values)out.push_back(key);return out;
}
bool banner(const std::string& text,std::chrono::steady_clock::time_point deadline) {
    const auto e=listener::decode(text);d::Fd fd(::socket(e.family,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0));if(!fd)fail("ALT local readiness socket unavailable");
    sockaddr_storage storage{};socklen_t length;
    if(e.family==AF_INET) {auto& a=reinterpret_cast<sockaddr_in&>(storage);a.sin_family=AF_INET;a.sin_port=htons(e.port);::inet_pton(AF_INET,e.ip=="0.0.0.0"?"127.0.0.1":e.ip.c_str(),&a.sin_addr);length=sizeof a;}
    else {auto& a=reinterpret_cast<sockaddr_in6&>(storage);a.sin6_family=AF_INET6;a.sin6_port=htons(e.port);::inet_pton(AF_INET6,e.ip=="::"?"::1":e.ip.c_str(),&a.sin6_addr);length=sizeof a;}
    const auto wait=[&](short events) {
        auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if(ms<=0)throw d::Failure(ActivationStatus::TimedOut,"ALT SSH readiness deadline");
        pollfd p{fd.get(),events,0};return ::poll(&p,1,int(std::min<std::int64_t>(ms,500)))>0;
    };
    if(::connect(fd.get(),reinterpret_cast<sockaddr*>(&storage),length)&&errno!=EINPROGRESS)return false;
    if(!wait(POLLOUT))return false;int error=0;socklen_t size=sizeof error;
    if(::getsockopt(fd.get(),SOL_SOCKET,SO_ERROR,&error,&size)||error)return false;
    std::string bytes;char buffer[128];
    while(bytes.size()<255) {
        if(!wait(POLLIN))return false;
        const auto n=::recv(fd.get(),buffer,sizeof buffer,0);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;if(n<=0)return false;bytes.append(buffer,n);
        if(bytes.find('\n')!=std::string::npos)return bytes.rfind("SSH-2.0-OpenSSH_",0)==0;
    }
    return false;
}
}
AltSshServiceFlow::AltSshServiceFlow(const d::ServiceState& state,std::chrono::steady_clock::time_point deadline)
    :deadline_(deadline),original_(owned(state)),keygen_(keygenToken()) {
    if(original_.empty()||original_.size()>16||!executable(state))fail("ALT initial runtime/listener not ready",ActivationStatus::ReadinessUnconfirmed);
}
bool AltSshServiceFlow::initiallyReady(const d::ServiceState& state) {
    if(!executable(state))return false;
    try {const auto current=owned(state);return !current.empty()&&current.size()<=16;}
    catch(const std::filesystem::filesystem_error&) {return false;}
}
std::map<std::string,std::string> AltSshServiceFlow::combined(const d::ServiceState& state,std::chrono::steady_clock::time_point) {
    if(!initiallyReady(state))fail("ALT initial runtime/listener not proven",ActivationStatus::ReadinessUnconfirmed);
    auto proof=state.properties;proof["alt:listeners"]=J(owned(state)).dump();proof["alt:keygen"]=keygenToken();return proof;
}
void AltSshServiceFlow::published(SshRuntime& runtime) {
    if(keygenToken()!=keygen_)fail("ALT keygen changed before restart");
    expected_=listener::effectiveEndpoints(runtime);
}
bool AltSshServiceFlow::readyCandidate(const d::ServiceState& state,std::chrono::steady_clock::time_point deadline) {
    if(!executable(state))return false;
    std::map<std::string,std::uint64_t> current;
    try {current=owned(state);}catch(const std::filesystem::filesystem_error&) {return false;}
    if(endpoints(current)!=expected_)return false;
    const auto all=listener::kernelListeners();
    for(const auto& [_,old]:original_)for(const auto& [__,inodes]:all)
        if(std::find(inodes.begin(),inodes.end(),old)!=inodes.end())return false;
    const auto token=J({state.at("InvocationID"),state.at("MainPID"),current}).dump();
    if(candidate_!=token) {
        if(!banner(expected_.front(),deadline))return false;
        if(owned(state)!=current)fail("ALT listener changed during protocol readiness");
        candidate_=token;
    }
    return true;
}
void AltSshServiceFlow::ready(const d::ServiceState& state) {
    if(!readyCandidate(state,deadline_))fail("ALT runtime/listener readiness disappeared",ActivationStatus::ReadinessUnconfirmed);
    promoted_=owned(state);promotedKnown_=true;
}
void AltSshServiceFlow::confirm(const d::ServiceState& state) const {
    if(!promotedKnown_||owned(state)!=promoted_||!executable(state)||keygenToken()!=keygen_)fail("ALT runtime/listener/executable changed after readiness");
}
void AltSshServiceFlow::requireOffline(std::chrono::steady_clock::time_point deadline) {
    const auto state=d::readAltSshRuntime(deadline);const auto v=[&](const char* key){return J::parse(state.at(std::string("launch.")+key)).at("value");};
    if(v("Id")!="sshd.service"||v("LoadState")!="loaded"||v("ActiveState")!="inactive"||v("SubState")!="dead"||v("MainPID")!=0||v("Job").at(0)!=0||!v("TriggeredBy").empty())
        fail("ALT rollback requires proven offline service; active/unknown runtime retains ownership",ActivationStatus::UnsupportedConfiguration);
}
}
