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

namespace fic::service::ssh::detail::listener {
namespace d=fic::service::detail;
[[noreturn]] static void fail(const std::string& why,ActivationStatus status=ActivationStatus::UnsupportedConfiguration) {throw d::Failure(status,why);}
std::string address(int family,const void* data) {
    char text[INET6_ADDRSTRLEN];if(!::inet_ntop(family,data,text,sizeof text))fail("invalid literal IP endpoint");return text;
}
Endpoint decode(const std::string& text) {
    std::string ip,port;
    if(!text.empty()&&text.front()=='[') {
        const auto end=text.find(']');if(end==std::string::npos||text.substr(end,2)!="]:")fail("unsupported IPv6 listen endpoint");
        ip=text.substr(1,end-1);port=text.substr(end+2);
    } else {
        if(std::count(text.begin(),text.end(),':')!=1)fail("IPv6 endpoint requires brackets");
        const auto end=text.rfind(':');if(end==std::string::npos)fail("listen endpoint lacks port");
        ip=text.substr(0,end);port=text.substr(end+1);
    }
    if(port.empty()||port.size()>5||port.find_first_not_of("0123456789")!=std::string::npos)fail("invalid listen port");
    const auto number=std::stoul(port);if(!number||number>65535)fail("listen port outside supported range");
    in_addr a4{};in6_addr a6{};
    if(::inet_pton(AF_INET,ip.c_str(),&a4)==1)return {AF_INET,address(AF_INET,&a4),unsigned(number)};
    if(::inet_pton(AF_INET6,ip.c_str(),&a6)==1)return {AF_INET6,address(AF_INET6,&a6),unsigned(number)};
    fail("hostname/scoped/rdomain listener is unsupported");
}
std::string encode(const Endpoint& e) {return (e.family==AF_INET?e.ip:"["+e.ip+"]")+":"+std::to_string(e.port);}
std::map<std::string,std::vector<std::uint64_t>> kernelListeners() {
    std::map<std::string,std::vector<std::uint64_t>> result;
    for(const auto& [path,family]:std::vector<std::pair<std::string,int>>{{"/proc/net/tcp",AF_INET},{"/proc/net/tcp6",AF_INET6}}) {
        std::ifstream file(path);if(!file)fail("kernel TCP listener table unavailable");std::string line;std::getline(file,line);unsigned count=0;
        while(std::getline(file,line)) {
            if(++count>65536||line.size()>8192)fail("kernel listener observation bound");
            std::istringstream fields(line);std::vector<std::string> v;std::string token;
            while(fields>>token)v.push_back(token);
            if(v.size()<10)fail("invalid kernel TCP record");if(v[3]!="0A")continue;
            const auto colon=v[1].find(':');if(colon==std::string::npos)fail("invalid kernel endpoint");
            const auto hex=v[1].substr(0,colon);const unsigned words=family==AF_INET?1:4;
            if(hex.size()!=words*8)fail("invalid kernel IP length");std::uint32_t raw[4]{};
            for(unsigned i=0;i<words;++i)raw[i]=std::stoul(hex.substr(i*8,8),nullptr,16);
            const auto ip=address(family,raw);const unsigned port=std::stoul(v[1].substr(colon+1),nullptr,16);
            result[encode({family,ip,port})].push_back(std::stoull(v[9]));
        }
    }
    return result;
}
std::set<std::uint64_t> descriptors(unsigned pid) {
    std::set<std::uint64_t> result;unsigned count=0;
    for(const auto& entry:std::filesystem::directory_iterator("/proc/"+std::to_string(pid)+"/fd")) {
        if(++count>8192)fail("descriptor observation bound");char text[128];
        const auto size=::readlink(entry.path().c_str(),text,sizeof text);
        if(size<0&&errno==ENOENT)continue;if(size<0||size==sizeof text)fail("descriptor identity unavailable");
        const std::string link(text,size);
        if(link.rfind("socket:[",0)==0&&link.back()==']')result.insert(std::stoull(link.substr(8,link.size()-9)));
    }
    return result;
}
std::vector<std::string> effectiveEndpoints(SshRuntime& runtime) {
    std::vector<std::string> ports,listens;std::string error;
    if(!runtime.effectiveValues("port",ports,error)||!runtime.effectiveValues("listenaddress",listens,error))fail("native endpoint proof unavailable",ActivationStatus::ReadinessUnconfirmed);
    std::set<std::string> uniquePorts(ports.begin(),ports.end());if(uniquePorts.size()!=1)fail("SSH verified profile requires one effective port");
    std::vector<std::string> out;for(const auto& text:listens) {
        auto e=decode(text);if(std::to_string(e.port)!=*uniquePorts.begin())fail("explicit ListenAddress port conflicts with effective Port");out.push_back(encode(e));
    }
    std::sort(out.begin(),out.end());if(out.empty()||out.size()>16||std::adjacent_find(out.begin(),out.end())!=out.end())fail("native endpoint set outside supported profile");
    ifaddrs* raw=nullptr;if(::getifaddrs(&raw))fail("local addresses unavailable");
    std::unique_ptr<ifaddrs,decltype(&::freeifaddrs)> local(raw,::freeifaddrs);
    std::set<std::string> addresses{"0.0.0.0","::"};
    for(auto* entry=raw;entry;entry=entry->ifa_next) {
        if(!entry->ifa_addr)continue;
        if(entry->ifa_addr->sa_family==AF_INET)addresses.insert(address(AF_INET,&reinterpret_cast<sockaddr_in*>(entry->ifa_addr)->sin_addr));
        if(entry->ifa_addr->sa_family==AF_INET6)addresses.insert(address(AF_INET6,&reinterpret_cast<sockaddr_in6*>(entry->ifa_addr)->sin6_addr));
    }
    for(const auto& text:out)if(!addresses.count(decode(text).ip))fail("nonlocal listener cannot be safely triggered");
    return out;
}
std::map<std::string,std::uint64_t> ownedListeners(unsigned pid) {
    const auto owned=descriptors(pid);const auto kernel=kernelListeners();std::map<std::string,std::uint64_t> result;
    for(const auto& [endpoint,inodes]:kernel) for(const auto inode:inodes) if(owned.count(inode)) {
        if(inodes.size()!=1||!result.emplace(endpoint,inode).second)fail("ambiguous controlled SSH listener");
    }
    return result;
}
}
