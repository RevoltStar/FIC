#pragma once
#include "modules/net/ssh/SshRuntime.h"
#include "service/VerifiedConfigMountSupport.h"
#include <cstdint>
namespace fic::service::ssh::detail::listener {
struct Endpoint {int family;std::string ip;unsigned port;};
std::string address(int family,const void*);
Endpoint decode(const std::string&);
std::string encode(const Endpoint&);
std::map<std::string,std::vector<std::uint64_t>> kernelListeners();
std::set<std::uint64_t> descriptors(unsigned pid);
std::map<std::string,std::uint64_t> ownedListeners(unsigned pid);
std::vector<std::string> effectiveEndpoints(SshRuntime&);
}
