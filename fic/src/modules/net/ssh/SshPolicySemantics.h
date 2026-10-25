#pragma once
#include "modules/net/ssh/SshConfigSyntax.h"
#include <charconv>
#include <set>

// One policy order for runtime audit and the verified immutable input closure.
// Global values remain exact; this order is only for conditional restrictions.
inline int sshRootLoginRank(const std::string& value) {
    const auto v=normalizeSshKeyword(value);
    if(v=="no")return 0;
    if(v=="forced-commands-only")return 1;
    if(v=="prohibit-password"||v=="without-password")return 2;
    if(v=="yes")return 3;
    return -1;
}
inline bool sshConditionalValueIsSafe(const std::string& parameter,
    const std::string& actual,const std::string& expected) {
    const auto key=normalizeSshKeyword(parameter);
    if(key=="permitrootlogin") {
        const auto a=sshRootLoginRank(actual),e=sshRootLoginRank(expected);
        return a>=0&&e>=0&&a<=e;
    }
    if(key=="maxauthtries") {
        const auto positive=[](const std::string& s,int& n) {
            const auto p=std::from_chars(s.data(),s.data()+s.size(),n);
            return !s.empty()&&p.ec==std::errc{}&&p.ptr==s.data()+s.size()&&n>0;
        };
        int a=0,e=0;return positive(actual,a)&&positive(expected,e)&&a<=e;
    }
    // Port and UsePAM are global-only even under Match all. Other native
    // verifier consumers (e.g. PAMServiceName) keep exact equality; the adapter
    // separately bounds its selected policy set to the five known policies.
    if(key=="port"||key=="usepam")return false;
    return !actual.empty()&&!expected.empty()&&
        normalizeSshKeyword(actual)==normalizeSshKeyword(expected);
}
inline bool sshSupportedMatch(const std::vector<std::string>& args,std::string& error) {
    if(args.size()==1&&normalizeSshKeyword(args[0])=="all")return true;
    const std::set<std::string> criteria{"user","group","address","localaddress","localport","host"};
    if(args.empty()||args.size()%2){error="unsupported SSH Match grammar";return false;}
    for(std::size_t i=0;i<args.size();i+=2) {
        if(!criteria.count(normalizeSshKeyword(args[i]))||args[i+1].empty()) {
            error="unsupported SSH Match criterion/argument";return false;
        }
    }
    return true; // native sshd -t/-T still validates criteria values/patterns
}
