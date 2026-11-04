#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>
namespace fic::daemon {
// Keep the Port override until every other SSH owner is released. Its final
// release can restore several foreign ports, outside scalar callers' existing
// single-port activation profile. This is an uninstall resource edge only;
// policy ENABLE values and PolicyRegistry dependencies are not changed.
inline void addSshPortReleaseOrdering(std::map<std::string,std::set<std::string>>& dependents) {
    const std::string port="NET:SshEdit:ssh_port",prefix="NET:SshEdit:";
    if(!dependents.count(port))return;
    for(const auto& [name,_]:dependents)if(name!=port&&name.rfind(prefix,0)==0)dependents.at(port).insert(name);
}
// Edges point from a resource to its dependents. Group before calling: a
// shared resource must be released once, after all its external dependents.
// Validate the complete graph before allowing the first physical release.
inline bool uninstallReleaseOrder(const std::map<std::string,std::set<std::string>>& dependents,
    std::vector<std::string>& order,std::string& error) {
    std::vector<std::string> candidate;
    std::set<std::string> done;
    for(const auto& [name,edges]:dependents)for(const auto& edge:edges)
        if(!dependents.count(edge)){error="unknown uninstall dependency: "+edge;return false;}
    while(done.size()<dependents.size()) {
        bool progress=false;
        for(const auto& [name,edges]:dependents) {
            if(done.count(name))continue;
            bool pending=false;for(const auto& edge:edges)pending|=!done.count(edge);
            if(pending)continue;
            done.insert(name);candidate.push_back(name);progress=true;
        }
        if(!progress){error="Required/shared-resource dependency cycle";return false;}
    }
    order=std::move(candidate);return true;
}
}
