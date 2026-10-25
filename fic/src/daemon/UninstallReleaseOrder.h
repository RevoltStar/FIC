#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>
namespace fic::daemon {
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
