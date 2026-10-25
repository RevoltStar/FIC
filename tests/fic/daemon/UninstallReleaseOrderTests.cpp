#include "daemon/UninstallReleaseOrder.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using Graph=std::map<std::string,std::set<std::string>>;
void require(bool ok,const char* error){if(!ok)throw std::runtime_error(error);}
int main(){try{
    std::string error;std::vector<std::string> order;
    Graph graph{{"A",{}},{"B",{"A"}},{"C",{"B"}},{"independent",{}}};
    require(fic::daemon::uninstallReleaseOrder(graph,order,error),"valid graph rejected");
    const auto pos=[&](const char* name){return std::find(order.begin(),order.end(),name)-order.begin();};
    require(pos("A")<pos("B")&&pos("B")<pos("C"),"release order is not reverse Required");
    // Project release failure propagation exactly along Required edges: an
    // independent resource is still attempted, transitive prerequisites wait.
    std::map<std::string,bool> result;std::set<std::string> attempted;
    for(const auto& name:order){bool blocked=false;for(const auto& dependent:graph.at(name))blocked|=!result.at(dependent);
        if(!blocked)attempted.insert(name);result[name]=!blocked&&name!="A";}
    require(attempted==std::set<std::string>{"A","independent"},"failed dependent did not block prerequisites only");
    graph={{"shared",{"consumer1","consumer2"}},{"consumer1",{}},{"consumer2",{}}};
    require(fic::daemon::uninstallReleaseOrder(graph,order,error),"shared graph rejected");
    require(order.back()=="shared"&&order.size()==3,"shared resource released too early or twice");
    const auto preserved=order;
    require(!fic::daemon::uninstallReleaseOrder({{"shared",{"other"}},{"other",{"shared"}},{"unrelated",{}}},order,error),"grouped cycle accepted");
    require(order==preserved,"partial plan published before cycle rejection");
    require(!fic::daemon::uninstallReleaseOrder({{"A",{"missing"}}},order,error),"unknown dependency accepted");
    require(fic::daemon::uninstallReleaseOrder({},order,error)&&order.empty(),"empty plan rejected");
    std::cout<<"PASS: reverse dependencies, shared ordering, independent continuation, pre-mutation cycle/unknown refusal\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
