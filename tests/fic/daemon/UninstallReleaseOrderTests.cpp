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
    Graph ssh{{"NET:SshEdit:ssh_port",{}},{"NET:SshEdit:ssh_root_login",{}},{"NET:SshEdit:ssh_use_pam",{}},{"unrelated",{}}};
    fic::daemon::addSshReleaseOrdering(ssh, false);
    require(fic::daemon::uninstallReleaseOrder(ssh,order,error),"SSH Port release graph rejected");
    require(pos("NET:SshEdit:ssh_port")>pos("NET:SshEdit:ssh_root_login")&&pos("NET:SshEdit:ssh_port")>pos("NET:SshEdit:ssh_use_pam"),"Port released before scalar owners");
    result.clear();attempted.clear();
    for(const auto& name:order){bool blocked=false;for(const auto& dependent:ssh.at(name))blocked|=!result.at(dependent);
        if(!blocked)attempted.insert(name);result[name]=!blocked&&name!="NET:SshEdit:ssh_root_login";}
    require(!attempted.count("NET:SshEdit:ssh_port")&&attempted.count("unrelated"),"failed SSH scalar did not preserve Port/independent resources");
    const char* mfa="NET:SshEdit:ssh_mfa_required";
    const char* sssd="IDENTITY_ACCESS:SSSD:sssd_offline_credentials_expiration";
    const char* krb="IDENTITY_ACCESS:KERBEROS:kerberos_ticket_lifetime";
    ssh.emplace(mfa,std::set<std::string>{});
    ssh.emplace("PAM",std::set<std::string>{});
    ssh.emplace(sssd,std::set<std::string>{});
    ssh.emplace(krb,std::set<std::string>{});
    fic::daemon::addSshReleaseOrdering(ssh, false);
    require(ssh.at(sssd).empty(),"local-only MFA unnecessarily blocks SSSD");
    fic::daemon::addSshReleaseOrdering(ssh, true);
    require(fic::daemon::uninstallReleaseOrder(ssh,order,error),"MFA release graph rejected");
    require(pos(mfa)<pos("NET:SshEdit:ssh_root_login")&&pos(mfa)<pos("NET:SshEdit:ssh_use_pam")&&
            pos("NET:SshEdit:ssh_port")>pos("NET:SshEdit:ssh_use_pam")&&
            pos(mfa)<pos("PAM")&&pos(mfa)<pos(sssd),"MFA or Port release runs out of order");
    result.clear();attempted.clear();
    for(const auto& name:order){bool blocked=false;for(const auto& dependent:ssh.at(name))blocked|=!result.at(dependent);
        if(!blocked)attempted.insert(name);result[name]=!blocked&&name!=mfa;}
    require(attempted==std::set<std::string>{krb,mfa,"unrelated"},
            "failed MFA changed its required inputs or blocked unrelated resources");
    ssh.at("NET:SshEdit:ssh_root_login").insert("NET:SshEdit:ssh_port");
    require(!fic::daemon::uninstallReleaseOrder(ssh,order,error),"SSH resource ordering overrode a conflicting dependency");
    const auto preserved=order;
    require(!fic::daemon::uninstallReleaseOrder({{"shared",{"other"}},{"other",{"shared"}},{"unrelated",{}}},order,error),"grouped cycle accepted");
    require(order==preserved,"partial plan published before cycle rejection");
    require(!fic::daemon::uninstallReleaseOrder({{"A",{"missing"}}},order,error),"unknown dependency accepted");
    require(fic::daemon::uninstallReleaseOrder({},order,error)&&order.empty(),"empty plan rejected");
    std::cout<<"PASS: reverse dependencies, shared ordering, independent continuation, pre-mutation cycle/unknown refusal\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
