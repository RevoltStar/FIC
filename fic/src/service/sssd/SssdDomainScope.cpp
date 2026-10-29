#include "service/sssd/SssdDomainScope.h"
#include <fic/core/integrity/ContentDigest.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <set>
namespace fic::service::sssd {
namespace {
using J=nlohmann::json;
std::string hash(const J& j){return fic::core::ContentDigest::sha256Hex(j.dump());}
std::string lower(std::string s){for(auto& c:s)if(c>='A'&&c<='Z')c+=32;return s;}
std::string trim(std::string s){auto a=s.find_first_not_of(" \t\r"),b=s.find_last_not_of(" \t\r");return a==s.npos?"":s.substr(a,b-a+1);}
bool validName(const std::string& s){return !s.empty()&&s.size()<=253&&s.front()!='.'&&s.back()!='.'&&s.find("..")==s.npos&&std::all_of(s.begin(),s.end(),[](char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_';});}
std::string setting(const IniProjection& p,const std::string& sec,const std::string& key){auto s=p.find(sec);if(s==p.end())return {};auto v=s->second.find(key);return v==s->second.end()?"":v->second.value;}
// Fingerprints bind observations, not arbitrary caller-supplied derived facts.
// Compare every fact that can influence preview or future consumer validation.
J issueFacts(const std::vector<SemanticIssue>& issues){
    J out=J::array();for(const auto& i:issues)out.push_back(J::array({static_cast<int>(i.status),i.section,i.key,i.diagnostic}));return out;
}
J scopeFacts(const DomainScopeData& data){
    J out={{"format",data.formatVersion},{"hypothetical",data.hypothetical},
        {"proposal",data.proposedGraphFingerprint},{"platform",data.platform},
        {"graph",data.graphFingerprint},{"launch",data.launchFingerprint},{"projection",data.projectionFingerprint},
        {"configured",data.configured},{"selected",data.selected},{"enabled",data.enabled},
        {"backends",data.expectedBackends},{"unselected",data.unselected},{"issues",issueFacts(data.issues)}};
    out["input"]=data.input?J(inputFingerprint(*data.input)):J(nullptr);
    out["domains"]=J::object();
    for(const auto& [key,d]:data.domains)out["domains"][key]=J::array({d.name,d.idProvider,d.authProvider,
        static_cast<int>(d.provider),d.selected,d.enabled,d.authDefault,d.dynamicPossible,d.trustedPossible,
        d.enabledSetting?J(*d.enabledSetting):J(nullptr),d.requiredConsumers,issueFacts(d.issues)});
    return out;
}

}
const char* semanticStatusName(SemanticStatus s){switch(s){
case SemanticStatus::Validated:return "Validated";case SemanticStatus::Conflict:return "Conflict";
case SemanticStatus::UnsupportedProvider:return "UnsupportedProvider";case SemanticStatus::UnknownSemantics:return "UnknownSemantics";
case SemanticStatus::UnsupportedConfiguration:return "UnsupportedConfiguration";case SemanticStatus::InvalidInput:return "InvalidInput";
case SemanticStatus::NotProven:return "NotProven";}return "UnknownSemantics";}
namespace detail_i2 {
std::optional<bool> boolean(const std::string& s){auto x=lower(s);if(x=="true")return true;if(x=="false")return false;return {};}
OrderedGraph orderedGraph(const SssdInputReference& input){
    OrderedGraph graph;const auto& tree=input.sources.at("/etc/sssd").tree;
    for(const auto& path:input.order){
        if(path.rfind("/etc/sssd/",0)!=0)throw std::invalid_argument("I2 requires an I1 ordered input reference");
        graph.emplace_back(path,detail_i1::project({path},{{path,tree.files.at(path.substr(10))}}));
    }return graph;
}
IniProjection merge(const OrderedGraph& graph){IniProjection out;for(const auto& [path,p]:graph)for(const auto& [sec,keys]:p){out[sec];for(const auto& [k,v]:keys)out[sec][k]=v;}return out;}
DomainScopeReference scopeProjection(const SssdInputReference& input,const IniProjection& p,const OrderedGraph* hypothetical){
    DomainScopeData out;out.platform=input.launch.profile.platform;out.graphFingerprint=inputFingerprint(input);
    out.launchFingerprint=hash(J{{"contract",input.launch.contract},{"process",input.launch.processIdentity},{"env",input.launch.environmentFingerprint},{"lookup",input.launch.unitLookupFingerprint},{"executables",input.launch.executables}});
    out.input=std::make_shared<const SssdInputReference>(input);
    const auto projectJson=[](const IniProjection& ini){J result=J::object();for(const auto& [sec,keys]:ini){result[sec]=J::object();for(const auto& [k,v]:keys)result[sec][k]=J::array({v.value,v.source});}return result;};
    out.projectionFingerprint=hash(projectJson(p));
    if(hypothetical){J graph=J::array();for(const auto& [path,ini]:*hypothetical)graph.push_back(J::array({path,projectJson(ini)}));out.hypothetical=true;out.proposedGraphFingerprint=hash(graph);}

    auto issue=[&](SemanticStatus st,const std::string& sec,const std::string& key,const std::string& why){out.issues.push_back({st,sec,key,why});};
    static const std::set<std::string> platforms{"debian-12","debian-13","ubuntu-24.04","ubuntu-26.04","alt-p11"};
    if(!platforms.count(out.platform))issue(SemanticStatus::UnsupportedConfiguration,"sssd","platform","no versioned native defaults for platform");
    for(const auto& [sec,keys]:p){
        const auto foldedSection=lower(sec);
        if((foldedSection=="sssd"||foldedSection=="pam"||foldedSection.rfind("domain/",0)==0)&&sec.substr(0,sec.find('/'))!=foldedSection.substr(0,foldedSection.find('/')))
            issue(SemanticStatus::UnsupportedConfiguration,sec,"case","section spelling outside closed canonical syntax");
        for(const auto& [key,v]:keys)if(key!=lower(key))issue(SemanticStatus::UnsupportedConfiguration,sec,key,"key spelling outside closed canonical syntax; no guessed default");
    }
    const auto implicit=setting(p,"sssd","enable_files_domain");
    if(!implicit.empty()&&boolean(implicit)!=std::optional<bool>{false})issue(SemanticStatus::UnknownSemantics,"sssd","enable_files_domain","implicit native roots are outside explicit LDAP scope");
    std::set<std::string> folded;
    for(const auto& [sec,keys]:p)if(sec.rfind("domain/",0)==0){
        const auto name=sec.substr(7);out.configured.push_back(name);Domain d;d.name=name;
        if((name.find('/')==name.npos&&!validName(name))||!folded.insert(lower(name)).second)issue(SemanticStatus::InvalidInput,sec,"name","invalid/ambiguous case domain identity");
        if(name.find('/')!=name.npos){d.dynamicPossible=d.trustedPossible=true;issue(SemanticStatus::UnknownSemantics,sec,"scope","configured trusted subdomain is not static root coverage");}
        out.domains.emplace(name,std::move(d));
    }
    auto text=setting(p,"sssd","domains");std::set<std::string> selectedFolded;
    if(!text.empty()){
        std::size_t pos=0;
        do{auto end=text.find(',',pos);auto name=trim(text.substr(pos,end==text.npos?text.npos:end-pos));
            if(!validName(name)||!selectedFolded.insert(lower(name)).second)issue(SemanticStatus::InvalidInput,"sssd","domains","invalid/duplicate/ambiguous selected domain: "+name);
            else {out.selected.push_back(name);auto it=out.domains.find(name);if(it==out.domains.end())issue(SemanticStatus::InvalidInput,"domain/"+name,"domains","selected domain section missing or case differs");else it->second.selected=true;}
            if(end==text.npos)break;pos=end+1;
        }while(pos<=text.size());
    }
    if(out.selected.empty())issue(SemanticStatus::UnsupportedConfiguration,"sssd","domains","no explicit selected static roots");
    for(auto& [name,d]:out.domains){
        const auto sec="domain/"+name;d.enabled=d.selected;
        auto enabled=setting(p,sec,"enabled");if(!enabled.empty()){
            d.enabledSetting=boolean(enabled);if(!d.enabledSetting)issue(SemanticStatus::InvalidInput,sec,"enabled","expected native true/false boolean");else d.enabled=*d.enabledSetting;
        }
        if(!d.selected)out.unselected.push_back(name);
        if(d.enabled&&!d.selected)issue(SemanticStatus::UnsupportedConfiguration,sec,"enabled","native enabled=true adds a root outside explicit selected scope");
        d.idProvider=setting(p,sec,"id_provider");d.authProvider=setting(p,sec,"auth_provider");
        if(d.authProvider.empty()){d.authProvider=d.idProvider;d.authDefault=true;} // dp_target_default_module(DPT_AUTH) -> DPT_ID.
        if(d.idProvider=="ldap"&&d.authProvider=="ldap")d.provider=ProviderClass::LdapPassword;
        else if(d.idProvider=="proxy")d.provider=ProviderClass::Proxy;
        else if(d.idProvider=="ad")d.provider=ProviderClass::Ad;
        else if(d.idProvider=="ipa")d.provider=ProviderClass::Ipa;
        if(d.provider==ProviderClass::Ad||d.provider==ProviderClass::Ipa)d.dynamicPossible=d.trustedPossible=true;
        for(const auto& [key,value]:p.at(sec)){
            if(key.rfind("subdomain",0)==0||key=="ad_enabled_domains"||key=="ipa_server_mode"||key=="domain_type"||key=="inherit_from")d.dynamicPossible=d.trustedPossible=true;
            if(key.find("provider")!=key.npos&&key!="id_provider"&&key!="auth_provider"&&value.value!="ldap"&&value.value!="permit"&&value.value!="none"){
                d.issues.push_back({SemanticStatus::UnknownSemantics,sec,key,"additional provider mapping outside reviewed LDAP password profile"});
            }
        }
        if(d.selected||d.enabled){
            if(d.provider!=ProviderClass::LdapPassword)d.issues.push_back({SemanticStatus::UnsupportedProvider,sec,"id_provider/auth_provider","selected provider pair lacks static LDAP password proof: "+d.idProvider+"/"+d.authProvider});
            if(d.dynamicPossible)d.issues.push_back({SemanticStatus::UnknownSemantics,sec,"scope","dynamic/trust/inherited scope cannot be proven from static inputs"});
            // Explicit alternate authentication mechanisms are not covered by the password contract.
            for(const auto& [section,keys]:p)for(const auto& [k,v]:keys)
                if((section==sec||section=="pam")&&(k=="pam_cert_auth"||k=="local_auth_policy"||k=="passkey_verification"||k=="pam_p11_allowed_services")&&v.value!="false")
                    d.issues.push_back({SemanticStatus::UnknownSemantics,section,k,"non-password authentication scope not proven by I2"});
            out.issues.insert(out.issues.end(),d.issues.begin(),d.issues.end());
        }
        d.requiredConsumers={"monitor:/usr/sbin/sssd","backend:"+name+":/usr/libexec/sssd/sssd_be","responder:/usr/libexec/sssd/sssd_pam","responder:/usr/libexec/sssd/sssd_nss"};
    }
    // Preserve explicit order. Auto-enabled roots are reported but never claimed supported.
    for(const auto& n:out.selected)if(out.domains.count(n)&&out.domains.at(n).enabled)out.enabled.push_back(n);
    for(const auto& n:out.unselected)if(out.domains.at(n).enabled)out.enabled.push_back(n);
    out.expectedBackends=out.enabled;
    if(out.enabled.empty())issue(SemanticStatus::UnsupportedConfiguration,"sssd","domains","no domain enabled; no expected backend");
    return DomainScopeReference(std::move(out));
}
}
std::string inputFingerprint(const SssdInputReference& in){
    J j={{"format",1},{"platform",in.launch.profile.platform},{"contract",in.launch.contract},{"process",in.launch.processIdentity},
         {"env",in.launch.environmentFingerprint},{"lookup",in.launch.unitLookupFingerprint},{"executables",in.launch.executables},
         {"consumers",in.consumers},{"order",in.order},{"negative",in.negativeDependencies},{"later",in.laterForeignSnippets}};
    for(const auto& [path,s]:in.sources){J x={{"present",s.present},{"identity",J::array({s.identity.mount,s.identity.device,s.identity.inode,s.identity.mode,s.identity.uid,s.identity.gid})},{"files",s.tree.files}};
        for(const auto& [n,st]:s.tree.attributes)x["metadata"][n]=J::array({st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_size,st.st_nlink,st.st_mtim.tv_sec,st.st_mtim.tv_nsec,st.st_ctim.tv_sec,st.st_ctim.tv_nsec});j["sources"][path]=std::move(x);}
    j["profile"]={in.launch.profile.fragment,in.launch.profile.environment,in.launch.profile.user,in.launch.profile.group,in.launch.profile.pidFile,in.launch.profile.preCommands,in.launch.profile.unitSha256};
    j["activationLimit"]=in.launch.activationLimit;j["genericSupported"]=in.launch.genericActivationSupported;j["negativeGap"]=in.engineNeedsNegativeDependencySupport;
    for(const auto& [sec,keys]:in.ini)for(const auto& [key,v]:keys)j["ini"][sec][key]=J::array({v.value,v.source});
    j["requestTimeout"]=in.inputs.timeout.count();j["requestBudget"]=in.inputs.maxSnapshotBytes;
    j["requestUnit"]=in.inputs.unit;for(const auto& path:in.inputs.paths)j["requestPaths"].push_back(J::array({path.path.string(),static_cast<int>(path.kind),path.sha256,path.manifest}));
    return hash(j);
}
DomainScopeReference domainScope(const SssdInputReference& input){return detail_i2::scopeProjection(input,detail_i2::merge(detail_i2::orderedGraph(input)));}
bool sameScopeReference(const DomainScopeReference& a,const DomainScopeReference& b){
    return a.data().hypothetical==b.data().hypothetical&&a.data().proposedGraphFingerprint==b.data().proposedGraphFingerprint&&
        a.data().formatVersion==b.data().formatVersion&&a.data().graphFingerprint==b.data().graphFingerprint&&
        a.data().launchFingerprint==b.data().launchFingerprint&&a.data().projectionFingerprint==b.data().projectionFingerprint&&
        scopeFacts(a.data())==scopeFacts(b.data());
}
} // namespace fic::service::sssd
