#include "service/sssd/SssdRelationValidator.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
namespace s=fic::service::sssd;
using J=nlohmann::json;
const char* origin(s::ValueOrigin v){switch(v){case s::ValueOrigin::Foreign:return "foreign";case s::ValueOrigin::NativeDefault:return "native-default";case s::ValueOrigin::FicOwned:return "fic-owned";case s::ValueOrigin::Unknown:return "unknown";case s::ValueOrigin::Proposed:return "proposed";}return "unknown";}
J value(const s::EffectiveValue& v){J out={{"section",v.setting.section},{"key",v.setting.key},{"source",v.source},{"raw",v.raw},{"origin",origin(v.origin)},{"explicit",v.explicitValue},{"status",s::semanticStatusName(v.status)},{"diagnostic",v.diagnostic}};
 if(auto x=std::get_if<s::Days>(&v.value)){out["value"]=x->value;out["unit"]="days";}
 else if(auto x=std::get_if<s::Seconds>(&v.value)){out["value"]=x->value;out["unit"]="seconds";}
 else if(auto x=std::get_if<bool>(&v.value)){out["value"]=*x;out["unit"]="boolean";}else out["value"]=nullptr;return out;}
int main(int argc,char** argv){J out;try{
 auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(30);
 auto in=s::capture(deadline);auto cfg=s::effectiveConfiguration(in);auto relation=s::validateRelations(cfg);const auto& scope=cfg.scope.data();
 out={{"status","PROJECTED"},{"semantic_status",s::semanticStatusName(relation.status)},{"graph",scope.graphFingerprint},{"launch",scope.launchFingerprint},{"selected",scope.selected},{"configured",scope.configured},{"enabled",scope.enabled},{"unselected",scope.unselected},{"expected_backends",scope.expectedBackends},{"offline",value(cfg.offlineDays)},{"completed_proofs",false},{"runtime_receipt",false}};
 for(const auto& [n,d]:scope.domains){out["scope"][n]={{"id_provider",d.idProvider},{"auth_provider",d.authProvider},{"auth_default",d.authDefault},{"enabled",d.enabled},{"selected",d.selected},{"dynamic_possible",d.dynamicPossible},{"trusted_possible",d.trustedPossible},{"consumers",d.requiredConsumers}};}
 for(const auto& [n,d]:cfg.domains){out["values"][n]={{"cache",value(d.cacheCredentials)},{"account",value(d.accountDays)},{"cached_auth",value(d.cachedAuthSeconds)}};if(d.expectedCachedAuthSeconds)out["values"][n]["expected_cached_seconds"]=d.expectedCachedAuthSeconds->value;}
 for(const auto& [n,st]:relation.domains)out["relations"][n]=s::semanticStatusName(st);
 for(const auto& i:relation.issues)out["issues"].push_back({{"status",s::semanticStatusName(i.status)},{"section",i.section},{"key",i.key},{"diagnostic",i.diagnostic}});
 if(argc==3&&std::string(argv[1])=="scope-change"){
  // Disposable fixture only: the candidate bytes are supplied by native.py.
  std::ifstream file(argv[2]);std::string bytes((std::istreambuf_iterator<char>(file)),{});
  {std::ofstream target("/etc/sssd/sssd.conf");target<<bytes;}
  auto next=s::capture(deadline);out["scope_unchanged"]=s::sameScopeReference(cfg.scope,s::domainScope(next));out["next_graph"]=s::inputFingerprint(next);
 }
 }catch(const fic::service::detail::Failure& e){out={{"status",fic::service::activationStatusName(e.status)},{"diagnostic",e.what()}};}
 catch(const std::exception& e){out={{"status","ERROR"},{"diagnostic",e.what()}};}
 std::cout<<out.dump(2)<<'\n';return 0;
}
