#include "service/sssd/SssdRelationValidator.h"
#include <iostream>
#include <stdexcept>
using namespace fic::service::sssd;
namespace {
void check(bool b,const std::string& why){if(!b)throw std::runtime_error(why);}
const std::string mainFile="/etc/sssd/sssd.conf", ownFile="/etc/sssd/conf.d/zzzz-fic.conf";
std::string base="[sssd]\ndomains=a\n[domain/a]\nid_provider=ldap\nauth_provider=ldap\n";
SssdInputReference input(std::string main=base,std::map<std::string,std::string> snippets={}){
    SssdInputReference in;in.launch.profile=launchProfile("debian-12");in.launch.processIdentity="pid:start:invocation";
    auto& tree=in.sources["/etc/sssd"].tree;tree.files["sssd.conf"]=main;in.order.push_back(mainFile);
    for(const auto& [n,v]:snippets){tree.files["conf.d/"+n]=v;in.order.push_back("/etc/sssd/conf.d/"+n);}
    in.ini=detail_i2::merge(detail_i2::orderedGraph(in));return in;
}
SemanticStatus status(const SssdInputReference& in){return validateRelations(effectiveConfiguration(in)).status;}
TrustedOwnershipContext own(const SssdInputReference& in,std::map<SettingKey,std::string> values){return {inputFingerprint(in),"test-only-trusted-journal-assertion",std::move(values)};}
unsigned days(const EffectiveValue& v){return std::get<Days>(v.value).value;}
void scopeTests(){
    auto a=input();auto scope=domainScope(a);check(scope.data().selected==std::vector<std::string>{"a"},"one explicit root");check(status(a)==SemanticStatus::Validated,"LDAP positive");
    check(scope.data().domains.at("a").requiredConsumers.size()==4,"future consumer identities");
    auto two=input("[sssd]\ndomains = a, b\n[domain/a]\nid_provider=ldap\n[domain/b]\nid_provider=ldap\n");
    check(status(two)==SemanticStatus::Validated&&domainScope(two).data().enabled==std::vector<std::string>({"a","b"}),"multi root ordered/default auth");
    auto extra=input(base+"[domain/inactive]\nid_provider=proxy\naccount_cache_expiration=bad\n");
    check(status(extra)==SemanticStatus::Validated&&domainScope(extra).data().unselected==std::vector<std::string>{"inactive"},"inactive foreign domain not backend covered");
    auto disabled=input(base+"enabled=false\n");check(status(disabled)!=SemanticStatus::Validated&&domainScope(disabled).data().enabled.empty(),"all disabled no coverage");
    auto enabled=input(base+"[domain/b]\nid_provider=ldap\nenabled=true\n");check(status(enabled)==SemanticStatus::UnsupportedConfiguration&&domainScope(enabled).data().enabled.size()==2,"unlisted explicit enabled added natively but outside support");
    for(const auto& roots:{"a,a","A,a","a,","a,,b","missing","a/b","a.*","a b"}){
        auto bad=input(std::string("[sssd]\ndomains=")+roots+"\n[domain/a]\nid_provider=ldap\n");
        check(status(bad)!=SemanticStatus::Validated,std::string("bad domains ")+roots);
    }
    check(status(input("[sssd]\n[domain/a]\nid_provider=ldap\n"))!=SemanticStatus::Validated,"absent selected domains");
    check(status(input("[sssd]\ndomains=a\nenable_files_domain=true\n[domain/a]\nid_provider=ldap\n"))==SemanticStatus::UnknownSemantics,"implicit files root");
    check(status(input(base+"[domain/A]\nid_provider=ldap\n"))!=SemanticStatus::Validated,"configured case collision");
    for(const auto& p:{"unknown","proxy","ad","ipa"}){
        auto ref=input("[sssd]\ndomains=a\n[domain/a]\nid_provider="+std::string(p)+"\n");
        check(status(ref)==SemanticStatus::UnsupportedProvider,"unsupported provider no partial success");
        if(std::string(p)=="ad"||std::string(p)=="ipa")check(domainScope(ref).data().domains.at("a").dynamicPossible,"trust discovery risk");
    }
    check(status(input(base+"subdomains_provider=ldap\n"))==SemanticStatus::UnknownSemantics,"dynamic scope");
    check(status(input(base+"[domain/a/child]\nid_provider=ldap\n"))!=SemanticStatus::Validated,"trusted subdomain not invented");
    check(status(input(base+"auth_provider=krb5\n"))==SemanticStatus::UnsupportedProvider,"non-password provider mapping");
    for(const auto& addition:{"enabled=yes\n","CACHE_CREDENTIALS=true\n","[PAM]\noffline_credentials_expiration=5\n"})check(status(input(base+addition))!=SemanticStatus::Validated,"unknown syntax/default cannot be compliant");
    // Immutable owned snapshot and exact invalidation, including source-only changes.
    const auto fp=scope.data().graphFingerprint;a.launch.processIdentity="different";
    check(scope.data().graphFingerprint==fp&&!sameScopeReference(scope,domainScope(a)),"immutable launch binding");
    for(int kind=0;kind<11;++kind){auto changed=input();
        if(kind==0)changed=input(base+"enabled=false\n");
        if(kind==1)changed=input(base+"id_provider=proxy\n");
        if(kind==2)changed=input(base+"auth_provider=proxy\n");
        if(kind==3)changed=input(base+"cache_credentials=true\n");
        if(kind==4)changed=input(base,{{"10-unrelated.conf","[pam]\ndebug_level=1\n"}});
        if(kind==5)changed.sources.at("/etc/sssd").identity.inode++;
        if(kind==6)changed=input(base+"[domain/unselected]\nid_provider=ldap\n");
        if(kind==7)changed.launch.contract["generation"]="new";
        if(kind==8)changed=input(base+"subdomain_inherit=cache_credentials\n");
        if(kind==9)changed.sources.at("/etc/sssd").tree.attributes["sssd.conf"].st_ino++;
        if(kind==10)changed.sources.at("/etc/sssd").tree.attributes["sssd.conf"].st_ctim.tv_nsec++;
        check(!sameScopeReference(domainScope(input()),domainScope(changed)),"scope drift detected "+std::to_string(kind));
    }
}
void valueTests(){
    auto in=input();auto cfg=effectiveConfiguration(in);
    check(days(cfg.offlineDays)==0&&cfg.offlineDays.origin==ValueOrigin::NativeDefault&&!cfg.offlineDays.explicitValue,"native offline default not FIC30");
    auto d=cfg.domains.at("a");check(!std::get<bool>(d.cacheCredentials.value)&&days(d.accountDays)==0&&std::get<Seconds>(d.cachedAuthSeconds.value).value==0,"domain defaults");
    for(const auto& b:{"true","TRUE","TrUe","false","FALSE"})check(status(input(base+"cache_credentials="+b+"\n"))==SemanticStatus::Validated,"native booleans");
    for(const auto& b:{"yes","no","1","0","on"})check(status(input(base+"cache_credentials="+b+"\n"))==SemanticStatus::UnsupportedConfiguration,"reject unknown boolean without inferred value");
    for(const auto& n:{"-1","+1","2147483648","4294967296","1days","0x1","010","abc","3651"}){
        auto x=input(base+"account_cache_expiration="+n+"\n");check(status(x)!=SemanticStatus::Validated,"unsafe day input");check(!effectiveConfiguration(x).domains.at("a").accountDays.diagnostic.empty(),"numeric diagnostic");
    }
    auto merged=input(base+"[pam]\noffline_credentials_expiration=30\n",{{"50-other.conf","[pam]\noffline_credentials_expiration=20\n"},{"zzzz-fic.conf","[pam]\noffline_credentials_expiration=4\noffline_credentials_expiration=5\n"}});
    auto foreign=effectiveConfiguration(merged);check(days(foreign.offlineDays)==5&&foreign.offlineDays.origin==ValueOrigin::Unknown&&foreign.offlineDays.source==ownFile,"FIC-named not owned; last wins");
    auto ctx=own(merged,{{{"pam","offline_credentials_expiration"},"5"}});auto owned=effectiveConfiguration(merged,&ctx);check(owned.offlineDays.origin==ValueOrigin::FicOwned,"trusted exact owner");
    ctx.graphFingerprint="stale";check(validateRelations(effectiveConfiguration(merged,&ctx)).status==SemanticStatus::NotProven,"stale proof no owned adoption");
    auto unknown=effectiveConfiguration(input());unknown.offlineDays.value=std::monostate{};
    check(validateRelations(unknown).status==SemanticStatus::UnknownSemantics,"unknown effective value never passes");
    auto clamp=effectiveConfiguration(input(base+"cached_auth_timeout=172800\n[pam]\noffline_credentials_expiration=1\n"));
    check(clamp.domains.at("a").expectedCachedAuthSeconds->value==86400&&std::get<Seconds>(clamp.domains.at("a").cachedAuthSeconds.value).value==172800,"seconds configured vs expected native clamp");
}
void relationTests(){
    for(auto [o,a]:std::vector<std::pair<int,int>>{{0,0},{0,1},{1,0},{1,1},{2,1},{1,2}})for(const auto& cache:{"true","false"}){
        auto in=input(base+"cache_credentials="+cache+"\naccount_cache_expiration="+std::to_string(a)+"\n[pam]\noffline_credentials_expiration="+std::to_string(o)+"\n");
        auto result=validateRelations(effectiveConfiguration(in));bool valid=a==0||(o>0&&a>=o);
        check(result.status==(valid?SemanticStatus::Validated:SemanticStatus::Conflict),"R2 LDAP matrix independent of cache");
        if(!valid)check(result.issues.back().section=="domain/a"&&result.issues.back().diagnostic.find("account=")!=std::string::npos,"conflict exact domain/values diagnostic");
    }
    auto multi=input("[sssd]\ndomains=a,b\n[pam]\noffline_credentials_expiration=10\n[domain/a]\nid_provider=ldap\naccount_cache_expiration=15\n[domain/b]\nid_provider=ldap\naccount_cache_expiration=5\n");
    auto r=validateRelations(effectiveConfiguration(multi));check(r.status==SemanticStatus::Conflict&&r.domains.at("a")==SemanticStatus::Validated&&r.domains.at("b")==SemanticStatus::Conflict,"one domain fails whole projection");
}
void previewTests(){
    SettingKey offline{"pam","offline_credentials_expiration"}, account{"domain/a","account_cache_expiration"},cache{"domain/a","cache_credentials"};
    auto in=input(base+"account_cache_expiration=5\n[pam]\noffline_credentials_expiration=1\n");
    auto scope=domainScope(in);
    auto apply=previewConfiguration(in,scope,{ProposedOperation::Apply,{{offline,Days{10}}}});
    check(apply.projectionAvailable&&validateRelations(*apply.configuration).status==SemanticStatus::Conflict,"foreign account + proposed offline");
    auto foreignOffline=input(base+"[pam]\noffline_credentials_expiration=10\n");
    auto foreignConflict=previewConfiguration(foreignOffline,domainScope(foreignOffline),{ProposedOperation::Apply,{{account,Days{5}}}});
    check(foreignConflict.projectionAvailable&&foreignConflict.semanticStatus==SemanticStatus::Conflict,"foreign offline + proposed account conflict");
    auto inverse=previewConfiguration(in,scope,{ProposedOperation::Apply,{{account,Days{0}}}});check(inverse.projectionAvailable&&validateRelations(*inverse.configuration).status==SemanticStatus::Validated,"independent account zero");
    in=input(base+"account_cache_expiration=5\n[pam]\noffline_credentials_expiration=10\n",{{"zzzz-fic.conf","[pam]\noffline_credentials_expiration=1\n[domain/a]\ncache_credentials=true\n"}});
    auto ctx=own(in,{{offline,"1"},{cache,"true"}});scope=domainScope(in);
    check(!previewConfiguration(in,scope,{ProposedOperation::Refresh,{{offline,Days{2}}}}).projectionAvailable,"no owner cannot refresh");
    auto refresh=previewConfiguration(in,scope,{ProposedOperation::Refresh,{{offline,Days{2}}}},&ctx);
    check(refresh.projectionAvailable&&days(refresh.configuration->offlineDays)==2&&std::get<bool>(refresh.configuration->domains.at("a").cacheCredentials.value),"refresh one key preserves sibling");
    auto multi=previewConfiguration(in,scope,{ProposedOperation::Apply,{{offline,Days{2}},{account,Days{3}}}},&ctx);
    check(multi.projectionAvailable&&multi.semanticStatus==SemanticStatus::Validated&&days(multi.configuration->domains.at("a").accountDays)==3,"multiple independent own keys logical merge");
    auto release=previewConfiguration(in,scope,{ProposedOperation::ReleasePreview,{{offline,{}}}},&ctx);
    check(release.projectionAvailable&&release.semanticStatus==SemanticStatus::Conflict&&!release.semanticIssues.empty()&&days(release.configuration->offlineDays)==10&&release.configuration->offlineDays.origin==ValueOrigin::Foreign&&validateRelations(*release.configuration).status==SemanticStatus::Conflict,"release reveals foreign conflict without forbidding release preview");
    check(release.configuration->domains.at("a").cacheCredentials.origin==ValueOrigin::FicOwned,"sibling ownership preserved");
    for(const auto& content:{"[pam]\noffline_credentials_expiration=2\n","[pam]\noffline_credentials_expiration=99\n","[pam]\ndebug_level=9\n"}){
        auto late=in;late.sources.at("/etc/sssd").tree.files["conf.d/zzzzz-foreign.conf"]=content;late.order.push_back("/etc/sssd/conf.d/zzzzz-foreign.conf");auto owner=own(late,{{offline,"1"},{cache,"true"}});
        check(!previewConfiguration(late,domainScope(late),{ProposedOperation::Refresh,{{offline,Days{2}}}},&owner).projectionAvailable,"all later snippets block refresh");
        auto preview=previewConfiguration(late,domainScope(late),{ProposedOperation::ReleasePreview,{{offline,{}}}},&owner);
        check(preview.projectionAvailable,"late snippet does not block own release preview");
        check(preview.configuration->scope.data().hypothetical&&!preview.configuration->scope.data().proposedGraphFingerprint.empty()&&!sameScopeReference(preview.configuration->scope,domainScope(late)),"shadowed removal cannot masquerade as observed graph");
    }
    auto changed=in;changed.sources.at("/etc/sssd").identity.inode++;
    check(!previewConfiguration(changed,scope,{ProposedOperation::Refresh,{{offline,Days{1}}}},&ctx).projectionAvailable,"same effective value changed object invalidates old scope");
    for(const auto& request:std::vector<ProposedSetting>{{offline,Seconds{2}},{{"domain/a","cached_auth_timeout"},Seconds{2}},{{"domain/unknown","cache_credentials"},true},{cache,false}})
        check(!previewConfiguration(in,scope,{ProposedOperation::Apply,{request}},&ctx).projectionAvailable,"invalid units/foreign dependency/dynamic domain/fixed true rejected");
    auto noFile=input(base);
    auto offlineOnly=previewConfiguration(noFile,domainScope(noFile),{ProposedOperation::Apply,{{offline,Days{30}}}});
    check(offlineOnly.projectionAvailable&&!std::get<bool>(offlineOnly.configuration->domains.at("a").cacheCredentials.value),"offline does not enable cache implicitly");
auto newCache=previewConfiguration(noFile,domainScope(noFile),{ProposedOperation::Apply,{{cache,true}}});
    check(newCache.projectionAvailable&&days(newCache.configuration->offlineDays)==0,"cache does not enable/change offline implicitly");
}
}
int main(){try{scopeTests();valueTests();relationTests();previewTests();std::cout<<"SSSD I2 scope/value/relation/preview tests PASS\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
