#include "service/sssd/SssdEffectiveConfiguration.h"
#include "service/sssd/SssdRelationValidator.h"
#include <algorithm>
#include <charconv>
#include <limits>
namespace fic::service::sssd {
namespace {
constexpr const char* ownedFile="/etc/sssd/conf.d/zzzz-fic.conf";
const IniValue* lookup(const IniProjection& p,const SettingKey& k){auto sec=p.find(k.section);if(sec==p.end())return nullptr;auto v=sec->second.find(k.key);return v==sec->second.end()?nullptr:&v->second;}
EffectiveValue value(const IniProjection& p,SettingKey key,const TrustedOwnershipContext* ownership,const std::set<SettingKey>& proposed){
    EffectiveValue out;out.setting=key;const bool boolean=key.key=="cache_credentials";const bool seconds=key.key=="cached_auth_timeout";
    const auto v=lookup(p,key);out.explicitValue=v!=nullptr;
    out.raw=v?v->value:(boolean?"false":"0");out.source=v?v->source:"native-default";
    out.origin=!v?ValueOrigin::NativeDefault:v->source==ownedFile?ValueOrigin::Unknown:ValueOrigin::Foreign;
    if(v&&v->source==ownedFile&&ownership&&ownership->ownedValues.count(key))out.origin=ValueOrigin::FicOwned;
    if(v&&v->source==ownedFile&&proposed.count(key)){out.origin=ValueOrigin::Proposed;out.hypothetical=true;}
    if(boolean){auto b=detail_i2::boolean(out.raw);if(b)out.value=*b;else{out.status=SemanticStatus::UnsupportedConfiguration;out.diagnostic="expected native case-insensitive true/false; not yes/no/1/0";}return out;}
    std::uint32_t parsed=0;
    auto result=std::from_chars(out.raw.data(),out.raw.data()+out.raw.size(),parsed,10);
    if(out.raw.empty()||(out.raw.size()>1&&out.raw.front()=='0')||!std::all_of(out.raw.begin(),out.raw.end(),[](char c){return c>='0'&&c<='9';})||result.ec!=std::errc{}||result.ptr!=out.raw.data()+out.raw.size()){
        out.status=SemanticStatus::InvalidInput;out.diagnostic="expected unsigned decimal integer without sign/suffix or overflow";return out;
    }
    if(!seconds&&parsed>3650){out.status=SemanticStatus::UnsupportedConfiguration;out.diagnostic="outside bounded FIC semantic days contract 0..3650; not a native SSSD range claim";return out;}
    if(seconds)out.value=Seconds{parsed};else out.value=Days{parsed};return out;
}
std::optional<std::string> proposedText(const ProposedSetting& s){
    if(s.setting.key=="cache_credentials"){auto b=std::get_if<bool>(&s.value);if(b&&*b)return "true";return {};}
    if(s.setting.key=="offline_credentials_expiration"||s.setting.key=="account_cache_expiration"){
        auto days=std::get_if<Days>(&s.value);if(days&&days->value<=3650)return std::to_string(days->value);
    }return {};
}
}
namespace detail_i2 {
bool ownershipMatches(const SssdInputReference& input,const TrustedOwnershipContext& ctx){
    if(ctx.proofIdentity.empty()||ctx.ownedValues.empty()||ctx.graphFingerprint!=inputFingerprint(input))return false;
    const auto graph=orderedGraph(input);auto own=std::find_if(graph.begin(),graph.end(),[](const auto& s){return s.first==ownedFile;});
    if(own==graph.end())return false;
    for(const auto& [k,expected]:ctx.ownedValues){auto v=lookup(own->second,k);if(!v||v->value!=expected)return false;}
    return true;
}
EffectiveConfiguration effectiveProjection(const SssdInputReference& input,const IniProjection& p,const TrustedOwnershipContext* ownership,const std::set<SettingKey>& proposed,const OrderedGraph* hypothetical){
    EffectiveConfiguration out{scopeProjection(input,p,hypothetical),value(p,{"pam","offline_credentials_expiration"},ownership,proposed),{}, {}};
    out.issues=out.scope.data().issues;
    auto record=[&](const EffectiveValue& v){if(v.status!=SemanticStatus::Validated)out.issues.push_back({v.status,v.setting.section,v.setting.key,v.diagnostic});};
    record(out.offlineDays);
    for(const auto& name:out.scope.data().configured){const auto sec="domain/"+name;
        DomainValues values{value(p,{sec,"cache_credentials"},ownership,proposed),value(p,{sec,"account_cache_expiration"},ownership,proposed),value(p,{sec,"cached_auth_timeout"},ownership,proposed),{}};
        // Source-derived expected in-memory clamp; not observation of consumer memory.
        if(auto seconds=std::get_if<Seconds>(&values.cachedAuthSeconds.value))if(auto offline=std::get_if<Days>(&out.offlineDays.value))
            values.expectedCachedAuthSeconds=Seconds{offline->value?std::min(seconds->value,offline->value*86400u):seconds->value};
        if(out.scope.data().domains.at(name).selected||out.scope.data().domains.at(name).enabled){record(values.cacheCredentials);record(values.accountDays);record(values.cachedAuthSeconds);}
        out.domains.emplace(name,std::move(values));
    }return out;
}
}
EffectiveConfiguration effectiveConfiguration(const SssdInputReference& input,const TrustedOwnershipContext* ownership){
    const bool trusted=!ownership||detail_i2::ownershipMatches(input,*ownership);
    auto result=detail_i2::effectiveProjection(input,detail_i2::merge(detail_i2::orderedGraph(input)),trusted?ownership:nullptr);
    if(!trusted)result.issues.push_back({SemanticStatus::NotProven,"","ownership","ownership assertion does not match exact I1 graph and own key values"});
    return result;
}
ConfigurationPreview previewConfiguration(const SssdInputReference& input,const DomainScopeReference& scope,const ProposedChange& change,const TrustedOwnershipContext* ownership){
    ConfigurationPreview out;
    auto refuse=[&](SemanticStatus status,const std::string& why){out.issues.push_back({status,"","preview",why});return out;};
    if(!sameScopeReference(domainScope(input),scope))return refuse(SemanticStatus::NotProven,"stale input/scope reference; re-evaluation required");
    if(change.settings.empty())return refuse(SemanticStatus::InvalidInput,"empty proposed operation");
    auto graph=detail_i2::orderedGraph(input);
    auto own=std::find_if(graph.begin(),graph.end(),[](const auto& s){return s.first==ownedFile;});
    if((ownership&&!detail_i2::ownershipMatches(input,*ownership))||(own!=graph.end()&&!ownership))return refuse(SemanticStatus::NotProven,"existing shared drop-in requires graph-bound trusted ownership context");
    const bool release=change.operation==ProposedOperation::ReleasePreview;
    if(!release)for(const auto& [path,p]:graph)if(path>std::string(ownedFile)&&path.rfind("/etc/sssd/conf.d/",0)==0)return refuse(SemanticStatus::UnsupportedConfiguration,"later eligible foreign snippet blocks Apply/REFRESH regardless of contents");
    if(change.operation!=ProposedOperation::Apply&&!ownership)return refuse(SemanticStatus::NotProven,"REFRESH/release requires proven existing own keys");
    if(own==graph.end()){
        graph.emplace_back(ownedFile,IniProjection{});
        std::stable_sort(graph.begin(),graph.end(),[](const auto& a,const auto& b){if(a.first=="/etc/sssd/sssd.conf")return b.first!=a.first;if(b.first=="/etc/sssd/sssd.conf")return false;return a.first<b.first;});
        own=std::find_if(graph.begin(),graph.end(),[](const auto& s){return s.first==ownedFile;});
    }
    std::set<SettingKey> changed;
    for(const auto& item:change.settings){const auto& k=item.setting;
        if(!changed.insert(k).second)return refuse(SemanticStatus::InvalidInput,"duplicate proposed key");
        const bool global=k.section=="pam"&&k.key=="offline_credentials_expiration";
        const auto domain=k.section.rfind("domain/",0)==0?k.section.substr(7):"";
        const bool domainKey=!domain.empty()&&(k.key=="account_cache_expiration"||k.key=="cache_credentials");
        if(!global&&!domainKey)return refuse(SemanticStatus::UnsupportedConfiguration,"only owned offline/account/cache keys can change; cached_auth_timeout is read-only");
        if(!global&&!scope.data().domains.count(domain))return refuse(SemanticStatus::NotProven,"cannot manufacture unknown domain section");
        const auto old=lookup(own->second,k);
        if((old||change.operation!=ProposedOperation::Apply)&&(!ownership||!ownership->ownedValues.count(k)))return refuse(SemanticStatus::NotProven,"target key lacks ownership proof");
        if(release){if(!std::holds_alternative<std::monostate>(item.value))return refuse(SemanticStatus::InvalidInput,"release preview only removes keys");own->second[k.section].erase(k.key);}
        else{
            if(!global&&(!scope.data().domains.at(domain).selected||!scope.data().domains.at(domain).enabled))return refuse(SemanticStatus::UnsupportedConfiguration,"new/updated domain setting requires selected enabled root");
            auto text=proposedText(item);if(!text)return refuse(SemanticStatus::InvalidInput,"wrong typed unit/range or cache value (only fixed true may be proposed)");
            own->second[k.section][k.key]={*text,ownedFile};
        }
    }
    const auto merged=detail_i2::merge(graph);
    if(!release)for(const auto& item:change.settings){
        const auto effective=lookup(merged,item.setting);const auto expected=proposedText(item);
        if(!effective||!expected||effective->source!=ownedFile||effective->value!=*expected)
            return refuse(SemanticStatus::NotProven,"proposed own value is not effective after full ordered merge");
    }
    out.configuration=detail_i2::effectiveProjection(input,merged,ownership,release?std::set<SettingKey>{}:changed,&graph);
    const auto relations=validateRelations(*out.configuration);out.semanticStatus=relations.status;out.semanticIssues=relations.issues;
    out.projectionAvailable=true;return out; // Semantic conflicts do not forbid previewing release.
}
} // namespace fic::service::sssd
