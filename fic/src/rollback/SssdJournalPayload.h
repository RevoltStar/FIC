#pragma once
#include "rollback/MutationRecord.h"
#include <fic/core/integrity/ContentDigest.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <set>

namespace fic::rollback::sssd_payload {
using J=nlohmann::json;
inline const char* phaseName(SssdTransitionPhase phase) {
    switch(phase) {
    case SssdTransitionPhase::Prepared:return "prepared";
    case SssdTransitionPhase::MutationArmed:return "mutation_armed";
    case SssdTransitionPhase::Published:return "published";
    case SssdTransitionPhase::DurablePublished:return "durable_published";
    case SssdTransitionPhase::ActivationArmed:return "activation_armed";
    case SssdTransitionPhase::RuntimeVerified:return "runtime_verified";
    case SssdTransitionPhase::Completed:return "completed";
    case SssdTransitionPhase::OfflineVerified:return "offline_verified";
    case SssdTransitionPhase::ReleasedAwaitingDisable:return "released_awaiting_disable";
    }
    throw std::invalid_argument("unknown SSSD phase");
}
inline void to_json(J& j,const SssdAssignment& a) {j={{"section",a.section},{"key",a.key},{"value",a.value}};}
inline void from_json(const J& j,SssdAssignment& a) {a={j.at("section").get<std::string>(),j.at("key").get<std::string>(),j.at("value").get<std::string>()};}
inline J image(const SssdImageWitness& w) {
    return {{"present",w.present},{"device",w.device},{"inode",w.inode},{"mode",w.mode},{"owner",w.owner},{"group",w.group},{"sha256",w.sha256}};
}
inline std::uint64_t number(const J& j,const char* key) {
    const auto& v=j.at(key);if(!v.is_number_unsigned())throw std::invalid_argument("SSSD unsigned field");return v.get<std::uint64_t>();
}
inline std::uint32_t small(const J& j,const char* key) {
    auto n=number(j,key);if(n>UINT32_MAX)throw std::invalid_argument("SSSD field overflow");return n;
}
inline SssdImageWitness parseImage(const J& j) {
    return {j.at("present").get<bool>(),number(j,"device"),number(j,"inode"),small(j,"mode"),small(j,"owner"),small(j,"group"),j.at("sha256").get<std::string>()};
}
inline J assignments(const std::vector<SssdAssignment>& v) {J out=J::array();for(const auto& a:v){J e;to_json(e,a);out.push_back(e);}return out;}
inline std::vector<SssdAssignment> parseAssignments(const J& j) {
    if(!j.is_array()||j.size()>256)throw std::invalid_argument("SSSD assignment bound");
    std::vector<SssdAssignment> out;for(const auto& e:j){SssdAssignment a;from_json(e,a);out.push_back(std::move(a));}return out;
}
inline J state(const SssdOwnedState& s) {
    return {{"assignments",assignments(s.assignments)},{"scope",s.scope},{"sequence",s.sequence},{"publication",image(s.publication)}};
}
inline SssdOwnedState parseState(const J& j) {return {parseAssignments(j.at("assignments")),j.at("scope").get<std::string>(),number(j,"sequence"),parseImage(j.at("publication"))};}
inline J container(const std::optional<SssdContainerWitness>& c) {
    if(!c)return nullptr;
    return {{"sequence",c->sequence},{"release_id",c->releaseId},{"publication",image(c->publication)}};
}
inline std::optional<SssdContainerWitness> parseContainer(const J& j) {
    if(j.is_null())return {};
    return SssdContainerWitness{number(j,"sequence"),number(j,"release_id"),parseImage(j.at("publication"))};
}
inline J release(const SssdReleaseDetails& d) {
    J survivors=J::array();for(const auto& o:d.survivors)
        survivors.push_back({{"id",o.id},{"policy",o.policy},{"state",state(o.state)},{"container",container(o.container)}});
    return {{"intent",d.intent==SssdReleaseIntent::ReleaseOnly?"release_only":"disable_release"},
        {"survivors",survivors},{"remaining",assignments(d.remaining)},{"target_absent",d.targetAbsent},
        {"offline",d.offline},{"offline_verified",d.offlineVerified},{"ownership_generation",d.ownershipGeneration},
        {"service_before",d.serviceBefore},{"service_after",d.serviceAfter},{"staged_path",d.stagedPath},
        {"disable_generation",d.disableGeneration},{"released_graph_fingerprint",d.releasedGraphFingerprint}};
}
inline SssdReleaseDetails parseRelease(const J& j) {
    SssdReleaseDetails d;
    if(j.at("intent")=="release_only")d.intent=SssdReleaseIntent::ReleaseOnly;
    else if(j.at("intent")=="disable_release")d.intent=SssdReleaseIntent::DisableRelease;
    else throw std::invalid_argument("unknown SSSD release intent");
    if(!j.at("survivors").is_array()||j.at("survivors").size()>2)throw std::invalid_argument("SSSD surviving owner bound");
    for(const auto& o:j.at("survivors"))d.survivors.push_back({number(o,"id"),o.at("policy").get<std::string>(),parseState(o.at("state")),parseContainer(o.at("container"))});
    d.remaining=parseAssignments(j.at("remaining"));d.targetAbsent=j.at("target_absent").get<bool>();
    d.offline=j.at("offline").get<bool>();d.offlineVerified=j.at("offline_verified").get<bool>();
    d.ownershipGeneration=j.at("ownership_generation").get<std::string>();d.serviceBefore=j.at("service_before").get<std::string>();
    d.serviceAfter=j.at("service_after").get<std::string>();d.stagedPath=j.at("staged_path").get<std::string>();
    d.disableGeneration=j.at("disable_generation").get<std::string>();d.releasedGraphFingerprint=j.at("released_graph_fingerprint").get<std::string>();return d;
}
inline J encode(const SssdJournalOwnership& own) {
    const bool v2=own.container||(own.transition&&own.transition->release);
    J j={{"version",v2?2u:1u},{"current",state(own.current)},{"transition",nullptr}};
    if(v2)j["container"]=container(own.container);
    if(own.transition) {
        const auto& t=*own.transition;
        j["transition"]={{"version",t.version},{"sequence",t.sequence},{"phase",phaseName(t.phase)},
            {"previous",state(t.previous)},{"target",assignments(t.target)},{"target_scope",t.targetScope},
            {"input_fingerprint",t.inputFingerprint},{"target_sha256",t.targetSha256},
            {"before",image(t.before)},{"publication",image(t.publication)},
            {"publication_durable",t.publicationDurable},{"activation_possible",t.activationPossible},
            {"a",t.a},{"b",t.b},{"c",t.c},{"p",t.p},{"clean",t.clean},
            {"residuals",t.residuals},{"cleanup_errors",t.cleanupErrors},{"runtime_facts",t.runtimeFacts}};
        if(t.release)j["transition"]["release"]=release(*t.release);
    }
    return j;
}
inline SssdJournalOwnership decode(const J& j) {
    const auto version=number(j,"version");
    if(version!=1&&version!=2)throw std::invalid_argument("unknown SSSD ownership version");
    SssdJournalOwnership out;out.current=parseState(j.at("current"));
    if(version==2)out.container=parseContainer(j.at("container"));
    else if(j.contains("container"))throw std::invalid_argument("I4 version 1 cannot contain handoff authority");
    if(!j.at("transition").is_null()) {
        const auto& v=j.at("transition");SssdOwnershipTransition t;
        t.version=small(v,"version");t.sequence=number(v,"sequence");
        bool found=false;for(auto p:{SssdTransitionPhase::Prepared,SssdTransitionPhase::MutationArmed,SssdTransitionPhase::Published,
            SssdTransitionPhase::DurablePublished,SssdTransitionPhase::ActivationArmed,SssdTransitionPhase::RuntimeVerified,SssdTransitionPhase::Completed,SssdTransitionPhase::OfflineVerified,SssdTransitionPhase::ReleasedAwaitingDisable})
            if(v.at("phase")==phaseName(p)){t.phase=p;found=true;}
        if(!found)throw std::invalid_argument("unknown SSSD transition phase");
        t.previous=parseState(v.at("previous"));t.target=parseAssignments(v.at("target"));
        t.targetScope=v.at("target_scope").get<std::string>();t.inputFingerprint=v.at("input_fingerprint").get<std::string>();
        t.targetSha256=v.at("target_sha256").get<std::string>();t.before=parseImage(v.at("before"));t.publication=parseImage(v.at("publication"));
        t.publicationDurable=v.at("publication_durable").get<bool>();t.activationPossible=v.at("activation_possible").get<bool>();
        t.a=v.at("a").get<bool>();t.b=v.at("b").get<bool>();t.c=v.at("c").get<bool>();t.p=v.at("p").get<bool>();t.clean=v.at("clean").get<bool>();
        t.residuals=v.at("residuals").get<std::vector<std::string>>();t.cleanupErrors=v.at("cleanup_errors").get<std::vector<std::string>>();
        t.runtimeFacts=v.at("runtime_facts").get<std::map<std::string,std::string>>();
        if(v.contains("release")) {
            if(version!=2)throw std::invalid_argument("I4 version 1 cannot contain release intent");
            t.release=parseRelease(v.at("release"));
        }
        out.transition=std::move(t);
    }
    return out;
}
inline bool validImage(const SssdImageWitness& w) {
    if(!w.present)return w.device==0&&w.inode==0&&w.mode==0&&w.owner==0&&w.group==0&&w.sha256.empty();
    return w.inode!=0&&w.owner==0&&(w.mode==0600||w.mode==0640)&&fic::core::ContentDigest::isCanonicalSha256Hex(w.sha256);
}
inline bool validAssignments(const std::vector<SssdAssignment>& as,const std::string& policy) {
    if(as.empty()||as.size()>256)return false;
    std::pair<std::string,std::string> last;bool haveLast=false;
    for(const auto& a:as) {
        auto key=std::make_pair(a.section,a.key);
        if(haveLast&&key<=last)return false;last=key;haveLast=true;
        if(a.key=="offline_credentials_expiration") {
            if(policy!="sssd_offline_credentials_expiration"||a.section!="pam"||as.size()!=1)return false;
        } else {
            if(a.section.rfind("domain/",0)!=0||a.section.size()<=7||a.section.size()>262)return false;
            for(char c:a.section.substr(7))if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return false;
            if((a.key!="cache_credentials"&&a.key!="account_cache_expiration")||policy!="sssd_"+a.key)return false;
        }
        if(a.key=="cache_credentials") {if(a.value!="true")return false;}
        else {
            unsigned days=0;auto r=std::from_chars(a.value.data(),a.value.data()+a.value.size(),days);
            if(a.value.empty()||r.ec!=std::errc{}||r.ptr!=a.value.data()+a.value.size()||days>3650||std::to_string(days)!=a.value)return false;
        }
    }
    return true;
}
inline bool validState(const SssdOwnedState& s,const std::string& policy,bool emptyAllowed) {
    if(s.assignments.empty())return emptyAllowed&&s.scope.empty()&&s.sequence==0&&!s.publication.present&&validImage(s.publication);
    return validAssignments(s.assignments,policy)&&s.sequence>0&&!s.scope.empty()&&s.scope.size()<65536&&s.publication.present&&validImage(s.publication);
}
inline bool validContainer(const std::optional<SssdContainerWitness>& c,const SssdOwnedState& s) {
    return !c||(c->sequence>s.sequence&&c->releaseId>0&&c->publication.present&&validImage(c->publication));
}
inline std::uint64_t sequence(const SssdJournalOwnership& o) {
    return o.container?o.container->sequence:o.current.sequence;
}
inline const SssdImageWitness& publication(const SssdJournalOwnership& o) {
    return o.container?o.container->publication:o.current.publication;
}
inline std::string rendered(const std::vector<SssdAssignment>& as) {
    std::map<std::string,std::map<std::string,std::string>> m;
    for(const auto& a:as)if(!m[a.section].emplace(a.key,a.value).second)throw std::invalid_argument("duplicate SSSD projection");
    std::string out;for(const auto& [section,keys]:m){out+="["+section+"]\n";for(const auto& [key,value]:keys)out+=key+" = "+value+"\n";out+="\n";}return out;
}
inline bool validReleaseRecord(const MutationRecord& r,const SssdJournalOwnership& o,std::string& error) {
    auto fail=[&](){error="Invalid SSSD I5 release identity/projection/proof";return false;};
    const auto& t=*o.transition;const auto& d=*t.release;
    if(t.version!=2||!t.targetScope.empty()||t.previous.assignments.empty()||state(o.current)!=state(t.previous)||!t.target.empty()||
       !validState(t.previous,r.policy.policyName,false)||t.sequence<=sequence(o)||!t.before.present||!validImage(t.before)||!validImage(t.publication)||
       !fic::core::ContentDigest::isCanonicalSha256Hex(t.inputFingerprint)||!fic::core::ContentDigest::isCanonicalSha256Hex(t.targetSha256)||
       !fic::core::ContentDigest::isCanonicalSha256Hex(d.ownershipGeneration)||!fic::core::ContentDigest::isCanonicalSha256Hex(d.serviceBefore)||
       d.survivors.size()>2||d.targetAbsent!=d.remaining.empty()||t.residuals.size()>64||t.cleanupErrors.size()>64||t.runtimeFacts.size()>128)return fail();
    if(d.intent!=SssdReleaseIntent::ReleaseOnly&&d.intent!=SssdReleaseIntent::DisableRelease)return fail();
    const auto stage="/etc/sssd/conf.d/zzzz-fic.conf.fic-removing-i5-"+std::to_string(r.id)+"-"+std::to_string(t.sequence);
    if(d.stagedPath!=(d.targetAbsent?stage:std::string()))return fail();
    std::set<MutationId> ids;std::set<std::string> policies;std::vector<SssdAssignment> expected;
    for(const auto& p:d.survivors) {
        if(p.id==0||p.id==r.id||!ids.insert(p.id).second||p.policy==r.policy.policyName||!policies.insert(p.policy).second||
           !validState(p.state,p.policy,false)||!validContainer(p.container,p.state)||
           t.sequence<=(p.container?p.container->sequence:p.state.sequence))return fail();
        expected.insert(expected.end(),p.state.assignments.begin(),p.state.assignments.end());
    }
    std::sort(expected.begin(),expected.end(),[](const auto& a,const auto& b){return std::tie(a.section,a.key)<std::tie(b.section,b.key);});
    if(expected!=d.remaining)return fail();
    std::uint64_t latest=sequence(o);SssdImageWitness before=publication(o);
    std::set<std::pair<std::string,std::string>> keys;
    for(const auto& a:t.previous.assignments)keys.emplace(a.section,a.key);
    for(const auto& a:d.remaining)if(!keys.emplace(a.section,a.key).second)return fail();
    for(const auto& p:d.survivors) {
        const auto seq=p.container?p.container->sequence:p.state.sequence;
        const auto& pub=p.container?p.container->publication:p.state.publication;
        if(seq==latest&&image(pub)!=image(before))return fail();
        if(seq>latest){latest=seq;before=pub;}
    }
    if(image(t.before)!=image(before))return fail();
    try{if(fic::core::ContentDigest::sha256Hex(rendered(expected))!=t.targetSha256)return fail();}catch(...){return fail();}
    const bool complete=t.phase==SssdTransitionPhase::Completed,awaiting=t.phase==SssdTransitionPhase::ReleasedAwaitingDisable;
    if((complete&&r.status!=MutationStatus::RolledBack)||(!complete&&r.status!=MutationStatus::Prepared))return fail();
    switch(t.phase) {
    case SssdTransitionPhase::Prepared:case SssdTransitionPhase::MutationArmed:
        if(t.publication.present||t.publicationDurable||t.activationPossible||d.offlineVerified||t.a||t.b||t.c||t.p||t.clean||!t.runtimeFacts.empty())return fail();break;
    case SssdTransitionPhase::Published:case SssdTransitionPhase::DurablePublished:case SssdTransitionPhase::ActivationArmed:
    case SssdTransitionPhase::RuntimeVerified:case SssdTransitionPhase::OfflineVerified:
    case SssdTransitionPhase::ReleasedAwaitingDisable:case SssdTransitionPhase::Completed:
        if(t.publication.present==d.targetAbsent||(!d.targetAbsent&&t.publication.sha256!=t.targetSha256))return fail();
        if(t.phase!=SssdTransitionPhase::Published&&!t.publicationDurable)return fail();break;
    default:return fail();
    }
    const bool verified=t.phase==SssdTransitionPhase::RuntimeVerified||t.phase==SssdTransitionPhase::OfflineVerified||awaiting||complete;
    if(d.offline) {
        if(t.activationPossible||t.a||t.b||t.c||t.phase==SssdTransitionPhase::ActivationArmed||t.phase==SssdTransitionPhase::RuntimeVerified)return fail();
        if(verified&&!d.offlineVerified)return fail();
    } else {
        if(d.offlineVerified||t.phase==SssdTransitionPhase::OfflineVerified)return fail();
        if(verified&&(!t.activationPossible||!t.a||!t.b||!t.c))return fail();
    }
    if(verified&&(!t.p||!t.clean||!t.residuals.empty()||!t.cleanupErrors.empty()||
       !fic::core::ContentDigest::isCanonicalSha256Hex(d.serviceAfter)||!fic::core::ContentDigest::isCanonicalSha256Hex(d.releasedGraphFingerprint)))return fail();
    if(awaiting&&d.intent!=SssdReleaseIntent::DisableRelease)return fail();
    // I5 cannot authenticate administrative registry/config generations.
    // Reserve the field, but reject fabricated terminal disable documents too,
    // not merely the public transition call. I6 must supply the real contract.
    if((complete&&d.intent==SssdReleaseIntent::DisableRelease)||!d.disableGeneration.empty())return fail();
    return true;
}
inline bool validRecord(const MutationRecord& r,std::string& error) {
    const auto* own=std::get_if<SssdJournalOwnership>(&r.undo.payload);if(!own)return true;
    auto fail=[&](){error="Invalid SSSD I4 identity/ownership/transition facts";return false;};
    if(r.undo.backend!=MutationBackend::Sssd||r.policy.moduleName!="IDENTITY_ACCESS"||r.policy.submoduleName!="SSSD"||
       r.resource!="sssd/managed/"+r.policy.policyName||!validState(own->current,r.policy.policyName,true)||!validContainer(own->container,own->current))return fail();
    if(!own->transition)return !own->current.assignments.empty()&&r.status==MutationStatus::Applied ? true:fail();
    if(own->transition->release)return validReleaseRecord(r,*own,error);
    const auto& t=*own->transition;const bool completed=t.phase==SssdTransitionPhase::Completed;
    if(static_cast<int>(t.phase)<0||static_cast<int>(t.phase)>static_cast<int>(SssdTransitionPhase::Completed)||t.version!=1||!validAssignments(t.target,r.policy.policyName)||!validState(t.previous,r.policy.policyName,true)||
       t.sequence<=t.previous.sequence||t.targetScope.empty()||t.targetScope.size()>=65536||!validImage(t.before)||!validImage(t.publication)||
       !fic::core::ContentDigest::isCanonicalSha256Hex(t.inputFingerprint)||!fic::core::ContentDigest::isCanonicalSha256Hex(t.targetSha256)||
       t.residuals.size()>64||t.cleanupErrors.size()>64||t.runtimeFacts.size()>128)return fail();
    if((completed&&r.status!=MutationStatus::Applied)||(!completed&&r.status!=MutationStatus::Prepared))return fail();
    if(state(own->current)!=(completed?state(SssdOwnedState{t.target,t.targetScope,t.sequence,t.publication}):state(t.previous)))return fail();
    if(t.phase<=SssdTransitionPhase::MutationArmed&&(t.publication.present||t.publicationDurable||t.activationPossible||t.a||t.b||t.c||t.p||t.clean||!t.runtimeFacts.empty()||!t.residuals.empty()||!t.cleanupErrors.empty()))return fail();
    if(t.phase>=SssdTransitionPhase::Published&&(!t.publication.present||t.publication.sha256!=t.targetSha256))return fail();
    if(t.phase>=SssdTransitionPhase::DurablePublished&&!t.publicationDurable)return fail();
    if(t.phase<SssdTransitionPhase::ActivationArmed&&(t.activationPossible||t.a||t.b||t.c||t.p||t.clean))return fail();
    if(t.phase>=SssdTransitionPhase::RuntimeVerified&&(!t.activationPossible||!t.a||!t.b||!t.c||!t.p||!t.clean||!t.residuals.empty()||!t.cleanupErrors.empty()))return fail();
    return true;
}
inline bool validContainerLinks(const std::vector<MutationRecord>& records,std::string& error) {
    for(const auto& owner:records) {
        auto p=std::get_if<SssdJournalOwnership>(&owner.undo.payload);if(!p||!p->container||!owner.isActive())continue;
        const auto& c=*p->container;const MutationRecord* source=nullptr;
        for(const auto& r:records)if(r.id==c.releaseId)source=&r;
        auto released=source?std::get_if<SssdJournalOwnership>(&source->undo.payload):nullptr;
        if(!released||source->status!=MutationStatus::RolledBack||!released->transition||!released->transition->release||
           released->transition->phase!=SssdTransitionPhase::Completed||released->transition->sequence!=c.sequence||
           image(released->transition->publication)!=image(c.publication)) {error="SSSD container handoff has no terminal release provenance";return false;}
        const auto& survivors=released->transition->release->survivors;
        auto found=std::find_if(survivors.begin(),survivors.end(),[&](const auto& s){return s.id==owner.id;});
        if(found==survivors.end()||found->policy!=owner.policy.policyName||state(found->state)!=state(p->current)) {
            error="SSSD handoff changed surviving assignment authority";return false;
        }
    }
    return true;
}
} // namespace fic::rollback::sssd_payload
