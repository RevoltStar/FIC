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
inline J encode(const SssdJournalOwnership& own) {
    J j={{"version",1u},{"current",state(own.current)},{"transition",nullptr}};
    if(own.transition) {
        const auto& t=*own.transition;
        j["transition"]={{"version",t.version},{"sequence",t.sequence},{"phase",phaseName(t.phase)},
            {"previous",state(t.previous)},{"target",assignments(t.target)},{"target_scope",t.targetScope},
            {"input_fingerprint",t.inputFingerprint},{"target_sha256",t.targetSha256},
            {"before",image(t.before)},{"publication",image(t.publication)},
            {"publication_durable",t.publicationDurable},{"activation_possible",t.activationPossible},
            {"a",t.a},{"b",t.b},{"c",t.c},{"p",t.p},{"clean",t.clean},
            {"residuals",t.residuals},{"cleanup_errors",t.cleanupErrors},{"runtime_facts",t.runtimeFacts}};
    }
    return j;
}
inline SssdJournalOwnership decode(const J& j) {
    if(number(j,"version")!=1)throw std::invalid_argument("unknown SSSD ownership version");
    SssdJournalOwnership out;out.current=parseState(j.at("current"));
    if(!j.at("transition").is_null()) {
        const auto& v=j.at("transition");SssdOwnershipTransition t;
        t.version=small(v,"version");t.sequence=number(v,"sequence");
        bool found=false;for(auto p:{SssdTransitionPhase::Prepared,SssdTransitionPhase::MutationArmed,SssdTransitionPhase::Published,
            SssdTransitionPhase::DurablePublished,SssdTransitionPhase::ActivationArmed,SssdTransitionPhase::RuntimeVerified,SssdTransitionPhase::Completed})
            if(v.at("phase")==phaseName(p)){t.phase=p;found=true;}
        if(!found)throw std::invalid_argument("unknown SSSD transition phase");
        t.previous=parseState(v.at("previous"));t.target=parseAssignments(v.at("target"));
        t.targetScope=v.at("target_scope").get<std::string>();t.inputFingerprint=v.at("input_fingerprint").get<std::string>();
        t.targetSha256=v.at("target_sha256").get<std::string>();t.before=parseImage(v.at("before"));t.publication=parseImage(v.at("publication"));
        t.publicationDurable=v.at("publication_durable").get<bool>();t.activationPossible=v.at("activation_possible").get<bool>();
        t.a=v.at("a").get<bool>();t.b=v.at("b").get<bool>();t.c=v.at("c").get<bool>();t.p=v.at("p").get<bool>();t.clean=v.at("clean").get<bool>();
        t.residuals=v.at("residuals").get<std::vector<std::string>>();t.cleanupErrors=v.at("cleanup_errors").get<std::vector<std::string>>();
        t.runtimeFacts=v.at("runtime_facts").get<std::map<std::string,std::string>>();out.transition=std::move(t);
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
inline bool validRecord(const MutationRecord& r,std::string& error) {
    const auto* own=std::get_if<SssdJournalOwnership>(&r.undo.payload);if(!own)return true;
    auto fail=[&](){error="Invalid SSSD I4 identity/ownership/transition facts";return false;};
    if(r.undo.backend!=MutationBackend::Sssd||r.policy.moduleName!="IDENTITY_ACCESS"||r.policy.submoduleName!="SSSD"||
       r.resource!="sssd/managed/"+r.policy.policyName||!validState(own->current,r.policy.policyName,true))return fail();
    if(!own->transition)return !own->current.assignments.empty()&&r.status==MutationStatus::Applied ? true:fail();
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
} // namespace fic::rollback::sssd_payload
