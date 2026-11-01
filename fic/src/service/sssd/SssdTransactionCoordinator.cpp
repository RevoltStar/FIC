#include "service/sssd/SssdTransactionCoordinator.h"
#include "rollback/SssdJournalPayload.h"
#include "modules/identity_access/sssd/SssdConfiguration.h"
#include "service/sssd/SssdRuntimeProof.h"
#include "service/sssd/SssdApplyIntent.h"
#include "service/sssd/SssdReleaseReceipt.h"
#include "rollback/SssdDisableProof.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fcntl.h>
#include <algorithm>
#include <mutex>
#include <sstream>

namespace fic::service::sssd {
namespace r=fic::rollback;
namespace d=fic::service::detail;
namespace j=r::sssd_payload;
namespace {
constexpr const char* file="/etc/sssd/conf.d/zzzz-fic.conf";
constexpr const char* relative="conf.d/zzzz-fic.conf";
std::timed_mutex resourceMutex;
std::string sha(const std::string& bytes){return fic::core::ContentDigest::sha256Hex(bytes);}
[[noreturn]] void refuse(const std::string& why){throw std::runtime_error("SSSD transaction: "+why);}
std::chrono::milliseconds remaining(Deadline end) {
    const auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(end-std::chrono::steady_clock::now());
    if(ms.count()<=0||ms>std::chrono::minutes(5))refuse("deadline expired/outside bounded contract");return ms;
}
r::SssdImageWitness witness(const AtomicTargetState& s) {
    return {true,static_cast<std::uint64_t>(s.identity.device),s.identity.inode,static_cast<std::uint32_t>(s.mode&07777),s.owner,s.group,sha(s.content)};
}
bool matches(const r::SssdImageWitness& w,const std::optional<AtomicTargetState>& s) {
    return w.present==bool(s)&&(!s||j::image(w)==j::image(witness(*s)));
}
std::optional<AtomicTargetState> physical() {
    // No symlinks in ancestors; no implicit conf.d creation.
    auto parent=d::openAbsolute("/etc/sssd/conf.d",O_PATH|O_DIRECTORY);
    const auto directory=d::identity(parent.get());
    if(directory.uid!=0||(directory.mode&0022))refuse("untrusted managed directory");
    struct stat st{};
    if(::fstatat(parent.get(),"zzzz-fic.conf",&st,AT_SYMLINK_NOFOLLOW)!=0) {
        if(errno==ENOENT)return {};refuse("cannot prove managed file presence");
    }
    AtomicTargetState s;std::string error;
    if(!AtomicFileWriter::captureTargetState(file,s,&error))refuse(error);
    if(s.owner!=0||((s.mode&07777)!=0600&&(s.mode&07777)!=0640)||st.st_nlink!=1)refuse("unsafe managed metadata");
    return s;
}
void stagedArtifacts(const d::Tree& tree) {
    for(const auto& [name,st]:tree.attributes)
        if(name.rfind("conf.d/.zzzz-fic.conf",0)==0||name.rfind("conf.d/"+fic::identity::sssd::managedSnippetRemovalStagingPrefix("zzzz-fic.conf"),0)==0)refuse("unresolved managed staging artifact: "+name);
}
std::vector<std::string> residualMounts() {
    std::vector<std::string> out;
    for(const auto& m:d::readMountInfo())
        if(m.source.rfind("fic-vcsa.",0)==0||m.target=="/etc/sssd"||d::below(m.target,"/etc/sssd"))out.push_back(m.target);
    return out;
}
void journalProof(r::MutationJournal& journal) {
    std::string error;
    if(!journal.lifecycleInitialized()||!journal.validatePersistentStateReadOnly(error)||!journal.usable())refuse("witness-aware journal unavailable: "+error);
}
struct Ownership {
    std::vector<r::SssdAssignment> all;
    std::map<std::string,r::MutationRecord> policies;
    r::SssdImageWitness image;
    std::uint64_t sequence=0;
};
Ownership ownership(r::MutationJournal& journal,const SssdInputReference& input,const std::optional<AtomicTargetState>& current,bool release=false) {
    Ownership out;std::set<SettingKey> unique;
    for(const auto& rec:journal.records())if(rec.isActive()&&rec.undo.backend==r::MutationBackend::Sssd) {
        auto* p=std::get_if<r::SssdJournalOwnership>(&rec.undo.payload);
        if(!p)refuse("legacy SSSD ownership requires future I6 integration; provenance preserved");
        std::string error;if(!j::validRecord(rec,error))refuse(error);
        if(rec.status!=r::MutationStatus::Applied||(p->transition&&p->transition->phase!=r::SssdTransitionPhase::Completed))refuse("unresolved shared SSSD transition");
        const auto kind=rec.policy.policyName=="sssd_cache_credentials"?SssdManagedParameter::CacheCredentials:
            rec.policy.policyName=="sssd_account_cache_expiration"?SssdManagedParameter::AccountCacheExpiration:SssdManagedParameter::OfflineCredentialsExpiration;
        const auto value=kind==SssdManagedParameter::CacheCredentials?SemanticValue(true):
            SemanticValue(Days{static_cast<std::uint32_t>(std::stoul(p->current.assignments.front().value))});
        if(!release&&detail_i4::targetAssignments(domainScope(input),kind,value)!=p->current.assignments)
            refuse("SSSD sibling ownership has incomplete/inconsistent target set");
        if(!out.policies.emplace(rec.policy.policyName,rec).second)refuse("duplicate SSSD owner");
        if(!release&&p->current.scope!=detail_i4::scopeIdentity(domainScope(input)))refuse("domain/provider scope changed; no automatic scope migration");
        if(j::sequence(*p)>out.sequence){out.sequence=j::sequence(*p);out.image=j::publication(*p);}
        for(const auto& a:p->current.assignments) {
            if(!unique.insert({a.section,a.key}).second)refuse("duplicate owned section/key");out.all.push_back(a);
        }
    }
    std::sort(out.all.begin(),out.all.end(),[](const auto& a,const auto& b){return std::tie(a.section,a.key)<std::tie(b.section,b.key);});
    if(out.all.empty()) {if(current)refuse("orphan managed file; filename/content is not provenance");}
    else if(!current||!matches(out.image,current)||current->content!=detail_i4::renderAssignments(out.all))refuse("owned image/identity/assignments drift; no repair/adoption");
    return out;
}
std::vector<SssdSemanticExpectation> expectations(const std::vector<r::SssdAssignment>& all) {
    std::vector<SssdSemanticExpectation> out;
    for(const auto& a:all)out.push_back({{a.section,a.key},a.key=="cache_credentials"?SemanticValue(true):SemanticValue(Days{static_cast<std::uint32_t>(std::stoul(a.value))})});
    return out;
}
struct AdministrativeProof {
    std::string generation;
    std::vector<r::SssdAssignment> required;
    std::map<std::string,std::vector<r::SssdAssignment>> requiredByPolicy;
};
struct AdministrativeConfiguration {
    std::string path, generation;
    AtomicTargetState state;
    std::unordered_map<std::string,std::string> entries;
};
AdministrativeConfiguration administrativeConfiguration(PolicyRegistry& registry) {
    detail_i6::verifyRegisteredPolicySet(registry);
    std::optional<AtomicTargetState> snapshot;std::string path,error;
    const auto expectedPath=(fic::core::FicRuntimePaths::get().configDir/"IDENTITY_ACCESS.conf").string();
    for(const auto parameter:{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration}) {
        const auto ref=detail_i4::policyIdentity(parameter);auto* member=registry.findPolicy(ref);
        AtomicTargetState captured;std::string memberPath;
        if(!member||member->ownerRegistry()!=&registry||!member->captureConfigurationVersion(memberPath,captured,error)||
           memberPath!=expectedPath||captured.owner!=0||(captured.mode&0022))refuse("complete current SSSD registry/configuration unproven: "+error);
        if(snapshot&&j::image(witness(*snapshot))!=j::image(witness(captured)))refuse("mixed SSSD registry configuration generations");
        snapshot=captured;path=memberPath;
    }
    FileHandlerOptions options;options.writeOptions.rejectSymlink=true;options.writeOptions.createIfMissing=false;
    ConfigFileHandler current(path,"=",options);
    if(!current.loadConfig())refuse("cannot read current SSSD administrative configuration");
    for(const auto parameter:{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration}) {
        const auto ref=detail_i4::policyIdentity(parameter);const auto status=current.entries().find(ref.policyName+".status");
        if(status==current.entries().end())continue; // unconfigured, never explicit DISABLE
        if((status->second!="ENABLE"&&status->second!="DISABLE")||
           registry.findPolicy(ref)->isEnabled()!=(status->second=="ENABLE"))refuse("invalid/inconsistent SSSD registry status: "+ref.policyName);
    }
    if(!AtomicFileWriter::targetStateMatches(path,*snapshot,&error)||
       !AtomicFileWriter::ensureTargetDurableIfCurrentState(path,*snapshot,&error))refuse("administrative configuration durability/drift: "+error);
    return {path,sha(j::J{{"path",path},{"witness",j::image(witness(*snapshot))}}.dump()),*snapshot,current.entries()};
}
AdministrativeProof administrativeProof(PolicyRegistry& registry,const PolicyRef& releasing,
                                       const std::string& expectedStatus,const SssdInputReference& input) {
    AdministrativeProof out;const auto current=administrativeConfiguration(registry);
    for(const auto parameter:{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration}) {
        const auto ref=detail_i4::policyIdentity(parameter);auto* member=registry.findPolicy(ref);
        const auto entry=current.entries.find(ref.policyName+".status");
        // Absent new entries are unconfigured, never an explicit DISABLE.
        if(entry==current.entries.end()) {if(ref==releasing)refuse("explicit releasing status missing");continue;}
        const auto& status=entry->second;
        if(status!="ENABLE"&&status!="DISABLE")refuse("invalid SSSD administrative status: "+ref.policyName);
        if(member->isEnabled()!=(status=="ENABLE"))refuse("SSSD registry status mismatch");
        if(ref==releasing) {if(status!=expectedStatus)refuse("explicit "+expectedStatus+" required for "+ref.policyName);continue;}
        if(status!="ENABLE")continue;
        const auto value=member->getValue();if(!value)refuse("remaining ENABLE SSSD policy has no valid value: "+ref.policyName);
        SemanticValue semantic;
        if(parameter==SssdManagedParameter::CacheCredentials) {if(*value!="true")refuse("invalid fixed cache value");semantic=true;}
        else {unsigned days=0;const auto parsed=std::from_chars(value->data(),value->data()+value->size(),days);
            if(value->empty()||parsed.ec!=std::errc{}||parsed.ptr!=value->data()+value->size()||days>3650)refuse("invalid remaining SSSD Days");semantic=Days{days};}
        const auto assignments=detail_i4::targetAssignments(domainScope(input),parameter,semantic);
        out.required.insert(out.required.end(),assignments.begin(),assignments.end());
        out.requiredByPolicy.emplace(ref.policyName,assignments);
    }
    std::string error;
    if(!AtomicFileWriter::targetStateMatches(current.path,current.state,&error))refuse("administrative configuration changed during projection: "+error);
    out.generation=current.generation;
    return out;
}
// Administrative ENABLE is OwnWhileEnabled, not foreign compliance. Compare
// per-policy projections; another owner or a matching effective value cannot
// supply this authority. Existing physical/semantic/runtime proofs remain separate.
void requireOwnershipCoverage(const AdministrativeProof& administrative,
                              const std::vector<r::MutationRecord>& records) {
    for(const auto& [name,required]:administrative.requiredByPolicy) {
        const auto reject=[&](const std::string& why) {
            refuse("remaining ENABLE SSSD ownership coverage: "+name+": "+why);
        };
        const r::MutationRecord* selected=nullptr;
        for(const auto& record:records)if(record.isActive()&&record.policy==PolicyRef{"IDENTITY_ACCESS","SSSD",name}) {
            if(selected)reject("duplicate active owner");
            selected=&record;
        }
        if(!selected)reject("active I4 owner missing; foreign compliance is not ownership");
        const auto* owner=std::get_if<r::SssdJournalOwnership>(&selected->undo.payload);
        if(selected->undo.backend!=r::MutationBackend::Sssd||!owner)reject("legacy or unsupported owner");
        std::string error;
        if(!j::validRecord(*selected,error))reject("invalid provenance: "+error);
        if(selected->status!=r::MutationStatus::Applied||
           (owner->transition&&owner->transition->phase!=r::SssdTransitionPhase::Completed))
            reject("owner is unresolved, not completed Applied");
        auto actual=owner->current.assignments,expected=required;
        const auto order=[](const auto& a,const auto& b){return std::tie(a.section,a.key,a.value)<std::tie(b.section,b.key,b.value);};
        std::sort(actual.begin(),actual.end(),order);std::sort(expected.begin(),expected.end(),order);
        if(actual!=expected)reject("owned assignments do not exactly cover canonical section/key/value scope");
    }
}
void mergeRequired(std::vector<SssdSemanticExpectation>& expected,const std::vector<r::SssdAssignment>& required) {
    for(const auto& value:expectations(required)) {
        const auto found=std::find_if(expected.begin(),expected.end(),[&](const auto& v){return v.key.section==value.key.section&&v.key.key==value.key.key;});
        if(found!=expected.end()) {if(!detail_i3::sameValue(found->value,value.value))refuse("administrative ENABLE intent conflicts with surviving ownership");}
        else expected.push_back(value);
    }
}
void graphAfter(const SssdInputReference& before,const SssdInputReference& after,const std::optional<AtomicTargetState>& installed,bool release=false) {
    if(detail_i3::configurationOnly(before.launch.contract)!=detail_i3::configurationOnly(after.launch.contract)||
       before.launch.unitLookupFingerprint!=after.launch.unitLookupFingerprint||before.launch.executables!=after.launch.executables||
       before.consumers!=after.consumers||(!release&&after.applyConflict())||before.laterForeignSnippets!=after.laterForeignSnippets)refuse("launch/consumer/late input changed around publication");
    if(before.sources.size()!=after.sources.size())refuse("source graph changed");
    for(const auto& [path,a]:before.sources) {
        const auto& b=after.sources.at(path);
        if(a.present!=b.present||!d::sameObject(a.identity,b.identity))refuse("source root changed");
        auto af=a.tree.files,bf=b.tree.files;auto aa=a.tree.attributes,ba=b.tree.attributes;
        if(path=="/etc/sssd") {af.erase(relative);bf.erase(relative);aa.erase(relative);ba.erase(relative);}
        if(af!=bf||aa.size()!=ba.size())refuse("foreign source graph changed");
        // Our rename can copy up both directories on OverlayFS. Their
        // timestamps/size/nlink are not stable witnesses of this transition;
        // identities, access metadata and complete child manifests remain so.
        for(const auto& [name,st]:aa) {
            const auto& other=ba.at(name);
            if(st.st_dev!=other.st_dev||st.st_ino!=other.st_ino||st.st_mode!=other.st_mode||st.st_uid!=other.st_uid||st.st_gid!=other.st_gid||(S_ISREG(st.st_mode)&&st.st_nlink!=other.st_nlink)||
               (!(path=="/etc/sssd"&&(name.empty()||name=="conf.d"))&&(st.st_size!=other.st_size||st.st_mtim.tv_sec!=other.st_mtim.tv_sec||st.st_mtim.tv_nsec!=other.st_mtim.tv_nsec||st.st_ctim.tv_sec!=other.st_ctim.tv_sec||st.st_ctim.tv_nsec!=other.st_ctim.tv_nsec)))refuse("foreign metadata/identity changed: "+path+"/"+name+" before="+std::to_string(st.st_dev)+":"+std::to_string(st.st_ino)+":"+std::to_string(st.st_mode)+":"+std::to_string(st.st_size)+":"+std::to_string(st.st_ctim.tv_nsec)+" after="+std::to_string(other.st_dev)+":"+std::to_string(other.st_ino)+":"+std::to_string(other.st_mode)+":"+std::to_string(other.st_size)+":"+std::to_string(other.st_ctim.tv_nsec));
        }
    }
    auto captured=physical();if(!matches(installed?witness(*installed):r::SssdImageWitness{},captured))refuse("installed persistent image replaced");
    const auto& t=after.sources.at("/etc/sssd").tree;
    if(installed) {
        const auto& st=t.attributes.at(relative);
        if(t.files.at(relative)!=installed->content||st.st_ino!=installed->identity.inode||st.st_dev!=installed->identity.device||
           (st.st_mode&07777)!=(installed->mode&07777)||st.st_uid!=installed->owner||st.st_gid!=installed->group)refuse("I1 target not bound to installed object");
    } else if(t.attributes.count(relative)||t.files.count(relative))refuse("released file reappeared in I1 graph");
    stagedArtifacts(t);
}
} // namespace
namespace detail_i4 {
PolicyRef policyIdentity(SssdManagedParameter p) {
    switch(p) {
    case SssdManagedParameter::OfflineCredentialsExpiration:return {"IDENTITY_ACCESS","SSSD","sssd_offline_credentials_expiration"};
    case SssdManagedParameter::CacheCredentials:return {"IDENTITY_ACCESS","SSSD","sssd_cache_credentials"};
    case SssdManagedParameter::AccountCacheExpiration:return {"IDENTITY_ACCESS","SSSD","sssd_account_cache_expiration"};
    }
    refuse("unknown parameter");
}
std::string scopeIdentity(const DomainScopeReference& scope) {
    const auto& s=scope.data();j::J domains=j::J::array();
    for(const auto& [name,v]:s.domains)domains.push_back({name,v.idProvider,v.authProvider,v.selected,v.enabled,v.dynamicPossible,v.trustedPossible,v.authDefault,v.enabledSetting?j::J(*v.enabledSetting):j::J(nullptr),v.requiredConsumers});
    return j::J{{"format",s.formatVersion},{"platform",s.platform},{"configured",s.configured},{"selected",s.selected},{"enabled",s.enabled},{"domains",domains}}.dump();
}
std::vector<r::SssdAssignment> targetAssignments(const DomainScopeReference& scope,SssdManagedParameter p,const SemanticValue& value) {
    if(scope.data().hypothetical||!scope.data().issues.empty()||scope.data().enabled.empty())refuse("unsupported/incomplete canonical scope");
    if(scope.data().selected!=scope.data().enabled)refuse("every explicitly selected root must be enabled; no partial coverage");
    std::string text;
    if(p==SssdManagedParameter::CacheCredentials) {auto v=std::get_if<bool>(&value);if(!v||!*v)refuse("cache requires explicit true");text="true";}
    else {auto v=std::get_if<Days>(&value);if(!v||v->value>3650)refuse("explicit bounded Days required");text=std::to_string(v->value);}
    if(p==SssdManagedParameter::OfflineCredentialsExpiration)return {{"pam","offline_credentials_expiration",text}};
    std::vector<r::SssdAssignment> out;
    for(const auto& name:scope.data().enabled) {
        const auto& v=scope.data().domains.at(name);
        if(v.provider!=ProviderClass::LdapPassword||!v.selected||v.dynamicPossible||v.trustedPossible)refuse("no partial LDAP coverage");
        out.push_back({"domain/"+name,p==SssdManagedParameter::CacheCredentials?"cache_credentials":"account_cache_expiration",text});
    }
    std::sort(out.begin(),out.end(),[](const auto& a,const auto& b){return a.section<b.section;});return out;
}
std::string renderAssignments(const std::vector<r::SssdAssignment>& all) {
    std::map<std::string,std::map<std::string,std::string>> sorted;
    for(const auto& a:all)if(!sorted[a.section].emplace(a.key,a.value).second)refuse("duplicate render target");
    std::string out;for(const auto& [section,keys]:sorted) {
        out+="["+section+"]\n";for(const auto& [key,value]:keys)out+=key+" = "+value+"\n";out+="\n";
    }return out;
}
} // namespace detail_i4
namespace {
SssdTransactionResult perform(r::MutationJournal& journal,const SssdTransactionRequest& request
#ifdef FIC_ACTIVATOR_TESTING
    ,const detail_i4::TransactionTestHooks* tests
#endif
) {
    SssdTransactionResult out;
    std::unique_lock<std::timed_mutex> lock(resourceMutex,std::defer_lock);
    auto checkpoint=[&](const std::string& phase){
#ifdef FIC_ACTIVATOR_TESTING
        if(tests&&tests->checkpoint)tests->checkpoint(phase);
#else
        (void)phase;
#endif
    };
    try {
        remaining(request.deadline);
        if(request.policy!=detail_i4::policyIdentity(request.parameter))refuse("policy/parameter identity mismatch");
        if(request.operation!=SssdTransactionOperation::Apply&&request.operation!=SssdTransactionOperation::Refresh)refuse("unknown operation");
        if(!lock.try_lock_until(request.deadline))refuse("shared resource busy");
        checkpoint("locked");
        if(request.productionIntent)request.productionIntent->verify(request);
        journalProof(journal);
        // Gate precedes service inspection: even an inactive service cannot
        // hide another policy's unresolved intent.
        for(const auto& rec:journal.records())if(rec.isActive()&&rec.undo.backend==r::MutationBackend::Sssd) {
            auto p=std::get_if<r::SssdJournalOwnership>(&rec.undo.payload);
            if(!p||rec.status!=r::MutationStatus::Applied||(p->transition&&p->transition->phase!=r::SssdTransitionPhase::Completed)) {
                out.status=SssdTransactionStatus::Unresolved;out.unresolved=true;refuse("shared resource has legacy/unresolved SSSD ownership");
            }
        }
        const auto input=capture(request.deadline);const auto scope=domainScope(input);
        if(input.applyConflict())refuse("later eligible foreign snippet");
        const auto& tree=input.sources.at("/etc/sssd").tree;
        if(!tree.attributes.count("conf.d"))refuse("existing trusted conf.d required");
        stagedArtifacts(tree);
        const auto before=physical();out.status=SssdTransactionStatus::OwnershipConflict;
        const auto owned=ownership(journal,input,before);
        out.status=SssdTransactionStatus::Refused;
        out.required=detail_i4::targetAssignments(scope,request.parameter,request.value);
        auto existing=owned.policies.find(request.policy.policyName);
        if(request.operation==SssdTransactionOperation::Refresh&&existing==owned.policies.end())refuse("REFRESH requires existing owner");
        r::SssdOwnedState prior;
        if(existing!=owned.policies.end())prior=std::get<r::SssdJournalOwnership>(existing->second.undo.payload).current;
        if(!prior.assignments.empty()) {
            if(prior.assignments.size()!=out.required.size())refuse("historical target set differs");
            for(size_t i=0;i<out.required.size();++i)if(prior.assignments[i].section!=out.required[i].section||prior.assignments[i].key!=out.required[i].key)refuse("historical target set differs");
        }
        TrustedOwnershipContext trusted{inputFingerprint(input),"journal/I4",{}};
        for(const auto& a:owned.all)trusted.ownedValues[{a.section,a.key}]=a.value;
        ProposedChange change{request.operation==SssdTransactionOperation::Refresh?ProposedOperation::Refresh:ProposedOperation::Apply,{}};
        for(const auto& e:expectations(out.required))change.settings.push_back({e.key,e.value});
        auto preview=previewConfiguration(input,scope,change,before?&trusted:nullptr);
        if(!preview.projectionAvailable||!preview.configuration||preview.semanticStatus!=SemanticStatus::Validated)refuse("I2 candidate/relation validation failed");
        auto all=owned.all;
        for(const auto& a:out.required) {
            auto it=std::find_if(all.begin(),all.end(),[&](const auto& b){return a.section==b.section&&a.key==b.key;});
            if(it==all.end())all.push_back(a);else *it=a;
        }
        const auto candidate=detail_i4::renderAssignments(all);
        // A valid active graph has at least one eligible native configuration
        // source, even when main is absent. Plan our OWN canonical metadata,
        // never copy a foreign read-only mode unsupported by this payload.
        if(input.order.empty())refuse("no native metadata template");
        const auto& metadata=tree.attributes.at(input.order.front().substr(10));
        const mode_t freshMode=(metadata.st_mode&0040)?0640:0600;
        const gid_t freshGroup=metadata.st_gid;
        const auto expected=expectations(all);
        // Reuse existing I3 native and publication prerequisite checks. These
        // are preflight observations, never A/B/C/P or a second engine.
        SssdVerifiedActivationRequest preflight{input,scope,expected,remaining(request.deadline)};
        const auto native=detail_i3::nativePreflight(preflight,*preview.configuration,request.deadline);
        auto paths=detail_i3::protectedRequest(input,remaining(request.deadline));
        d::validatePublicationEnvironment(paths);
        revalidate(input,request.deadline);
        if(before&&!AtomicFileWriter::targetStateMatches(file,*before,&out.diagnostic))refuse("pre-Prepared image changed");
        out.sameValue=before&&before->content==candidate;
        r::SssdOwnershipTransition t;
        t.sequence=owned.sequence+1;t.previous=prior;t.target=out.required;t.targetScope=detail_i4::scopeIdentity(scope);
        t.inputFingerprint=inputFingerprint(input);t.before=before?witness(*before):r::SssdImageWitness{};t.targetSha256=sha(candidate);
        if(request.productionIntent)request.productionIntent->verify(request);
        checkpoint("before-prepared");out.status=SssdTransactionStatus::JournalFailed;
        if(!journal.beginSssdTransaction(request.policy,t,out.mutation,out.diagnostic)) {
            out.unresolved=!journal.usable();return out;
        }
        out.prepared=true;out.ownershipRetained=true;out.unresolved=true;out.status=SssdTransactionStatus::Unresolved;
        auto advance=[&](){if(journal.advanceSssdTransaction(out.mutation,t,out.diagnostic))return true;out.status=SssdTransactionStatus::JournalFailed;return false;};
        checkpoint("prepared");
        revalidate(input,request.deadline);
        t.phase=r::SssdTransitionPhase::MutationArmed;
        if(!advance())return out;
        checkpoint("mutation-armed");remaining(request.deadline);
        AtomicTargetState installed;
        if(out.sameValue) {
            installed=*before;
            if(!AtomicFileWriter::ensureTargetDurableIfCurrentState(file,installed,&out.diagnostic)) {out.status=SssdTransactionStatus::PersistentFailed;return out;}
            out.durable=true;
        } else {
            AtomicWriteOptions options;options.rejectSymlink=true;options.createIfMissing=!before;options.exclusiveCreate=!before;
            if(before)options.expectedTargetState=*before;
            else {
                // Match already-provisioned native readability; never repair
                // foreign ownership or create conf.d on the caller's behalf.
                options.fileOwner=0;options.fileGroup=freshGroup;options.fileMode=freshMode;
            }
            AtomicWriteResult written;
            const bool ok=AtomicFileWriter::writeWithResult(file,candidate,options,&out.diagnostic,&written);
            out.installed=written.installed;out.durable=written.durabilityConfirmed;out.casRefused=written.preconditionFailed;
            if(!written.installed) {out.status=written.preconditionFailed?SssdTransactionStatus::CasRefused:SssdTransactionStatus::PersistentFailed;return out;}
            if(!written.installedTargetState)refuse("publication has no descriptor witness");
            installed=*written.installedTargetState;
            t.publication=witness(installed);t.phase=r::SssdTransitionPhase::Published;
            if(!advance()) {out.status=SssdTransactionStatus::JournalFailed;return out;}
            checkpoint("published");
            if(!ok||!written.durabilityConfirmed) {out.status=SssdTransactionStatus::PersistentFailed;return out;}
        }
        if(out.sameValue) {
            t.publication=witness(installed);t.phase=r::SssdTransitionPhase::Published;
            if(!advance())return out;
        }
        t.phase=r::SssdTransitionPhase::DurablePublished;t.publicationDurable=true;
        if(!advance())return out;
        checkpoint("durable-published");
        const auto target=capture(request.deadline);graphAfter(input,target,installed);
        auto cfg=effectiveConfiguration(target);detail_i3::validateExpectations(cfg,expected);
        if(detail_i4::scopeIdentity(domainScope(target))!=t.targetScope)refuse("post-publication domain scope changed");
        t.phase=r::SssdTransitionPhase::ActivationArmed;t.activationPossible=true;
        if(!advance())return out;
        checkpoint("before-activation");
        SssdVerifiedActivationRequest activation{target,domainScope(target),expected,remaining(request.deadline)};
#ifdef FIC_ACTIVATOR_TESTING
        if(tests&&tests->adapter)out.activation=detail_i3::activateForTests(activation,*tests->adapter);
        else
#endif
        out.activation=activate(activation);
        checkpoint("after-activation");
        t.a=out.activation.inputs==SssdProofState::Proven;t.b=out.activation.activation==SssdProofState::Proven;
        t.c=out.activation.semantics==SssdProofState::Proven;t.p=out.activation.persistent==SssdProofState::Proven;
        t.clean=out.activation.engine.cleanupErrors.empty()&&out.activation.engine.residualPaths.empty();
        t.residuals=out.activation.engine.residualPaths;t.cleanupErrors=out.activation.engine.cleanupErrors;
        t.runtimeFacts={{"diagnostic",out.activation.diagnostic},{"attempted",out.activation.engine.activationAttempted?"true":"false"},
            {"old_invocation",out.activation.oldInvocation},{"new_invocation",out.activation.newInvocation},{"configdb",out.activation.configDbGeneration},
            {"adapter_status",std::to_string(static_cast<unsigned>(out.activation.status))},
            {"engine_status",activationStatusName(out.activation.engine.status)},
            {"primary_status",activationStatusName(out.activation.engine.primaryStatus)},
            {"readiness",out.activation.engine.readinessConfirmed?"true":"false"},
            {"runtime_effect_possible",out.activation.runtimeEffectPossible?"true":"false"}};
        j::J consumers=j::J::array();
        for(const auto& e:out.activation.parameters)consumers.push_back({
            {"section",e.key.section},{"key",e.key.key},{"consumer",e.consumer},{"process",e.processToken},
            {"generation",e.configDbGeneration},{"source_contract",e.sourceContract},{"read_moment",e.readMoment},{"scope",e.scope}});
        t.runtimeFacts["consumer_evidence"]=consumers.dump();
        if(out.activation.success())t.phase=r::SssdTransitionPhase::RuntimeVerified;
        out.status=SssdTransactionStatus::JournalFailed;
        if(!advance())return out;
        if(!out.activation.success()){out.status=SssdTransactionStatus::ActivationFailed;out.diagnostic=out.activation.diagnostic;return out;}
        out.status=SssdTransactionStatus::Unresolved;
        checkpoint("runtime-verified");
        const auto final=capture(request.deadline);graphAfter(target,final,installed);
        detail_i3::validateExpectations(effectiveConfiguration(final),expected);
        detail_i1::verifyPersistentSources(target,request.deadline);
        detail_i3::confirmRuntime(native,out.activation,request.deadline);
        if(!AtomicFileWriter::ensureTargetDurableIfCurrentState(file,installed,&out.diagnostic))refuse("final persistent durability failed");
        out.confirmed=out.required;
        if(request.productionIntent)request.productionIntent->verify(request);
        checkpoint("before-finalization");out.status=SssdTransactionStatus::FinalizationFailed;
        if(!journal.commitSssdTransaction(out.mutation,out.diagnostic))return out;
        out.finalized=true;out.unresolved=false;out.status=SssdTransactionStatus::Success;out.diagnostic.clear();
        checkpoint("completed");return out;
    } catch(const std::exception& e) {
        out.diagnostic=e.what();
        if(out.prepared&&out.status!=SssdTransactionStatus::JournalFailed&&out.status!=SssdTransactionStatus::FinalizationFailed)
            out.status=SssdTransactionStatus::Unresolved;
        return out;
    }
}
SssdReleaseResult performRelease(r::MutationJournal& journal,const SssdReleaseRequest& request
#ifdef FIC_ACTIVATOR_TESTING
    ,const detail_i4::TransactionTestHooks* tests
#endif
) {
    SssdReleaseResult out;
    std::unique_lock<std::timed_mutex> lock(resourceMutex,std::defer_lock);
    auto checkpoint=[&](const std::string& phase) {
#ifdef FIC_ACTIVATOR_TESTING
        if(tests&&tests->checkpoint)tests->checkpoint(phase);
#else
        (void)phase;
#endif
    };
    try {
        remaining(request.deadline);
        if(request.policy!=detail_i4::policyIdentity(request.parameter)||
           (request.intent!=r::SssdReleaseIntent::ReleaseOnly&&request.intent!=r::SssdReleaseIntent::DisableRelease))refuse("invalid closed release identity/intent");
        if(!lock.try_lock_until(request.deadline))refuse("shared resource busy");
        checkpoint("locked");journalProof(journal);
        for(const auto& rec:journal.records())if(rec.isActive()&&rec.undo.backend==r::MutationBackend::Sssd) {
            auto* p=std::get_if<r::SssdJournalOwnership>(&rec.undo.payload);
            if(!p||rec.status!=r::MutationStatus::Applied||(p->transition&&p->transition->phase!=r::SssdTransitionPhase::Completed)) {
                out.status=SssdReleaseStatus::Unresolved;out.unresolved=true;
                refuse("legacy/unresolved SSSD ownership; no new mutation authorized");
            }
        }
        // RefUnit loads/pins a stopped unit without starting it. Actual service
        // observations still use the existing verified private root-PID1 bus.
        const auto lease=d::retainSshUnitsForValidation(d::ActivationProfile::SssdNotify,request.deadline);
        const auto launch=detail_i5::admitForRelease(request.deadline);
        out.offline=classifyService(launch.contract)==AdmissionState::Stopped;
        const auto offlineEpoch=out.offline?d::readSssdReleaseEpoch(request.deadline):d::LaunchContract{};
        if(out.offline) {
            if(j::J::parse(offlineEpoch.at("launch.ControlGroup"))!=j::J{{"signature","s"},{"value",""}})
                refuse("inactive service still has an unproven cgroup");
            for(const auto* key:{"launch.ExecMainStartTimestampMonotonic","launch.ExecMainExitTimestampMonotonic"}) {
                const auto value=j::J::parse(offlineEpoch.at(key));
                if(value.at("signature")!="t"||!value.at("value").is_number_unsigned())refuse("offline epoch type unproven");
            }
        }
        const auto serviceProof=[&]() {
            d::verifySshUnitReferences(*lease,request.deadline);
            detail_i5::revalidateRelease(launch,request.deadline);
            if(out.offline&&d::readSssdReleaseEpoch(request.deadline)!=offlineEpoch)refuse("SSSD started/stopped during offline release");
            const auto proof=out.offline?detail_i3::proveStoppedConsumers(launch,request.deadline):sha(j::J(launch.contract).dump());
            return sha(j::J{{"service",proof},{"epoch",offlineEpoch}}.dump());
        };
        const auto serviceBefore=serviceProof();
        const auto input=detail_i1::snapshotGraph(launch,request.deadline);
        const auto administrative=request.registry&&request.intent==r::SssdReleaseIntent::DisableRelease?
            std::optional<AdministrativeProof>(administrativeProof(*request.registry,request.policy,"ENABLE",input)):std::nullopt;
        stagedArtifacts(input.sources.at("/etc/sssd").tree);
        if(!residualMounts().empty())refuse("residual SSSD publication mounts");
        const auto before=physical();out.status=SssdReleaseStatus::OwnershipConflict;
        if(administrative)requireOwnershipCoverage(*administrative,journal.records());
        const auto owned=ownership(journal,input,before,true);
        const auto found=owned.policies.find(request.policy.policyName);
        if(found==owned.policies.end())refuse("no active I4 owner; absence/name/value is not release authority");
        out.status=SssdReleaseStatus::Refused;
        out.mutation=found->second.id;
        const auto& own=std::get<r::SssdJournalOwnership>(found->second.undo.payload);
        out.released=own.current.assignments;
        r::SssdOwnershipTransition t;t.version=request.registry?3:2;t.sequence=owned.sequence+1;t.previous=own.current;
        t.before=witness(*before);t.inputFingerprint=inputFingerprint(input);t.release.emplace();auto& release=*t.release;
        release.intent=request.intent;release.offline=out.offline;release.serviceBefore=serviceBefore;
        j::J generation=j::J::array();
        for(const auto& [name,rec]:owned.policies) {
            const auto& sibling=std::get<r::SssdJournalOwnership>(rec.undo.payload);
            generation.push_back({rec.id,name,j::state(sibling.current),j::container(sibling.container)});
            if(rec.id==out.mutation)continue;
            release.survivors.push_back({rec.id,name,sibling.current,sibling.container});
            release.remaining.insert(release.remaining.end(),sibling.current.assignments.begin(),sibling.current.assignments.end());
        }
        std::sort(release.remaining.begin(),release.remaining.end(),[](const auto& a,const auto& b){return std::tie(a.section,a.key)<std::tie(b.section,b.key);});
        out.surviving=release.remaining;release.ownershipGeneration=sha(generation.dump());
        const auto candidate=detail_i4::renderAssignments(release.remaining);t.targetSha256=sha(candidate);
        release.targetAbsent=release.remaining.empty();
        if(release.targetAbsent)out.stagedPath=release.stagedPath=std::string(file)+".fic-removing-i5-"+std::to_string(out.mutation)+"-"+std::to_string(t.sequence);
        // I2 preview is diagnostic, never permission to retain an owned key.
        // Foreign relations/scope can prevent activation AFTER physical release.
        TrustedOwnershipContext trusted{inputFingerprint(input),"journal/I5",{}};
        for(const auto& a:owned.all)trusted.ownedValues[{a.section,a.key}]=a.value;
        ProposedChange change{ProposedOperation::ReleasePreview,{}};
        for(const auto& a:out.released)change.settings.push_back({{a.section,a.key},SemanticValue{}});
        const auto preview=previewConfiguration(input,domainScope(input),change,&trusted);
        if(!preview.projectionAvailable)refuse("I2 release projection not proven");
        detail_i1::verifyPersistentSources(input,request.deadline);serviceProof();
        if(administrative&&administrativeProof(*request.registry,request.policy,"ENABLE",input).generation!=administrative->generation)
            refuse("SSSD administrative generation changed before release");
        out.status=SssdReleaseStatus::JournalFailed;
        checkpoint("before-prepared");
        if(!journal.beginSssdRelease(out.mutation,t,out.diagnostic))return out;
        out.prepared=true;out.unresolved=true;out.status=SssdReleaseStatus::Unresolved;
        const auto advance=[&]() {
            if(journal.advanceSssdRelease(out.mutation,t,out.diagnostic))return true;
            out.status=SssdReleaseStatus::JournalFailed;return false;
        };
        checkpoint("prepared");detail_i1::verifyPersistentSources(input,request.deadline);serviceProof();
        t.phase=r::SssdTransitionPhase::MutationArmed;if(!advance())return out;
        checkpoint("mutation-armed");remaining(request.deadline);
        std::optional<AtomicTargetState> installed;
        if(release.targetAbsent) {
            fic::identity::SecureConfigurationFileOptions options;options.path=file;
            options.expectedOwner=before->owner;options.expectedGroup=before->group;options.exactMode=before->mode;
            fic::identity::SecureConfigurationDirectoryOptions directory;
            const auto removed=fic::identity::sssd::removeProvenManagedSnippet(options,directory,*before,release.stagedPath);
            out.physicalReleased=removed.removed;out.durable=removed.durable;out.casRefused=removed.conflict;
            out.diagnostic=removed.diagnostic;
            if(!removed.removed)return out;
        } else {
            AtomicWriteOptions options;options.rejectSymlink=true;options.expectedTargetState=*before;
            AtomicWriteResult written;
            const bool ok=AtomicFileWriter::writeWithResult(file,candidate,options,&out.diagnostic,&written);
            out.physicalReleased=written.installed;out.durable=written.durabilityConfirmed;out.casRefused=written.preconditionFailed;
            if(!written.installed)return out;
            if(!written.installedTargetState)refuse("release publication missing descriptor witness");
            installed=*written.installedTargetState;
            if(!ok&&!out.durable)out.diagnostic="release installed but durability unproven: "+out.diagnostic;
        }
        t.publication=installed?witness(*installed):r::SssdImageWitness{};
        t.phase=r::SssdTransitionPhase::Published;if(!advance())return out;checkpoint("published");
        if(!out.durable)return out;
        t.phase=r::SssdTransitionPhase::DurablePublished;t.publicationDurable=true;
        if(!advance())return out;checkpoint("durable-published");
        serviceProof();
        const auto target=detail_i1::snapshotGraph(launch,request.deadline);graphAfter(input,target,installed,true);
        auto expected=expectations(out.surviving);const auto cfg=effectiveConfiguration(target);
        if(administrative)mergeRequired(expected,administrative->required);
        // Even with no remaining owner C has a non-vacuous native consumer
        // proof, observing the resulting backend option, not the removed value.
        if(expected.empty())for(const auto& name:cfg.scope.data().enabled)
            expected.push_back({{"domain/"+name,"account_cache_expiration"},cfg.domains.at(name).accountDays.value});
        detail_i3::validateExpectations(cfg,expected);
        // Surviving assignments must still cover the canonical complete scope.
        for(const auto& survivor:release.survivors) {
            const auto kind=survivor.policy=="sssd_cache_credentials"?SssdManagedParameter::CacheCredentials:
                survivor.policy=="sssd_account_cache_expiration"?SssdManagedParameter::AccountCacheExpiration:SssdManagedParameter::OfflineCredentialsExpiration;
            const auto value=kind==SssdManagedParameter::CacheCredentials?SemanticValue(true):SemanticValue(Days{static_cast<std::uint32_t>(std::stoul(survivor.state.assignments.front().value))});
            if(detail_i4::targetAssignments(domainScope(target),kind,value)!=survivor.state.assignments||
               survivor.state.scope!=detail_i4::scopeIdentity(domainScope(target)))refuse("surviving ownership no longer matches full canonical scope");
        }
        std::optional<detail_i3::NativeRuntimeContract> nativeProof;
        if(out.offline) {
            release.serviceAfter=serviceProof();release.offlineVerified=true;out.offlineVerified=true;
            t.p=true;t.clean=residualMounts().empty();t.phase=r::SssdTransitionPhase::OfflineVerified;
            release.releasedGraphFingerprint=inputFingerprint(target);
            if(!advance())return out;checkpoint("released-offline");
        } else {
            SssdVerifiedActivationRequest activation{target,domainScope(target),expected,remaining(request.deadline),SssdActivationIntent::ConfigurationRelease};
            nativeProof=detail_i3::nativePreflight(activation,cfg,request.deadline);
            const auto& native=*nativeProof;
            t.phase=r::SssdTransitionPhase::ActivationArmed;t.activationPossible=true;
            if(!advance())return out;checkpoint("before-activation");
#ifdef FIC_ACTIVATOR_TESTING
            if(tests&&tests->adapter)out.activation=detail_i3::activateForTests(activation,*tests->adapter);
            else
#endif
            out.activation=activate(activation);
            checkpoint("after-activation");
            t.a=out.activation.inputs==SssdProofState::Proven;t.b=out.activation.activation==SssdProofState::Proven;
            t.c=out.activation.semantics==SssdProofState::Proven;t.p=out.activation.persistent==SssdProofState::Proven;
            t.clean=out.activation.engine.cleanupErrors.empty()&&out.activation.engine.residualPaths.empty();
            t.residuals=out.activation.engine.residualPaths;t.cleanupErrors=out.activation.engine.cleanupErrors;
            t.runtimeFacts={{"diagnostic",out.activation.diagnostic},{"old_invocation",out.activation.oldInvocation},
                {"new_invocation",out.activation.newInvocation},{"configdb",out.activation.configDbGeneration},
                {"attempted",out.activation.engine.activationAttempted?"true":"false"},
                {"runtime_effect_possible",out.activation.runtimeEffectPossible?"true":"false"}};
            j::J consumers=j::J::array();
            for(const auto& e:out.activation.parameters)consumers.push_back({
                {"section",e.key.section},{"key",e.key.key},{"consumer",e.consumer},{"process",e.processToken},
                {"generation",e.configDbGeneration},{"source_contract",e.sourceContract},{"read_moment",e.readMoment},{"scope",e.scope}});
            t.runtimeFacts["consumer_evidence"]=consumers.dump();
            if(!out.activation.success()) {
                advance();out.status=t.clean?SssdReleaseStatus::Unresolved:SssdReleaseStatus::CleanupFailed;
                out.diagnostic=out.activation.diagnostic;return out;
            }
            detail_i3::confirmRuntime(native,out.activation,request.deadline);
            if(t.version==3)release.runtimeReceipt=detail_i6::captureReceipt(out.activation);
            const auto final=capture(request.deadline);graphAfter(target,final,installed,true);
            detail_i1::verifyPersistentSources(target,request.deadline);
            detail_i3::validateExpectations(effectiveConfiguration(final),expected);
            release.serviceAfter=sha(j::J(final.launch.contract).dump());release.releasedGraphFingerprint=inputFingerprint(final);
            t.phase=r::SssdTransitionPhase::RuntimeVerified;
            if(!advance())return out;checkpoint("runtime-verified");
        }
        // Final P is separately bound to the exact persistent publication.
        std::string error;
        if(!(installed?AtomicFileWriter::ensureTargetDurableIfCurrentState(file,*installed,&error):
                      AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(file,&error)))refuse("final release P failed: "+error);
        detail_i1::verifyPersistentSources(target,request.deadline);
        if(!residualMounts().empty())refuse("residual mounts before release finalization");
        if(out.offline)serviceProof();else {
            d::verifySshUnitReferences(*lease,request.deadline);
            detail_i3::confirmRuntime(*nativeProof,out.activation,request.deadline);
        }
        if(request.intent==r::SssdReleaseIntent::DisableRelease) {
            if(administrative&&administrativeProof(*request.registry,request.policy,"ENABLE",target).generation!=administrative->generation)
                refuse("SSSD administrative generation changed during release");
            t.phase=r::SssdTransitionPhase::ReleasedAwaitingDisable;
            if(!advance())return out;
            out.status=SssdReleaseStatus::ReleasedAwaitingDisable;
            out.diagnostic="physical/runtime release proven; explicit durable DISABLE and trusted acknowledgement pending";
            checkpoint("released-awaiting-disable");return out;
        }
        checkpoint("before-finalization");out.status=SssdReleaseStatus::JournalFailed;
        if(!journal.completeSssdRelease(out.mutation,out.diagnostic))return out;
        out.finalized=true;out.unresolved=false;out.status=out.offline?SssdReleaseStatus::ReleasedOffline:SssdReleaseStatus::Completed;
        out.diagnostic.clear();checkpoint("completed");return out;
    } catch(const std::exception& error) {
        out.diagnostic=error.what();
        if(out.prepared&&out.status!=SssdReleaseStatus::JournalFailed)out.status=SssdReleaseStatus::Unresolved;
        return out;
    }
}
SssdRecoveryInspection inspectLocked(r::MutationJournal& journal,Deadline deadline,bool resolve) {
    SssdRecoveryInspection out;
    try {
        remaining(deadline);journalProof(journal);out.classification=SssdRecoveryClassification::NoTransition;
        const r::SssdJournalOwnership* owner=nullptr;
        for(const auto& rec:journal.records())if(rec.isActive()&&rec.undo.backend==r::MutationBackend::Sssd) {
            auto p=std::get_if<r::SssdJournalOwnership>(&rec.undo.payload);
            if(!p){out.classification=SssdRecoveryClassification::UnsupportedSchema;out.diagnostic="legacy scalar ownership is not an I4 transition";return out;}
            if(rec.status!=r::MutationStatus::Applied||(p->transition&&p->transition->phase!=r::SssdTransitionPhase::Completed)) {
                if(owner){out.classification=SssdRecoveryClassification::UnsupportedSchema;out.diagnostic="multiple unresolved SSSD transitions";return out;}
                owner=p;out.mutation=rec.id;
            }
        }
        if(!owner)return out;
        if(!owner->transition){out.classification=SssdRecoveryClassification::UnsupportedSchema;return out;}
        const auto& t=*owner->transition;out.phase=t.phase;out.publicationDurable=t.publicationDurable;out.activationPossible=t.activationPossible;
        out.residuals=residualMounts();
        if(!out.residuals.empty()||!t.residuals.empty()||!t.cleanupErrors.empty()){out.classification=SssdRecoveryClassification::ResidualMounts;return out;}
        auto root=d::openAbsolute("/etc/sssd",O_RDONLY|O_DIRECTORY);std::uint64_t budget=8*1024*1024;
        const auto tree=d::readTree(root.get(),ControlledPathKind::Directory,budget);stagedArtifacts(tree);
        const auto state=physical();out.previousMatches=matches(t.before,state);
        out.targetMatches=(t.publication.present||(t.release&&t.release->targetAbsent&&t.phase!=r::SssdTransitionPhase::Prepared&&t.phase!=r::SssdTransitionPhase::MutationArmed))&&matches(t.publication,state);
        out.targetBytesMatch=state?sha(state->content)==t.targetSha256:bool(t.release&&t.release->targetAbsent);
        if(t.activationPossible)out.classification=SssdRecoveryClassification::RuntimeUnknown;
        else if(out.targetMatches)out.classification=t.publicationDurable?SssdRecoveryClassification::DurableTarget:SssdRecoveryClassification::TargetImage;
        else if(out.previousMatches)out.classification=SssdRecoveryClassification::PreviousImage;
        else if(out.targetBytesMatch)out.classification=SssdRecoveryClassification::TargetBytesUnattributed;
        else {out.classification=SssdRecoveryClassification::ForeignDrift;return out;}
        if(t.phase==r::SssdTransitionPhase::Prepared&&out.previousMatches&&!t.publication.present&&!t.publicationDurable&&!t.activationPossible) {
            // The durable phase proves no writer/engine was authorized. Exact
            // identity plus staging/mount absence excludes ambiguous leftovers.
            std::string error;
            const bool durable=state?AtomicFileWriter::ensureTargetDurableIfCurrentState(file,*state,&error):AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(file,&error);
            if(!durable)refuse("previous state durability unproven: "+error);
            out.classification=SssdRecoveryClassification::NoEffectPrepared;out.noEffectResolvable=true;
            if(resolve&&!journal.abortSssdNoEffect(out.mutation,error))refuse("no-effect journal finalization failed: "+error);
        }
        return out;
    }catch(const std::exception& e){out.diagnostic=e.what();out.noEffectResolvable=false;
        out.classification=journal.usable()?SssdRecoveryClassification::ForeignDrift:SssdRecoveryClassification::JournalIndeterminate;return out;}
}
} // namespace
SssdTransactionResult SssdTransactionCoordinator::execute(const SssdTransactionRequest& request) {
    return perform(journal_,request
#ifdef FIC_ACTIVATOR_TESTING
        ,nullptr
#endif
    );
}
SssdReleaseResult SssdTransactionCoordinator::release(const SssdReleaseRequest& request) {
    return performRelease(journal_,request
#ifdef FIC_ACTIVATOR_TESTING
        ,nullptr
#endif
    );
}
bool SssdTransactionCoordinator::provePolicyUnowned(const PolicyRef& policy,Deadline deadline,std::string& error,PolicyRegistry* disabledRegistry) {
    try {
        remaining(deadline);std::unique_lock<std::timed_mutex> lock(resourceMutex,std::defer_lock);
        if(!lock.try_lock_until(deadline))refuse("shared resource busy");journalProof(journal_);
        bool known=false;
        for(const auto parameter:{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration})
            known|=policy==detail_i4::policyIdentity(parameter);
        if(!known)refuse("unknown SSSD policy cannot prove no ownership");
        bool surviving=false;
        for(const auto& record:journal_.records())if(record.isActive()&&record.undo.backend==r::MutationBackend::Sssd) {
            const auto* owner=std::get_if<r::SssdJournalOwnership>(&record.undo.payload);
            if(record.policy==policy||!owner||record.status!=r::MutationStatus::Applied||
               (owner->transition&&owner->transition->phase!=r::SssdTransitionPhase::Completed))
                refuse("active/legacy/unresolved SSSD ownership prevents no-owner proof");
            surviving=true;
        }
        bool absent=false;
        const auto options=fic::identity::sssd::SssdConfigurationOptions::production();
        // The legacy absence helper deliberately requires mode 0600 for a
        // present legacy file. An I4-owned sibling may legitimately be 0640
        // on native precommand platforms: validate its exact I4 witness and
        // complete union below, without weakening the legacy helper.
        if(!surviving&&!fic::identity::sssd::proveManagedSnippetAbsent(options,absent,error))refuse(error);
        if(absent) {
            for(const auto& record:journal_.records())if(record.isActive()&&record.undo.backend==r::MutationBackend::Sssd)
                refuse("surviving SSSD owner missing its physical artifact");
        } else {
            bool staged=false;
            if(!fic::identity::sssd::hasManagedSnippetStagingArtifacts(options,staged,error)||staged)refuse("unproven SSSD staged artifacts: "+error);
            ownership(journal_,SssdInputReference{},physical(),true);
        }
        if(!residualMounts().empty())refuse("residual SSSD publication mounts");
        if(disabledRegistry) {
            const auto current=administrativeConfiguration(*disabledRegistry);
            const auto status=current.entries.find(policy.policyName+".status");
            if(status==current.entries.end()||status->second!="DISABLE")refuse("explicit durable DISABLE required even without ownership");
        }
        error.clear();return true;
    }catch(const std::exception& e){error=e.what();return false;}
}
bool SssdTransactionCoordinator::acknowledgeDisable(const PolicyRef& policy,PolicyRegistry& registry,Deadline deadline,std::string& error) {
    try {
        remaining(deadline);std::unique_lock<std::timed_mutex> lock(resourceMutex,std::defer_lock);
        if(!lock.try_lock_until(deadline))refuse("shared resource busy");journalProof(journal_);
        std::optional<r::MutationRecord> releasing;
        for(const auto& record:journal_.records())if(record.isActive()&&record.undo.backend==r::MutationBackend::Sssd) {
            const auto* owned=std::get_if<r::SssdJournalOwnership>(&record.undo.payload);
            if(!owned)refuse("legacy SSSD owner cannot acknowledge production DISABLE: "+record.policy.policyName);
            if(record.policy==policy) {
                if(releasing||record.status!=r::MutationStatus::Prepared||!owned->transition||!owned->transition->release||
                   owned->transition->phase!=r::SssdTransitionPhase::ReleasedAwaitingDisable||
                   owned->transition->release->intent!=r::SssdReleaseIntent::DisableRelease)
                    refuse("exact own ReleasedAwaitingDisable required");
                releasing=record;
            } else if(record.status!=r::MutationStatus::Applied||(owned->transition&&owned->transition->phase!=r::SssdTransitionPhase::Completed))
                refuse("unresolved SSSD sibling prevents acknowledgement: "+record.policy.policyName);
        }
        if(!releasing)refuse("no awaiting SSSD disable to acknowledge");
        const auto& transition=*std::get<r::SssdJournalOwnership>(releasing->undo.payload).transition;
        const auto& release=*transition.release;
        if(transition.version!=3)refuse("legacy v2 awaiting lacks the production v3 proof contract; provenance retained");
        const auto lease=d::retainSshUnitsForValidation(d::ActivationProfile::SssdNotify,deadline);
        const auto launch=detail_i5::admitForRelease(deadline);
        if((classifyService(launch.contract)==AdmissionState::Stopped)!=release.offline)refuse("SSSD active/offline state changed since release");
        const auto input=detail_i1::snapshotGraph(launch,deadline);
        if(inputFingerprint(input)!=release.releasedGraphFingerprint)refuse("released protected configuration graph changed");
        const auto administrative=administrativeProof(registry,policy,"DISABLE",input);
        stagedArtifacts(input.sources.at("/etc/sssd").tree);
        if(!residualMounts().empty())refuse("residual SSSD publication mounts");
        const auto current=physical();if(!matches(transition.publication,current))refuse("released physical witness drift");
        if(current&&current->content!=detail_i4::renderAssignments(release.remaining))refuse("released keys/surviving projection drift");
        std::size_t survivors=0;
        for(const auto& record:journal_.records())if(record.isActive()&&record.undo.backend==r::MutationBackend::Sssd&&record.id!=releasing->id) {
            ++survivors;const auto& owned=std::get<r::SssdJournalOwnership>(record.undo.payload);
            const auto found=std::find_if(release.survivors.begin(),release.survivors.end(),[&](const auto& s){return s.id==record.id;});
            if(found==release.survivors.end()||found->policy!=record.policy.policyName||j::state(found->state)!=j::state(owned.current)||
               j::container(found->container)!=j::container(owned.container))refuse("surviving SSSD ownership changed");
        }
        if(survivors!=release.survivors.size())refuse("missing surviving SSSD journal owner");
        requireOwnershipCoverage(administrative,journal_.records());
        auto expected=expectations(release.remaining);mergeRequired(expected,administrative.required);
        const auto cfg=effectiveConfiguration(input);
        if(expected.empty())for(const auto& name:cfg.scope.data().enabled)
            expected.push_back({{"domain/"+name,"account_cache_expiration"},cfg.domains.at(name).accountDays.value});
        detail_i3::validateExpectations(cfg,expected);
        const auto verifyService=[&]() {
            d::verifySshUnitReferences(*lease,deadline);detail_i5::revalidateRelease(launch,deadline);
            if(release.offline) {
                const auto epoch=d::readSssdReleaseEpoch(deadline);
                const auto stopped=detail_i3::proveStoppedConsumers(launch,deadline);
                if(sha(j::J{{"service",stopped},{"epoch",epoch}}.dump())!=release.serviceAfter)
                    refuse("offline epoch/consumer absence changed since release");
            } else {
                if(!release.runtimeReceipt||sha(j::J(launch.contract).dump())!=release.serviceAfter||
                   detail_i3::invocationIdentity(launch.contract)!=release.runtimeReceipt->invocation)
                    refuse("SSSD release runtime generation/receipt unproven");
                SssdVerifiedActivationRequest request{input,domainScope(input),expected,remaining(deadline),SssdActivationIntent::ConfigurationRelease};
                const auto native=detail_i3::nativePreflight(request,cfg,deadline);
                detail_i6::confirmReceipt(*release.runtimeReceipt,native,cfg,deadline);
            }
        };
        verifyService();detail_i1::verifyPersistentSources(input,deadline);
        std::string detail;
        if(!(current?AtomicFileWriter::ensureTargetDurableIfCurrentState(file,*current,&detail):
                     AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(file,&detail)))refuse("release durability unproven: "+detail);
        if(administrativeProof(registry,policy,"DISABLE",input).generation!=administrative.generation)refuse("DISABLE generation changed before acknowledgement");
        verifyService();journalProof(journal_);
        // validatePersistentStateReadOnly reloads the journal's vector. Keep
        // a value snapshot throughout proof collection and rebind by identity
        // afterwards; never retain a pointer/reference into a reloadable tree.
        const auto found=std::find_if(journal_.records().begin(),journal_.records().end(),[&](const auto& record){return record.id==releasing->id;});
        if(found==journal_.records().end()||found->policy!=policy||found->status!=r::MutationStatus::Prepared||
           !std::holds_alternative<r::SssdJournalOwnership>(found->undo.payload)||
           j::encode(std::get<r::SssdJournalOwnership>(found->undo.payload))!=j::encode(std::get<r::SssdJournalOwnership>(releasing->undo.payload)))
            refuse("awaiting SSSD transaction changed during final journal reproof");
        requireOwnershipCoverage(administrative,journal_.records());
        const r::SssdDisableProof proof(releasing->id,transition.sequence,administrative.generation);
        return journal_.acknowledgeSssdDisable(proof,error);
    }catch(const std::exception& e){error=e.what();return false;}
}
SssdRecoveryInspection SssdTransactionCoordinator::inspect(Deadline deadline) {
    std::unique_lock<std::timed_mutex> lock(resourceMutex,std::defer_lock);
    if(!lock.try_lock_until(deadline))return {SssdRecoveryClassification::JournalIndeterminate,0,r::SssdTransitionPhase::Prepared,false,false,false,false,false,false,{},"resource busy"};
    return inspectLocked(journal_,deadline,false);
}
SssdRecoveryInspection SssdTransactionCoordinator::resolveNoEffect(Deadline deadline) {
    std::unique_lock<std::timed_mutex> lock(resourceMutex,std::defer_lock);
    if(!lock.try_lock_until(deadline))return {SssdRecoveryClassification::JournalIndeterminate,0,r::SssdTransitionPhase::Prepared,false,false,false,false,false,false,{},"resource busy"};
    return inspectLocked(journal_,deadline,true);
}
#ifdef FIC_ACTIVATOR_TESTING
void detail_i4::requireOwnershipCoverageForTests(const std::map<std::string,std::vector<r::SssdAssignment>>& required,const std::vector<r::MutationRecord>& records) {
    AdministrativeProof proof;proof.requiredByPolicy=required;requireOwnershipCoverage(proof,records);
}
SssdReleaseResult detail_i4::releaseForTests(r::MutationJournal& journal,const SssdReleaseRequest& request,const TransactionTestHooks& tests) {
    return performRelease(journal,request,&tests);
}
SssdTransactionResult detail_i4::executeForTests(r::MutationJournal& journal,const SssdTransactionRequest& request,const TransactionTestHooks& tests) {
    return perform(journal,request,&tests);
}
#endif
} // namespace fic::service::sssd
