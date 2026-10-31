#include "service/sssd/SssdTransactionCoordinator.h"
#include "rollback/SssdJournalPayload.h"
#include "modules/identity_access/sssd/SssdConfiguration.h"
#include "service/sssd/SssdRuntimeProof.h"
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
Ownership ownership(r::MutationJournal& journal,const SssdInputReference& input,const std::optional<AtomicTargetState>& current) {
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
        if(detail_i4::targetAssignments(domainScope(input),kind,value)!=p->current.assignments)
            refuse("SSSD sibling ownership has incomplete/inconsistent target set");
        if(!out.policies.emplace(rec.policy.policyName,rec).second)refuse("duplicate SSSD owner");
        if(p->current.scope!=detail_i4::scopeIdentity(domainScope(input)))refuse("domain/provider scope changed; no automatic scope migration");
        if(p->current.sequence>out.sequence){out.sequence=p->current.sequence;out.image=p->current.publication;}
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
void graphAfter(const SssdInputReference& before,const SssdInputReference& after,const AtomicTargetState& installed) {
    if(detail_i3::configurationOnly(before.launch.contract)!=detail_i3::configurationOnly(after.launch.contract)||
       before.launch.unitLookupFingerprint!=after.launch.unitLookupFingerprint||before.launch.executables!=after.launch.executables||
       before.consumers!=after.consumers||after.applyConflict())refuse("launch/consumer/late input changed around publication");
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
    auto captured=physical();if(!captured||!matches(witness(installed),captured))refuse("installed persistent image replaced");
    const auto& t=after.sources.at("/etc/sssd").tree;
    const auto& st=t.attributes.at(relative);
    if(t.files.at(relative)!=installed.content||st.st_ino!=installed.identity.inode||st.st_dev!=installed.identity.device||
       (st.st_mode&07777)!=(installed.mode&07777)||st.st_uid!=installed.owner||st.st_gid!=installed.group)refuse("I1 target not bound to installed object");
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
        out.targetMatches=t.publication.present&&matches(t.publication,state);
        out.targetBytesMatch=state&&sha(state->content)==t.targetSha256;
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
SssdTransactionResult detail_i4::executeForTests(r::MutationJournal& journal,const SssdTransactionRequest& request,const TransactionTestHooks& tests) {
    return perform(journal,request,&tests);
}
#endif
} // namespace fic::service::sssd
