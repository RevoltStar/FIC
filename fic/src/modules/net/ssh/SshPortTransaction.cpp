#include "modules/net/ssh/SshPortTransaction.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include <fic/core/integrity/ContentDigest.h>
#include <algorithm>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace {
using namespace fic::rollback;
using Adapter=fic::service::ssh::SshVerifiedActivationAdapter;
using Intent=fic::service::ssh::SshActivationIntent;
std::string digest(const std::string& bytes){return fic::core::ContentDigest::sha256Hex(bytes);}
SshPublicationProof proof(const AtomicTargetState& state,bool durable=false) {
    return {static_cast<std::uint64_t>(state.identity.device),static_cast<std::uint64_t>(state.identity.inode),
        static_cast<std::uint32_t>(state.mode&07777),state.owner,state.group,digest(state.content),durable};
}
std::vector<std::string> ids(const std::map<std::string,std::string>& map) {
    std::vector<std::string> out;for(const auto& [id,_]:map)out.push_back(id);return out;
}
void require(bool yes,const std::string& error){if(!yes)throw std::runtime_error(error);}
std::set<std::string> ownedPaths(const UndoRemoveSshManagedPolicy* previous) {
    std::set<std::string> paths;if(previous)for(const auto& [path,_]:previous->includedWrappers)paths.insert(path);return paths;
}
}
SshPortMutationPlan planSshPortMutation(fic::service::ssh::SshPortSourceMap source,
    const fic::rollback::UndoRemoveSshManagedPolicy* previous,const std::string& value,bool release) {
    SshPortMutationPlan plan;plan.source=std::move(source);
    require(!plan.source.reference.reference.paths.empty(),"Port source reference missing main");
    // Adapter capture always puts the trusted profile main first. Keeping the
    // captured path here also permits isolated planner tests without /etc writes.
    const auto main=plan.source.reference.reference.paths.front().path.string();
    require(plan.source.files.count(main),"Port plan lacks trusted main");
    if(previous) {
        require(previous->policyName=="ssh_port"&&previous->directive=="Port","Port permission identity mismatch");
        plan.targetOwnership=*previous;plan.targetOwnership.transition.reset();
    } else {plan.targetOwnership.policyName="ssh_port";plan.targetOwnership.directive="Port";}
    plan.targetOwnership.appliedValue=value;
    std::string error;int ordinal=0;
    for(const auto& [path,before]:plan.source.files) {
        SshConfigFileHandler file(path);
        require(file.loadConfig()&&file.loadSnapshot()&&file.loadSnapshot()->content==before.content&&
            file.loadSnapshot()->identity.device==before.identity.device&&file.loadSnapshot()->identity.inode==before.identity.inode&&
            AtomicFileWriter::targetStateMatches(path,before,&error),"Port source changed: "+path+": "+error);
        SshManagedModel model;
        require(parseSshManagedModel(file.lines(),model,error)==SshManagedParseStatus::Ok,error);
        const bool isMain=path==main;
        require(isMain||!model.blockPresent,"Included file contains an unsupported FIC container");
        std::vector<std::string> allowed;std::map<std::string,std::string> hashes;std::uint32_t version=1;
        if(previous) {
            if(isMain){allowed=previous->disabledMutationIds;hashes=previous->wrapperFingerprints;version=previous->ownershipVersion;}
            else if(auto old=previous->includedWrappers.find(path);old!=previous->includedWrappers.end()){hashes=old->second;allowed=ids(hashes);}
        }
        for(const auto& wrapper:model.disabled)require(wrapper.policy=="ssh_port"||isMain,"unattributable foreign policy wrapper in Include");
        const auto provenance=checkSshDisabledProvenance(model,"ssh_port",allowed,hashes,version);
        require(provenance.safeToRelease(),describeSshDisabledProvenance(provenance,"ssh_port"));
        if(isMain) {
            const auto found=std::find_if(model.policies.begin(),model.policies.end(),[](const auto& p){return p.name=="ssh_port";});
            if(previous) {
                require(release||found!=model.policies.end(),"recorded Port block disappeared; no recreation");
                require(found==model.policies.end()||found->directiveLine==sshManagedDirectiveLine("Port",previous->appliedValue),"owned Port block drift");
            } else require(found==model.policies.end()&&!sshManagedModelHasDisabledForPolicy(model,"ssh_port"),"orphan Port markers");
        }
        bool changed=false;
        if(release) {
            if(isMain)require(removeSshManagedPolicyBlock(file.lines(),"ssh_port",sshManagedDirectiveLine("Port",previous->appliedValue),changed,error),error);
            require(restoreSshDisabledLines(file.lines(),"ssh_port",allowed,changed,error),error);
        } else {
            // Physical positions come from the bounded logical Include graph;
            // each file is edited once, and only currently global active Ports.
            if(auto positions=plan.source.graph.globalPorts.find(path);positions!=plan.source.graph.globalPorts.end()) {
                for(auto pos=positions->second.rbegin();pos!=positions->second.rend();++pos) {
                    if(isMain&&model.blockPresent&&*pos>=model.blockBegin&&*pos<=model.blockEnd)continue;
                    const auto directive=parseSshConfigLine(file.lines().at(*pos));
                    require(directive.ok&&directive.hasDirective&&normalizeSshKeyword(directive.directive.keyword)=="port"&&
                        directive.directive.arguments.size()==1,"ambiguous physical Port source");
                    auto number=directive.directive.arguments.front();
                    if(!number.empty()&&number.front()=='+')number.erase(0,1);
                    require(!number.empty()&&number.find_first_not_of("0123456789")==std::string::npos,"unsupported original Port syntax");
                    const auto significant=number.find_first_not_of('0');
                    require(significant!=std::string::npos,"zero original Port unsupported");
                    number.erase(0,significant);
                    require(number.size()<=5&&std::stoul(number)<=65535,"original Port outside native range");
                    const auto token=generateSshDisabledMutationId(++ordinal);
                    hashes.emplace(token,digest(file.lines().at(*pos)));allowed.push_back(token);
                    disableSshLine(file.lines(),*pos,"ssh_port",token);
                }
            }
            if(isMain)require(upsertSshManagedPolicyBlock(file.lines(),"ssh_port",sshManagedDirectiveLine("Port",value),changed,error),error);
            if(isMain){plan.targetOwnership.disabledMutationIds=allowed;plan.targetOwnership.wrapperFingerprints=hashes;}
            else if(!hashes.empty())plan.targetOwnership.includedWrappers[path]=hashes;
        }
        const auto target=file.pendingContent();plan.targets.emplace(path,target);
        SshPlannedFilePublication publication;publication.before=proof(before);publication.targetSha256=digest(target);
        publication.replacement=before.content!=target;plan.changed|=publication.replacement;
        plan.publication.emplace(path,std::move(publication));
    }
    // Legacy ID-only no-op is permitted, but never promote observed wrapper
    // bodies to historical fingerprints or extend that ownership by REFRESH.
    if(previous&&previous->ownershipVersion==0&&!previous->disabledMutationIds.empty())
        require(release||!plan.changed,"legacy ID-only wrappers block Port REFRESH");
    else if(!release)plan.targetOwnership.ownershipVersion=1;
    return plan;
}

bool publishSshPortPlan(fic::rollback::MutationJournal& journal,fic::rollback::MutationId id,
    const SshPortMutationPlan& plan,const std::function<bool(std::string&)>& admission,
    const std::function<void()>& beforeWrite,std::map<std::string,AtomicTargetState>& installed,std::set<std::string>& notInstalled,std::string& error) {
    const auto main=fic::service::ssh::detail::inputProfile().mainFile;
    try {
        if(beforeWrite)beforeWrite();
        for(const auto& [path,before]:plan.source.files) {
            require(admission(error),error);
            const auto mainSha=installed.count(main)?digest(installed.at(main).content):digest(plan.source.files.at(main).content);
            const auto fresh=Adapter::capturePortSources(mainSha);
            require(Adapter::sameAuthorizedPortGeneration(plan.source.reference,fresh.reference,installed),"SSH graph/foreign generation changed before per-file CAS");
            require(AtomicFileWriter::targetStateMatches(path,before,&error),error);
            require(journal.noteSshFileAttempt(id,path,error),error);
            AtomicTargetState target;
            if(plan.publication.at(path).replacement) {
                // Publish the exact image produced by the SSH serializer.
                AtomicWriteOptions options;options.createIfMissing=false;options.rejectSymlink=true;options.expectedTargetState=before;
                AtomicWriteResult result;
                const bool saved=AtomicFileWriter::writeWithResult(path,plan.targets.at(path),options,&error,&result);
                if(!saved&&!result.installed&&!result.installedTargetState)notInstalled.insert(path);
#ifdef FIC_SSH_TRANSACTION_TESTING
                FileHandler::FileSaveOutcome observed;observed.installed=result.installed;
                observed.result=saved?FileHandler::FileSaveResult::Installed:FileHandler::FileSaveResult::Failed;
                observed.durabilityConfirmed=result.durabilityConfirmed;observed.installedTargetState=result.installedTargetState;
                observeSshSaveOutcomeForTests(observed);result.durabilityConfirmed=observed.durabilityConfirmed;
#endif
                if(result.installed&&result.installedTargetState) {
                    installed[path]=*result.installedTargetState;
                    require(journal.noteSshFilePublication(id,path,*result.installedTargetState,result.durabilityConfirmed,error),error);
                }
                require(saved&&result.installed&&result.durabilityConfirmed&&result.installedTargetState.has_value(),"Port CAS/durability unproven: "+error);
                target=*result.installedTargetState;
            } else {
                // An unchanged foreign file may have been edited in-place by
                // its administrator. Parent fsync alone does not flush data.
                const int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
                require(fd>=0,"cannot pin unchanged SSH input for durability");
                struct stat info{};
                const bool flushed=::fstat(fd,&info)==0&&info.st_dev==before.identity.device&&info.st_ino==before.identity.inode&&::fsync(fd)==0;
                ::close(fd);require(flushed,"unchanged SSH input fsync/identity failed");
                require(AtomicFileWriter::ensureTargetDurableIfCurrentState(path,before,&error),error);target=before;installed[path]=target;
                require(journal.noteSshFilePublication(id,path,target,true,error),error);
            }
            require(AtomicFileWriter::targetStateMatches(path,target,&error),error);
        }
        require(journal.noteSshPublication(id,installed.at(main),true,error),error);
        return true;
    } catch(const std::exception& e){error=e.what();return false;}
}

SshPortOperationResult applySshPortGraph(fic::rollback::MutationJournal& journal,const PolicyRef& policy,
    const std::string& value,const AtomicTargetState& mainSnapshot,const std::map<std::string,std::string>& expectedService,
    const std::map<std::string,std::string>& additionalPolicies,const std::function<bool(std::string&)>& currentIntent,
    const std::function<void()>& beforeWrite) {
    SshPortOperationResult result;MutationId id=0;bool pending=false;
    try {
        const auto records=journal.activeRecords(policy);
        const UndoRemoveSshManagedPolicy* old=nullptr;
        if(!records.empty()) {
            const auto main=fic::service::ssh::detail::inputProfile().mainFile;
            require(records.size()==1&&records[0].status==MutationStatus::Applied&&records[0].undo.backend==MutationBackend::Ssh&&
                records[0].policy==policy&&records[0].resource=="ssh:"+main+":Port","exact Applied Port resource ownership required");
            old=std::get_if<UndoRemoveSshManagedPolicy>(&records[0].undo.payload);require(old,"Port undo payload missing");id=records[0].id;
        }
        auto source=Adapter::capturePortSources(digest(mainSnapshot.content),ownedPaths(old));
        auto plan=planSshPortMutation(std::move(source),old,value);
        const std::map<std::string,std::string> selected{{"ssh_port",value}};
        Adapter::validatePortPlan(plan.source,plan.targets,selected,Intent::SelectedPolicies);
        std::string error;require(currentIntent(error),error);
        require(Adapter::serviceAdmission()==expectedService,"SSH service changed during Port planning");
        if(!plan.changed) {
            require(old,"initial Port apply did not establish ownership");
            auto request=Adapter::captureReference(selected,digest(mainSnapshot.content));
            require(Adapter::sameAuthorizedPortGeneration(plan.source.reference,request,{}),"SSH graph changed before owned Port no-op");
            request.expectedService=expectedService;request.additionalPolicies=additionalPolicies;
            const auto activated=Adapter::activate(request);require(activated.success(),activated.diagnostic);
            require(currentIntent(error),error);result.ok=true;result.message="owned Port graph unchanged";return result;
        }
        if(old)require(journal.beginSshPortChange(id,plan.targetOwnership,plan.publication,false,error),error);
        else {
            const auto main=fic::service::ssh::detail::inputProfile().mainFile;
            require(journal.prepareSshPortInitial(policy,main,plan.targetOwnership,plan.publication,id,error),error);
        }
        pending=true;std::map<std::string,AtomicTargetState> installed;std::set<std::string> notInstalled;
        const auto admission=[&](std::string& detail){return currentIntent(detail)&&Adapter::serviceAdmission()==expectedService;};
        if(!publishSshPortPlan(journal,id,plan,admission,beforeWrite,installed,notInstalled,error)) {
            std::string abort;if(journal.abortSshPortNoEffect(id,notInstalled,abort))pending=false;
            throw std::runtime_error(error+(pending?"; no-effect abort unavailable: "+abort:"; proven no effect; intent aborted"));
        }
        require(admission(error),error);
        const auto main=fic::service::ssh::detail::inputProfile().mainFile;
        auto request=Adapter::captureReference(selected,digest(installed.at(main).content));
        require(Adapter::sameAuthorizedPortGeneration(plan.source.reference,request,installed),"SSH foreign inputs changed after Port publication");
        request.expectedService=expectedService;request.additionalPolicies=additionalPolicies;
        const auto activated=Adapter::activate(request);
        require(journal.noteSshRuntime(id,activated.success(),activated.observedFacts(),error),error);
        require(activated.success(),activated.diagnostic);require(currentIntent(error),error);
        for(const auto& [path,state]:installed)require(AtomicFileWriter::targetStateMatches(path,state,&error),error);
        require(journal.commitSshRefresh(id,error),error);pending=false;result.ok=true;result.message="Port graph ownership applied";
    } catch(const std::exception& e) {
        result.message=e.what();if(pending){std::string checkpoint;journal.failSshTransition(id,result.message.substr(0,4096),checkpoint);result.message+="; Prepared retained: "+checkpoint;}
    }
    return result;
}

bool verifySshPortReleasedFiles(const fic::rollback::SshOwnershipTransition& transition,std::string& error) {
    if(transition.version!=3){error="missing multi-file release receipts";return false;}
    for(const auto& [path,f]:transition.files) {
        AtomicTargetState state;SshConfigFileHandler file(path);SshManagedModel model;
        if(!f.publication||!f.publication->durable||!file.loadConfig()||!file.loadSnapshot()||
           parseSshManagedModel(file.lines(),model,error)!=SshManagedParseStatus::Ok||
           sshManagedModelHasPolicy(model,"ssh_port")||sshManagedModelHasDisabledForPolicy(model,"ssh_port"))return false;
        state=*file.loadSnapshot();struct stat links{};
        if(::lstat(path.c_str(),&links)||!S_ISREG(links.st_mode)||links.st_nlink!=1){error="released SSH file alias/type unproven";return false;}
        const auto expected=*f.publication;const auto actual=proof(state,true);
        if(actual.device!=expected.device||actual.inode!=expected.inode||actual.mode!=expected.mode||actual.owner!=expected.owner||
           actual.group!=expected.group||actual.sha256!=expected.sha256||!AtomicFileWriter::targetStateMatches(path,state,&error)) {
            error="released SSH file drift before acknowledgement";return false;
        }
    }
    return true;
}

#include "modules/net/ssh/SshRollback.h"
SshRollbackResult releaseSshPortGraph(const SshRollbackOptions& options,
    const fic::rollback::UndoRemoveSshManagedPolicy& permission,const AtomicTargetState& mainSnapshot) {
    using namespace fic::rollback;
    SshRollbackResult result;bool pending=false;
    const auto record=[&]() -> const MutationRecord* {
        if(options.journal)for(const auto& r:options.journal->records())if(r.id==options.mutationId)return &r;
        return nullptr;
    };
    try {
        require(options.journal&&options.remainingRequestedState&&options.mutationId,"Port release context unavailable");
        auto& journal=*options.journal;const auto* current=record();
        const auto* owned=current?std::get_if<UndoRemoveSshManagedPolicy>(&current->undo.payload):nullptr;
        const auto main=fic::service::ssh::detail::inputProfile().mainFile;
        require(owned&&current->policy==PolicyRef{"NET","SshEdit","ssh_port"}&&current->resource=="ssh:"+main+":Port"&&
            owned->appliedValue==permission.appliedValue&&owned->disabledMutationIds==permission.disabledMutationIds&&
            owned->wrapperFingerprints==permission.wrapperFingerprints&&owned->includedWrappers==permission.includedWrappers,
            "Port release permission mismatch");
        const bool retry=sshReleaseAwaitingDisable(*owned)&&current->error.empty();pending=retry;
        require(retry||(current->status!=MutationStatus::Prepared&&!sshTransitionPending(*owned)),"unresolved Port operation; no automatic recovery");
        for(const auto& other:journal.records())if(other.id!=options.mutationId&&other.resource.rfind("ssh:"+main+":",0)==0) {
            auto* p=std::get_if<UndoRemoveSshManagedPolicy>(&other.undo.payload);
            require(!p||(other.status!=MutationStatus::Prepared&&!sshTransitionPending(*p)),"another SSH operation pending");
        }
        std::map<std::string,std::string> selected;std::string error;
        require(options.remainingRequestedState(selected,error),error);
        require(!selected.count("ssh_port"),"released Port still selected");
        const auto sameIntent=[&](std::string& detail) {
            std::map<std::string,std::string> now;
            if(!options.remainingRequestedState(now,detail)||now!=selected){detail="remaining SSH selections changed";return false;}return true;
        };
        auto source=Adapter::capturePortSources(digest(mainSnapshot.content),ownedPaths(owned));
        auto baseline=Adapter::captureReference(selected,digest(mainSnapshot.content),Intent::ConfigurationRelease);
        require(Adapter::sameAuthorizedPortGeneration(source.reference,baseline,{}),"Port release capture changed");
        baseline.allowReleasedPortSet=true;
        const auto admission=Adapter::releaseAdmission(baseline);
        if(retry) {
            require(verifySshPortReleasedFiles(*owned->transition,error),error);
            const auto activated=Adapter::releaseConfiguration(baseline,admission);
            require(journal.noteSshRuntime(options.mutationId,activated.success(),activated.observedFacts(),error),error);
            require(activated.success(),activated.diagnostic);require(sameIntent(error),error);
        } else {
            auto plan=planSshPortMutation(std::move(source),owned,permission.appliedValue,true);
            Adapter::validatePortPlan(plan.source,plan.targets,selected,Intent::ConfigurationRelease);
            require(sameIntent(error),error);
            require(journal.beginSshPortChange(options.mutationId,{},plan.publication,true,error),error);pending=true;
            const auto recheck=[&](std::string& detail) {
                if(!sameIntent(detail))return false;
                const auto mainSha=digest(plan.source.files.at(main).content);
                // Service admission is read-only; source generation checks are
                // independently performed before every file publication.
                auto request=plan.source.reference;
                const auto now=Adapter::releaseAdmission(request);
                if(now.offline!=admission.offline||now.service!=admission.service){detail="SSH release service changed";return false;}
                return true;
            };
            // releaseAdmission above needs the original digests; after any CAS
            // use the pinned runtime-only snapshot from the initial admission.
            const auto admissionBeforePublication=[&](std::string& detail){return sameIntent(detail);};
            require(recheck(error),error);
            std::map<std::string,AtomicTargetState> installed;std::set<std::string> notInstalled;
            if(!publishSshPortPlan(journal,options.mutationId,plan,admissionBeforePublication,options.beforeWrite,installed,notInstalled,error)) {
                std::string abort;if(journal.abortSshPortNoEffect(options.mutationId,notInstalled,abort))pending=false;
                throw std::runtime_error(error+(pending?"; no-effect abort unavailable: "+abort:"; proven no effect; intent aborted"));
            }
            require(sameIntent(error),error);
            auto next=Adapter::captureReference(selected,digest(installed.at(main).content),Intent::ConfigurationRelease);
            next.allowReleasedPortSet=true;
            require(Adapter::sameAuthorizedPortGeneration(plan.source.reference,next,installed),"foreign SSH inputs changed during release");
            const auto activated=Adapter::releaseConfiguration(next,admission);
            require(journal.noteSshRuntime(options.mutationId,activated.success(),activated.observedFacts(),error),error);
            require(activated.success(),activated.diagnostic);require(sameIntent(error),error);
            for(const auto& [path,state]:installed)require(AtomicFileWriter::targetStateMatches(path,state,&error),error);
            require(journal.finishSshReleaseVerification(options.mutationId,error),error);
        }
        const auto* verified=std::get_if<UndoRemoveSshManagedPolicy>(&record()->undo.payload);
        require(verified&&verified->transition&&verifySshPortReleasedFiles(*verified->transition,error),error);
        if(options.releaseContext==SshReleaseContext::Uninstall)require(journal.commitSshRelease(options.mutationId,error),error);
        result.ok=true;result.disposition=admission.offline?SshReleaseDisposition::ReleasedOffline:SshReleaseDisposition::RuntimeVerified;
        result.message=admission.offline?"ReleasedOffline; runtime NOT activated":"RuntimeVerified; multi-file Port released";pending=false;
    } catch(const std::exception& e) {
        result.message=e.what();if(pending){std::string checkpoint;options.journal->failSshTransition(options.mutationId,result.message.substr(0,4096),checkpoint);result.message+="; Prepared retained: "+checkpoint;result.disposition=SshReleaseDisposition::RecoveryRequired;}
    }
    return result;
}
