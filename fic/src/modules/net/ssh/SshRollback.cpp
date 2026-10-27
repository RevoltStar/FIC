#include "modules/net/ssh/SshRollback.h"

#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "service/ssh/SshVerifiedActivationAdapter.h"
#include "rollback/MutationJournal.h"
#include "rollback/DaemonMutationJournal.h"
#include "modules/net/ssh/SshResourceLock.h"
#include "policy/registry/PolicyRegistry.h"
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <mutex>

#include <fic/core/fs/AtomicFileWriter.h>

#include "service/ssh/UbuntuSshSocketFlow.h"
#include "service/ssh/AltSshServiceFlow.h"
#include <algorithm>
#include <utility>

namespace {

SshRuntime makeRuntime(const SshRollbackOptions& options) {
    SshRuntimeOptions runtimeOptions;
    runtimeOptions.configPath = options.configPath;
    runtimeOptions.includeBasePath = options.includeBasePath;
    runtimeOptions.serviceUnits = options.serviceUnits;
    return SshRuntime(runtimeOptions, *options.executables, options.runner);
}

void requireOffline(const SshRollbackOptions& options) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    switch(options.offlineRelease) {
    case SshOfflineReleaseProfile::UbuntuSocket:fic::service::ssh::detail::UbuntuSshSocketFlow::requireOffline(deadline);return;
    case SshOfflineReleaseProfile::AltService:fic::service::ssh::detail::AltSshServiceFlow::requireOffline(deadline);return;
    default:throw std::runtime_error("unknown SSH offline release profile");
    }
}
SshConfigTransactionHooks makeHooks(const SshRollbackOptions& options) {
    SshConfigTransactionHooks hooks;
    hooks.beforeWrite = options.beforeWrite;
    hooks.beforeRestore = options.beforeRestore;
    if(options.offlineRelease!=SshOfflineReleaseProfile::None) {
        const auto offline=[options](std::string& error) {
            try {requireOffline(options);return true;}
            catch(const std::exception& e) {error=e.what();return false;}
        };
        hooks.offlineOwnershipRelease=true;hooks.verifiedAdmission=offline;
        hooks.verifiedActivation=[offline](const AtomicTargetState&,std::string& error) {return offline(error);};
    }
    return hooks;
}

bool publicationMatches(const fic::rollback::SshPublicationProof& proof,const AtomicTargetState& state) {
    return proof.device==static_cast<std::uint64_t>(state.identity.device)&&proof.inode==static_cast<std::uint64_t>(state.identity.inode)&&
        proof.mode==(state.mode&07777)&&proof.owner==state.owner&&proof.group==state.group&&
        proof.sha256==fic::core::ContentDigest::sha256Hex(state.content);
}
SshRollbackResult runVerifiedRelease(const SshRollbackOptions& options,
    const fic::rollback::UndoRemoveSshManagedPolicy& permission,SshConfigFileHandler& handler,bool hasArtifacts) {
    using namespace fic::rollback;
    using Adapter=fic::service::ssh::SshVerifiedActivationAdapter;
    using Intent=fic::service::ssh::SshActivationIntent;
    SshRollbackResult result;auto* journal=options.journal;bool pending=false,retry=false;
    const auto currentRecord=[&]() -> const MutationRecord* {
        if(journal)for(const auto& record:journal->records())if(record.id==options.mutationId)return &record;
        return nullptr;
    };
    const auto fail=[&](const std::string& message) {
        result.message=message;
        if(pending) {
            result.disposition=SshReleaseDisposition::RecoveryRequired;
            std::string checkpoint;if(journal&&journal->usable())journal->failSshTransition(options.mutationId,message.substr(0,4096),checkpoint);
            if(!checkpoint.empty())result.message+="; "+checkpoint;
        }
    };
    const auto abortNoEffect=[&](const std::string& message) {
        std::string error;
        if(!retry&&journal->abortSshTransitionNoEffect(options.mutationId,error)) {
            pending=false;result.message=message+"; no SSH replacement/activation by this attempt; predecessor retained";
        } else fail(message+"; "+error);
    };
    try {
        if(!journal||!journal->usable()||!options.mutationId||!options.remainingRequestedState||!handler.loadSnapshot()) {
            result.message="verified SSH release context/journal unavailable";return result;
        }
        const auto* record=currentRecord();const auto* owned=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
        const auto resource="ssh:"+options.configPath.string()+":"+permission.directive;
        if(!owned||record->policy!=PolicyRef{"NET","SshEdit",permission.policyName}||record->resource!=resource||
           owned->policyName!=permission.policyName||owned->directive!=permission.directive||owned->appliedValue!=permission.appliedValue||
           owned->disabledMutationIds!=permission.disabledMutationIds||owned->ownershipVersion!=permission.ownershipVersion||
           owned->wrapperFingerprints!=permission.wrapperFingerprints||
           normalizeSshKeyword(permission.directive)!=normalizeSshKeyword(sshPolicyDirectiveKeyword(permission.policyName))) {
            result.conflict=true;result.message="SSH release identity/permission mismatch";return result;
        }
        retry=sshReleaseAwaitingDisable(*owned)&&record->error.empty();pending=retry;
        if((record->status==MutationStatus::Prepared||sshTransitionPending(*owned))&&!retry) {
            result.disposition=SshReleaseDisposition::RecoveryRequired;
            result.message="RecoveryRequired: unresolved SSH operation; no automatic recovery";return result;
        }
        const auto prefix="ssh:"+options.configPath.string()+":";
        for(const auto& other:journal->records()) {
            const auto* p=std::get_if<UndoRemoveSshManagedPolicy>(&other.undo.payload);
            if(p&&other.id!=options.mutationId&&other.resource.rfind(prefix,0)==0&&
               (other.status==MutationStatus::Prepared||sshTransitionPending(*p))) {
                result.message="RecoveryRequired: another SSH shared-resource operation pending";
                result.disposition=SshReleaseDisposition::RecoveryRequired;return result;
            }
        }
        const auto before=*handler.loadSnapshot();
        if(retry&&(hasArtifacts||!owned->transition->publication||!publicationMatches(*owned->transition->publication,before))) {
            result.conflict=true;fail("recorded released SSH image changed/reappeared; no adoption or historical restoration");return result;
        }
        std::map<std::string,std::string> selected;std::string error;
        if(!options.remainingRequestedState(selected,error)){fail("remaining SSH intent unproven: "+error);return result;}
        const auto sameIntent=[&](std::string& detail) {
            std::map<std::string,std::string> fresh;
            if(!options.remainingRequestedState(fresh,detail))return false;
            if(fresh!=selected){detail="remaining SSH selections changed";return false;}
            return true;
        };
        auto planned=handler.lines();bool removed=false,restored=false;
        if(!removeSshManagedPolicyBlock(planned,permission.policyName,sshManagedDirectiveLine(permission.directive,permission.appliedValue),removed,error)||
           !restoreSshDisabledLines(planned,permission.policyName,permission.disabledMutationIds,restored,error)) {
            result.conflict=true;fail(error);return result;
        }
        SshConfigFileHandler image(options.configPath.string());image.lines()=planned;
        const auto target=hasArtifacts?image.pendingContent():before.content;
        const bool replacing=target!=before.content;
        auto baseline=Adapter::captureReference(selected,fic::core::ContentDigest::sha256Hex(before.content),Intent::ConfigurationRelease);
        const auto admission=Adapter::releaseAdmission(baseline);
        if(!retry) {
            if(!journal->beginSshRelease(options.mutationId,fic::core::ContentDigest::sha256Hex(before.content),
                fic::core::ContentDigest::sha256Hex(target),replacing,error)) {
                if(!journal->usable())result.disposition=SshReleaseDisposition::RecoveryRequired;
                result.message="SSH release prepare failed; ownership retained: "+error;return result;
            }
            pending=true;
        }
        const auto preview=Adapter::validateReleasePlan(baseline,admission,target);
        if(!preview.success()) {
            const bool cleaned=preview.snapshot.cleanupErrors.empty()&&preview.snapshot.residualPaths.empty()&&
                preview.snapshot.status!=fic::service::ActivationStatus::CleanupFailed;
            if(!retry&&cleaned)abortNoEffect("planned SSH release refused before CAS: "+preview.diagnostic);
            else fail("planned SSH release unproven: "+preview.diagnostic);
            return result;
        }
        SshConfigTransactionHooks hooks;hooks.beforeWrite=options.beforeWrite;hooks.offlineOwnershipRelease=admission.offline;
        hooks.verifiedAdmission=[&](std::string& detail) {
            if(!sameIntent(detail))return false;
            const auto current=Adapter::captureReference(selected,fic::core::ContentDigest::sha256Hex(before.content),Intent::ConfigurationRelease);
            if(!Adapter::sameInputGeneration(baseline,current,false)){detail="SSH inputs changed before release CAS";return false;}
            const auto service=Adapter::releaseAdmission(current);
            if(service.offline!=admission.offline||service.service!=admission.service){detail="SSH service changed before release CAS";return false;}
            return true;
        };
        hooks.verifiedActivation=[&](const AtomicTargetState& installed,std::string& detail) {
            if(!retry&&!journal->noteSshPublication(options.mutationId,installed,true,detail))return false;
            if(!sameIntent(detail)||!AtomicFileWriter::targetStateMatches(options.configPath.string(),installed,&detail))return false;
            auto next=Adapter::captureReference(selected,fic::core::ContentDigest::sha256Hex(installed.content),Intent::ConfigurationRelease);
            if(!Adapter::sameInputGeneration(baseline,next,replacing)){detail="foreign SSH input changed during release";return false;}
            const auto activated=Adapter::releaseConfiguration(next,admission);
            if(!journal->noteSshRuntime(options.mutationId,activated.success(),activated.observedFacts(),detail))return false;
            if(!activated.success()){detail="saved release; runtime/persistent result unproven: "+activated.diagnostic;return false;}
            return sameIntent(detail);
        };
        std::optional<AtomicTargetState> installed;
        if(replacing) {
            SshRuntime runtime=makeRuntime(options);
            const auto transaction=runSshConfigTransaction(handler,runtime,hooks,
                [&](std::string&){handler.lines()=planned;return true;},[](std::string&){return true;},"SSH ownership released");
            installed=transaction.installedTargetState;
            if(!transaction.ok) {
                if(transaction.provesNoEffect())abortNoEffect(transaction.message);
                else {
                    if(installed&&journal->usable()) {
                        const auto* r=currentRecord();const auto* p=r?std::get_if<UndoRemoveSshManagedPolicy>(&r->undo.payload):nullptr;
                        if(p&&p->transition&&static_cast<int>(p->transition->phase)<=static_cast<int>(SshTransitionPhase::DurablePublished))
                            journal->noteSshPublication(options.mutationId,*installed,transaction.persistentEffect==SshPersistentEffect::DurableInstalled,error);
                    }
                    fail(transaction.message);
                }
                return result;
            }
        } else {
            if(hooks.beforeWrite)hooks.beforeWrite();
            if(!hooks.verifiedAdmission(error)){if(retry)fail(error);else abortNoEffect(error);return result;}
            if(!AtomicFileWriter::ensureTargetDurableIfCurrentState(options.configPath.string(),before,&error)||
               !hooks.verifiedActivation(before,error)){fail(error);return result;}
            installed=before;
        }
        if(!installed||!AtomicFileWriter::targetStateMatches(options.configPath.string(),*installed,&error)||!sameIntent(error)) {
            fail("released SSH persistent/intent recheck failed: "+error);return result;
        }
        SshConfigFileHandler final(options.configPath.string());SshManagedModel model;
        if(!final.loadConfig()||parseSshManagedModel(final.lines(),model,error)!=SshManagedParseStatus::Ok||
           sshManagedModelHasPolicy(model,permission.policyName)||sshManagedModelHasDisabledForPolicy(model,permission.policyName)||
           !AtomicFileWriter::targetStateMatches(options.configPath.string(),*installed,&error)) {
            fail("physical SSH owner absence unproven: "+error);return result;
        }
        if(!retry&&!journal->finishSshReleaseVerification(options.mutationId,error)){fail(error);return result;}
        if(options.releaseContext==SshReleaseContext::Uninstall&&!journal->commitSshRelease(options.mutationId,error)){fail(error);return result;}
        result.ok=true;result.disposition=admission.offline?SshReleaseDisposition::ReleasedOffline:SshReleaseDisposition::RuntimeVerified;
        result.message=admission.offline?"ReleasedOffline; runtime NOT activated":"RuntimeVerified; released SSH configuration active";
        pending=false;
    } catch(const std::exception& error){fail(std::string("verified SSH release failed: ")+error.what());}
    return result;
}

} // namespace

SshRollbackResult undoSshManagedPolicyMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRemoveSshManagedPolicy& undo) {
    SshRollbackResult result;
    if (options.executables == nullptr || options.configPath.empty() ||
        undo.policyName.empty() || undo.directive.empty() ||
        undo.appliedValue.empty()) {
        result.message = "SSH rollback backend настроен неполно или undo payload "
                         "повреждён";
        return result;
    }

    if(!options.verifiedRelease&&options.offlineRelease!=SshOfflineReleaseProfile::None) {
        try {requireOffline(options);}
        catch(const std::exception& e) {result.message=e.what();return result;}
    }
    SshConfigFileHandler handler(options.configPath.string());
    if (!handler.loadConfig()) {
        // Malformed FIC markers are a drifted FIC ownership state: classify
        // as a conflict, never as a transient error.
        result.conflict = handler.lastLoadMarkerMalformed();
        result.message = "Не удалось проанализировать " +
                         options.configPath.string() +
                         " (в том числе структуру FIC-маркеров)";
        return result;
    }

    SshManagedModel model;
    std::string modelError;
    const SshManagedParseStatus status = parseSshManagedModel(
        handler.lines(), model, modelError);
    if (status != SshManagedParseStatus::Ok) {
        result.conflict = true;
        result.message = "Структура FIC-маркеров sshd_config повреждена "
                         "(файл не изменён): " + modelError;
        return result;
    }

    const std::string expectedDirectiveLine =
        sshManagedDirectiveLine(undo.directive, undo.appliedValue);
    bool blockOwned = false;
    const bool blockPresent = sshManagedModelHasPolicy(model, undo.policyName);
    if (blockPresent) {
        for (const SshManagedPolicyBlock& block : model.policies) {
            if (block.name == undo.policyName) {
                blockOwned =
                    block.directiveLine == expectedDirectiveLine;
                break;
            }
        }
    }
    const bool wrappersPresent =
        sshManagedModelHasDisabledForPolicy(model, undo.policyName);

    // Ownership-release provenance check (subset semantics): every wrapper
    // that still exists in the file must be proven by the journal payload;
    // payload ids whose wrappers have already disappeared are treated as
    // released and are not an error. A corrupted payload is refused
    // unconditionally; the existing-wrapper proof is required whenever any
    // FIC-owned state of the policy remains in the file (the neither-block-
    // nor-wrapper case below is the already-rolled-back / never-applied /
    // externally cleaned recovery state).
    const SshDisabledProvenanceCheck provenance = checkSshDisabledProvenance(
        model, undo.policyName, undo.disabledMutationIds,undo.wrapperFingerprints,undo.ownershipVersion);
    if (provenance.payloadMalformed) {
        result.conflict = true;
        result.message = "Journal payload политики '" + undo.policyName +
                         "' повреждён (дублирующийся mutation id); владение "
                         "не может быть доказано (файл не изменён)";
        return result;
    }
    if (blockPresent || wrappersPresent) {
        if (!provenance.safeToRelease()) {
            result.conflict = true;
            result.message =
                describeSshDisabledProvenance(provenance, undo.policyName) +
                "; владение не может быть доказано (файл не изменён)";
            return result;
        }
    }

    if(options.verifiedRelease) {
        if(blockPresent&&!blockOwned) {
            result.conflict=true;result.message="SSH owned block differs from recorded permission; no release";return result;
        }
        return runVerifiedRelease(options,undo,handler,blockPresent||wrappersPresent);
    }
    if(options.offlineRelease==SshOfflineReleaseProfile::UbuntuSocket)fic::service::ssh::detail::UbuntuSshSocketFlow::prepareRuntimeDirectory();
    if (!blockPresent && !wrappersPresent) {
        // Nothing FIC-owned remains for this policy: the mutation was never
        // applied or already factually rolled back (e.g. crash after the
        // file write but before the journal update). The runtime must still
        // be reconciled before the journal record is resolved.
        result.nothingToDo = true;
        SshRuntime runtime = makeRuntime(options);
        std::string validationError;
        if (!runtime.validateConfiguration(validationError)) {
            result.nothingToDo = false;
            result.message = "FIC не владеет состоянием политики '" +
                             undo.policyName +
                             "', но sshd -T не принимает текущую "
                             "конфигурацию; откат не подтверждён: " +
                             validationError;
            return result;
        }
        if (!handler.loadSnapshot().has_value()) {
            result.nothingToDo = false;
            result.message = "in-memory snapshot sshd_config недоступен; "
                             "durability не может быть привязана к "
                             "состоянию отката";
            return result;
        }
        std::string barrierError;
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                options.configPath.string(), *handler.loadSnapshot(),
                &barrierError)) {
            result.nothingToDo = false;
            result.message = "Durability состояния sshd_config не "
                             "подтверждена; откат не подтверждён: " +
                             barrierError;
            return result;
        }
        if(options.offlineRelease!=SshOfflineReleaseProfile::None) {
            try {requireOffline(options);}
            catch(const std::exception& e) {result.nothingToDo=false;result.message=e.what();return result;}
            result.message="offline ownership already released; runtime NOT activated";return result;
        }
        const SshActivationResult activation = runtime.activateIfRunning();
        if (!activation.ok) {
            result.nothingToDo = false;
            result.message = "Откат уже выполнен в sshd_config, но "
                             "перезагрузка SSH-сервиса не удалась: " +
                             activation.message;
            return result;
        }
        result.message = "FIC не владеет состоянием политики '" +
                         undo.policyName + "'; откат не требуется";
        return result;
    }
    // Wrapper provenance was already proven above (subset semantics: every
    // existing wrapper id is in the payload; payload ids whose wrappers have
    // disappeared are already released): the transaction below may restore
    // exactly the wrappers that still exist and nothing else.
    if (blockPresent && !blockOwned) {
        // The managed sub-block exists but its directive line does not match
        // the recorded applied value: the block was manually edited and FIC
        // refuses to overwrite user content by guesswork.
        result.conflict = true;
        result.message = "Содержимое FIC policy-блока '" + undo.policyName +
                         "' изменено вручную; владение не может быть "
                         "доказано (файл не изменён)";
        return result;
    }

    // Build the rollback edits in memory: remove the policy sub-block and
    // restore only the disabled lines this mutation owns. Other policies'
    // sub-blocks and wrappers are untouched.
    const SshConfigTransactionHooks hooks = makeHooks(options);
    SshRuntime runtime = makeRuntime(options);

    SshConfigTransactionResult transaction = runSshConfigTransaction(
        handler, runtime, hooks,
        [&handler, &undo, &expectedDirectiveLine](std::string& error) {
            bool removed = false;
            if (!removeSshManagedPolicyBlock(handler.lines(), undo.policyName,
                                             expectedDirectiveLine, removed,
                                             error)) {
                return false;
            }
            bool restored = false;
            if (!restoreSshDisabledLines(handler.lines(), undo.policyName,
                                         undo.disabledMutationIds, restored,
                                         error)) {
                return false;
            }
            return true;
        },
        // Rollback postcondition: the restored configuration must be
        // accepted by sshd (-t/-T). No policy value is expected here.
        [](std::string&) { return true; },
        "FIC-владение политикой '" + undo.policyName +
            "' в sshd_config отозвано");

    result.ok = transaction.ok;
    result.conflict = transaction.conflict;
    result.message = transaction.message;
    return result;
}

bool acknowledgeSshPolicyDisable(const PolicyRef& policy,const PolicyRegistry& registry,std::string& error) {
    using namespace fic::rollback;
    if(policy.moduleName!="NET"||policy.submoduleName!="SshEdit")return true;
    const std::lock_guard<std::mutex> lock(sshResourceMutex());
    auto* journal=DaemonMutationJournal::instance().tryGet(error);if(!journal)return false;
    const auto active=journal->activeRecords(policy);if(active.empty())return true;
    const auto* configured=registry.findPolicy(policy);
    std::string configPath;AtomicTargetState configState;
    if(!configured||configured->isEnabled()||!configured->captureConfigurationVersion(configPath,configState,error)||
       configPath!=(fic::core::FicRuntimePaths::get().configDir/"NET.conf").string()||configState.owner!=0||(configState.mode&0022)) {
        error="current disabled SSH registry/configuration proof unavailable: "+error;return false;
    }
    FileHandlerOptions readonly;readonly.writeOptions.createIfMissing=false;readonly.writeOptions.rejectSymlink=true;
    ConfigFileHandler config(configPath,"=",readonly);
    if(!config.loadConfig()||!config.isParameterExists(policy.policyName+".status")||
       config.getValue(policy.policyName+".status")!="DISABLE"||
       !AtomicFileWriter::ensureTargetDurableIfCurrentState(configPath,configState,&error)) {
        error="durable explicit SSH DISABLE unproven; release intent retained: "+error;return false;
    }
    const auto main=fic::platform::makeBuildPlatformProfile().ssh.configPath;
    for(const auto& record:active) {
        const auto* p=std::get_if<UndoRemoveSshManagedPolicy>(&record.undo.payload);
        if(!p||!sshReleaseAwaitingDisable(*p)||record.status!=MutationStatus::Prepared||
           record.resource!="ssh:"+main.string()+":"+p->directive||!p->transition->publication||!record.error.empty()) {
            error="SSH release is not explicitly verified/awaiting acknowledgement";return false;
        }
        SshConfigFileHandler handler(main.string());SshManagedModel model;
        if(!handler.loadConfig()||!handler.loadSnapshot()||!publicationMatches(*p->transition->publication,*handler.loadSnapshot())||
           parseSshManagedModel(handler.lines(),model,error)!=SshManagedParseStatus::Ok||
           sshManagedModelHasPolicy(model,policy.policyName)||sshManagedModelHasDisabledForPolicy(model,policy.policyName)||
           !AtomicFileWriter::targetStateMatches(main.string(),*handler.loadSnapshot(),&error)||
           !AtomicFileWriter::targetStateMatches(configPath,configState,&error)) {
            std::string checkpoint;journal->failSshTransition(record.id,"physical/configuration drift before DISABLE acknowledgement",checkpoint);
            error="released SSH physical/configuration state changed; intent retained: "+error;return false;
        }
        if(!journal->commitSshRelease(record.id,error))return false;
    }
    return true;
}
