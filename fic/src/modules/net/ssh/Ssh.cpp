#include "modules/net/ssh/Ssh.h"

#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/SshResourceLock.h"
#include "service/ssh/SshVerifiedActivationAdapter.h"
#include <fic/core/integrity/ContentDigest.h>

#include "rollback/DaemonMutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/i18n/LocalizationManager.h>

#include <algorithm>
#include <mutex>
#include <utility>

namespace {

std::string sshMutationResource(const std::filesystem::path& configPath,
                                const std::string& parameter) {
    return "ssh:" + configPath.string() + ":" + parameter;
}

// Ownership state of the current configuration against one journal payload.
struct SshOwnershipState {
    bool blockPresent = false;
    bool blockOwned = false;   // sub-block line == recorded applied line
    bool wrappersPresent = false;
    bool wrappersValid = false;
    bool malformed = false;
    std::string error;
};

SshOwnershipState analyzeOwnership(const std::vector<std::string>& lines,
                                   const fic::rollback::UndoRemoveSshManagedPolicy& undo) {
    SshOwnershipState state;
    SshManagedModel model;
    std::string error;
    const SshManagedParseStatus status =
        parseSshManagedModel(lines, model, error);
    if (status != SshManagedParseStatus::Ok) {
        state.malformed = true;
        state.error = error;
        return state;
    }
    const std::string expectedLine =
        sshManagedDirectiveLine(undo.directive, undo.appliedValue);
    for (const SshManagedPolicyBlock& block : model.policies) {
        if (block.name == undo.policyName) {
            state.blockPresent = true;
            state.blockOwned = block.directiveLine == expectedLine;
            break;
        }
    }
    for (const SshDisabledBlock& disabled : model.disabled) {
        if (disabled.policy == undo.policyName) {
            state.wrappersPresent = true;
        }
    }
    // Journal payload provenance is proven unconditionally: a corrupted
    // payload (duplicate mutation ids) must fail closed even when every
    // FIC-owned artifact of the policy has already disappeared — neither the
    // compliance fast-path nor the planner may silently accept a damaged
    // active record. Ownership-release subset semantics are unchanged:
    // payload ids whose wrappers no longer exist are treated as already
    // released (releasedIds) and never make this check fail. Only a
    // duplicate payload id, a duplicate actual wrapper id or an actual
    // wrapper absent from the payload is an error.
    state.wrappersValid = true;
    const SshDisabledProvenanceCheck provenance = checkSshDisabledProvenance(
        model, undo.policyName, undo.disabledMutationIds,undo.wrapperFingerprints,undo.ownershipVersion);
    if (!provenance.safeToRelease()) {
        state.wrappersValid = false;
        state.error =
            describeSshDisabledProvenance(provenance, undo.policyName);
    }
    return state;
}

// Port is multi-value: the policy postcondition is that the effective port
// set is exactly the configured value.
bool verifyEffectiveValue(SshRuntime& runtime,
                          SshDirectiveSemantics semantics,
                          const std::string& directive,
                          const std::string& expectedValue,
                          std::string& error) {
    if (semantics == SshDirectiveSemantics::MultiValue) {
        std::vector<std::string> values;
        if (!runtime.effectiveValues(directive, values, error)) {
            return false;
        }
        if (values.size() == 1 && values.front() == expectedValue) {
            return true;
        }
        error = "effective-набор значений '" + directive + "' не соответствует "
                "политике";
        return false;
    }
    return runtime.verifyPolicyValue(directive, expectedValue, error);
}


} // namespace

Ssh::~Ssh() = default;

Ssh::Ssh(fic::platform::SshPlatformConfig platformConfig,
         const fic::platform::PlatformExecutableResolver& executables)
    : Net(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables),
      runtimeOptions_(std::make_unique<SshRuntimeOptions>(SshRuntimeOptions{
          platformConfig_.configPath,
          platformConfig_.includeBasePath,
          platformConfig_.serviceUnits
      })),
      sshConfig_(std::make_unique<SshConfigFileHandler>(
          platformConfig_.configPath.string())) {
    this->submoduleName = "SshEdit";
}

SshRollbackOptions Ssh::makeRollbackOptions() const {
    SshRollbackOptions options;
    options.offlineRelease=platformConfig_.applyContract==fic::platform::SshApplyContract::AltVerified?SshOfflineReleaseProfile::AltService:
            platformConfig_.applyContract==fic::platform::SshApplyContract::UbuntuSocketVerified?SshOfflineReleaseProfile::UbuntuSocket:SshOfflineReleaseProfile::None;
    options.configPath = platformConfig_.configPath;
    options.includeBasePath = platformConfig_.includeBasePath;
    options.serviceUnits = platformConfig_.serviceUnits;
    options.executables = &executables_;
    options.runner = commandRunner_;
    options.beforeWrite = beforeWriteHook_;
    options.beforeRestore = beforeRestoreHook_;
    return options;
}

bool Ssh::apply() {
    if (this->sshParameter.empty()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:parameter_not_configured_part1]") +
                      this->policyName +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:parameter_not_configured_part2]"),
                  logLevel::FATAL);
        return false;
    }

    const std::lock_guard<std::mutex> lock(sshResourceMutex());

    const std::optional valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    const std::string expectedValue = *valueOpt;
    if (expectedValue.empty() || expectedValue == "[NO VALUE SET]") {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:reference_value_empty_part1]") +
                      this->policyName +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:reference_value_empty_part2]"),
                  logLevel::ERROR);
        return false;
    }

    // Explicit directive semantics: an unclassified SSH policy must fail
    // closed instead of assuming scalar first-obtained-value behavior.
    const SshDirectiveSemantics semantics =
        sshPolicyDirectiveSemantics(this->policyName);
    if (semantics == SshDirectiveSemantics::Unsupported) {
        this->log("SSH-политика '" + this->policyName +
                      "' не имеет объявленной семантики директивы; применение "
                      "отклонено",
                  logLevel::ERROR);
        return false;
    }

    using Adapter = fic::service::ssh::SshVerifiedActivationAdapter;
    using Reference = fic::service::ssh::SshVerifiedActivationRequest;
    const bool verified = platformConfig_.applyContract != fic::platform::SshApplyContract::Legacy;
    std::map<std::string,std::string> serviceBaseline;
    if (verified) {
        try { serviceBaseline = Adapter::serviceAdmission(); }
        catch (const std::exception& e) { this->log(e.what(), logLevel::ERROR); return false; }
    }
    SshRuntime runtime(*runtimeOptions_, executables_, commandRunner_);
    const std::string sshPath = platformConfig_.configPath.string();
    const std::string resource =
        sshMutationResource(platformConfig_.configPath, this->sshParameter);

    if (!this->sshConfig_->loadConfig()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:load_failed]"),
                  logLevel::ERROR);
        return false;
    }

    // Crash-consistent journaling: resolve the provenance BEFORE the
    // compliance decision and before any mutation.
    fic::rollback::MutationId mutationId = 0;
    bool newRecord = false;
    std::vector<fic::rollback::MutationRecord> activeRecords;
    std::string journalError;
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        this->log("Mutation journal недоступен" +
                      std::string(journalError.empty() ? "" : ": " + journalError),
                  logLevel::ERROR);
        return false;
    }
    activeRecords = journal->activeRecords(this->policyRef());

    // Schema 2 cannot distinguish a safe interrupted apply from a failed
    // compensation or an uncertain service effect. Gate the shared file,
    // including attempts by another SSH policy, before runtime commands.
    for (const auto& record : journal->records()) {
        if (record.undo.backend == fic::rollback::MutationBackend::Ssh &&
            (record.status == fic::rollback::MutationStatus::Prepared ||
             (std::get_if<fic::rollback::UndoRemoveSshManagedPolicy>(&record.undo.payload) &&
              fic::rollback::sshTransitionPending(std::get<fic::rollback::UndoRemoveSshManagedPolicy>(record.undo.payload)))) &&
            record.resource.rfind("ssh:" + sshPath + ":", 0) == 0) {
            this->log("SSH recovery required: unresolved Prepared mutation " +
                      std::to_string(record.id) + "; автоматическое применение запрещено", logLevel::ERROR);
            return false;
        }
    }

    fic::rollback::UndoRemoveSshManagedPolicy payload;
    payload.policyName = this->policyName;
    payload.directive = this->sshParameter;
    payload.appliedValue = expectedValue;
    // Ownership analysis of the current configuration against the newest
    // active record (all active records of the policy share the same
    // policyName/directive; only appliedValue and wrapper ids differ).
    SshOwnershipState ownership;
    bool hasExistingRecord = !activeRecords.empty();
    if (hasExistingRecord) {
        const fic::rollback::MutationRecord& newest = activeRecords.back();
        if (newest.undo.backend != fic::rollback::MutationBackend::Ssh) {
            this->log("Активная запись mutation journal политики '" +
                          this->policyName + "' имеет неожиданный backend",
                  logLevel::ERROR);
            return false;
        }
        const auto* newestPayload = std::get_if<
            fic::rollback::UndoRemoveSshManagedPolicy>(&newest.undo.payload);
        if (newestPayload == nullptr) {
            this->log("Активная запись mutation journal политики '" +
                          this->policyName + "' повреждена",
                  logLevel::ERROR);
            return false;
        }
        mutationId = newest.id;
        ownership = analyzeOwnership(this->sshConfig_->lines(), *newestPayload);
        if (ownership.malformed) {
            this->log("Структура FIC-маркеров sshd_config повреждена: " +
                          ownership.error,
                  logLevel::ERROR);
            return false;
        }
        if (newest.status == fic::rollback::MutationStatus::Prepared &&
            ownership.blockPresent && !ownership.blockOwned) {
            this->log("Prepared SSH-мутация не восстановлена: содержимое "
                      "FIC-блока изменено вручную; требуется ручное разрешение",
                  logLevel::ERROR);
            return false;
        }
        if (newest.status == fic::rollback::MutationStatus::Prepared &&
            !ownership.wrappersValid) {
            this->log("Prepared SSH-мутация не восстановлена: владение "
                      "существующими FIC_DISABLED блоками не доказано "
                      "journal payload'ом: " +
                          ownership.error,
                  logLevel::ERROR);
            return false;
        }
        if (newest.status != fic::rollback::MutationStatus::Prepared &&
            ((ownership.blockPresent && !ownership.blockOwned) ||
             !ownership.wrappersValid)) {
            // A drift of the FIC-owned state (for example a manually edited
            // block or an unproven wrapper id) must never be silently
            // overwritten. Wrappers that merely disappeared externally are
            // not a drift: ownership-release semantics treats them as
            // already released.
            this->log("FIC-владение политикой '" + this->policyName +
                          "' не может быть доказано (изменённый FIC-блок или "
                          "несовпадающий провенанс DISABLED маркеров): " +
                          ownership.error + "; применение отклонено",
                  logLevel::ERROR);
            return false;
        }
    }
    // Legacy test contract keeps its old explicit release path. Verified
    // profiles retain the predecessor and plan a single atomic REFRESH.
    if (hasExistingRecord) {
        bool valueChanged = false;
        for (const fic::rollback::MutationRecord& record : activeRecords) {
            const auto* recordPayload = std::get_if<
                fic::rollback::UndoRemoveSshManagedPolicy>(&record.undo.payload);
            if (recordPayload != nullptr &&
                recordPayload->appliedValue != expectedValue) {
                valueChanged = true;
            }
        }
        if (valueChanged && !verified) {
            SshRollbackOptions rollbackOptions = makeRollbackOptions();
            for (const fic::rollback::MutationRecord& record : activeRecords) {
                const auto* recordPayload = std::get_if<
                    fic::rollback::UndoRemoveSshManagedPolicy>(
                    &record.undo.payload);
                if (recordPayload == nullptr) {
                    this->log("Активная запись mutation journal политики '" +
                                  this->policyName + "' повреждена",
                          logLevel::ERROR);
                    return false;
                }
                const SshRollbackResult rollback = undoSshManagedPolicyMutation(
                    rollbackOptions, *recordPayload);
                // Ownership-release semantics: NothingToDo means every
                // previously owned artifact is already gone (external edit,
                // earlier rollback + crash, ...) — the old state counts as
                // released, and the new value must be applied to the actual
                // current configuration, not to a reconstructed one.
                if (!rollback.ok && !rollback.nothingToDo) {
                    this->log("Не удалось откатить предыдущее состояние "
                              "политики '" + this->policyName + "': " +
                                  rollback.message,
                          logLevel::ERROR);
                    return false;
                }
                std::string statusError;
                if (!journal->setStatus(
                        record.id, fic::rollback::MutationStatus::RolledBack,
                        statusError)) {
                    this->log("Ошибка фиксации статуса отката в mutation "
                              "journal: " + statusError,
                          logLevel::ERROR);
                    return false;
                }
            }
            activeRecords.clear();
            hasExistingRecord = false;
            // The rollback of the previous owned state changed the on-disk
            // file behind this handler's back: reload it before planning the
            // new state so the conditional atomic write compares against the
            // actual current state.
            if (!this->sshConfig_->loadConfig()) {
                this->log(LocalizationManager::getLang(
                              "[module:NET][submodule:SshEdit][message:load_failed]"),
                          logLevel::ERROR);
                return false;
            }
        }
    }

    // Ownership sanity BEFORE the compliance fast-path: a malformed FIC
    // ownership structure, or a stale/orphan FIC policy block or
    // FIC_DISABLED wrapper of this policy without an active journal record,
    // must never be silently accepted just because sshd -T shows a
    // compliant effective value.
    {
        SshManagedModel model;
        std::string modelError;
        if (parseSshManagedModel(this->sshConfig_->lines(), model,
                                 modelError) != SshManagedParseStatus::Ok) {
            this->log("Структура FIC-маркеров sshd_config повреждена: " +
                          modelError,
                  logLevel::ERROR);
            return false;
        }
        if (!hasExistingRecord &&
            (sshManagedModelHasPolicy(model, this->policyName) ||
             sshManagedModelHasDisabledForPolicy(model, this->policyName))) {
            this->log("Обнаружены FIC-маркеры политики '" + this->policyName +
                          "' без активной записи mutation journal; применение "
                          "отклонено",
                  logLevel::ERROR);
            return false;
        }
    }

    Reference baseline;
    std::map<std::string,std::string> additionalPolicies;
    if(verified) for(const auto* id:{"ssh_root_login","ssh_pubkey_auth","ssh_use_pam","ssh_max_auth_tries","ssh_port"}) {
        if(this->moduleConf->hasPolicyStatus(id)&&this->moduleConf->getPolicyStatus(id)=="ENABLE"&&this->moduleConf->hasConfiguredValue(id))
            additionalPolicies.emplace(id,this->moduleConf->getPolicyValue(id));
    }
    const std::map<std::string,std::string> selected{{this->policyName, expectedValue}};
    if (verified) {
        try {
            if (!this->sshConfig_->loadSnapshot()) throw std::runtime_error("SSH main snapshot unavailable");
            baseline = Adapter::captureReference(selected,
                fic::core::ContentDigest::sha256Hex(this->sshConfig_->loadSnapshot()->content));
            baseline.expectedService = serviceBaseline;
            baseline.additionalPolicies = additionalPolicies;
            Adapter::prepareRuntimeProbe(baseline);
        } catch (const std::exception& e) { this->log(e.what(), logLevel::ERROR); return false; }
    }
    // Every foreign input must remain the exact captured reference. Only the
    // main file may change, and only when separately bound to our CAS receipt.
    const auto sameInputs = [&](const Reference& next, bool ownMainChanged) {
        if (baseline.reference.paths.size() != next.reference.paths.size()) return false;
        auto metadata = next.observedMetadata;
        auto expectedMetadata = baseline.observedMetadata;
        if (ownMainChanged) { metadata.erase(sshPath); expectedMetadata.erase(sshPath); }
        if (metadata != expectedMetadata) return false;
        for (std::size_t i=0; i<baseline.reference.paths.size(); ++i) {
            const auto& a=baseline.reference.paths[i]; const auto& b=next.reference.paths[i];
            if (a.path!=b.path || a.kind!=b.kind || a.manifest!=b.manifest ||
                (!(ownMainChanged && a.path==sshPath) && a.sha256!=b.sha256)) return false;
        }
        return true;
    };

    // Compliance fast-path: a configuration that already satisfies the
    // policy must not be rewritten (idempotent re-apply).
    const SshComplianceResult compliance =
        runtime.policyValueCompliance(this->sshParameter, expectedValue);
    if (verified && compliance.compliance == SshCompliance::Unknown) {
        this->log("SSH compliance unknown: " + compliance.error, logLevel::ERROR);
        return false;
    }
    if (compliance.compliance == SshCompliance::Compliant) {
        if (verified) {
            const auto result = Adapter::activate(baseline);
            if (!result.success()) { this->log(result.diagnostic, logLevel::ERROR); return false; }
        }
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:already_configured]") +
                      this->sshParameter + " = " + expectedValue,
                  logLevel::INFO);
        return true;
    }
    // ---- Planning (in-memory, on a copy of the loaded snapshot) ----
    // (Ownership sanity — malformed markers and orphan FIC state — has
    // already been proven before the compliance fast-path.)

    std::vector<std::string> planned = this->sshConfig_->lines();
    bool changed = false;
    std::string planError;
    std::vector<std::string> newWrapperIds;

    if (!upsertSshManagedPolicyBlock(
            planned, this->policyName,
            sshManagedDirectiveLine(this->sshParameter, expectedValue),
            changed, planError)) {
        this->log("Не удалось спланировать FIC policy-блок: " + planError,
                  logLevel::ERROR);
        return false;
    }

    if (semantics == SshDirectiveSemantics::MultiValue) {
        // Every other effective occurrence of the directive (outside the FIC
        // managed block and outside FIC_DISABLED wrappers) must be disabled
        // with a fresh provenance id. Covered line ranges come from the
        // parsed model of the planned content.
        SshManagedModel model;
        std::string modelError;
        if (parseSshManagedModel(planned, model, modelError) !=
            SshManagedParseStatus::Ok) {
            this->log("Внутренняя ошибка планирования FIC-маркеров: " +
                          modelError,
                  logLevel::ERROR);
            return false;
        }
        std::vector<bool> covered(planned.size(), false);
        if (model.blockPresent) {
            for (std::size_t i = model.blockBegin; i <= model.blockEnd; ++i) {
                covered[i] = true;
            }
        }
        for (const SshDisabledBlock& disabled : model.disabled) {
            for (std::size_t i = disabled.beginLine; i <= disabled.endLine;
                 ++i) {
                covered[i] = true;
            }
        }
        int ordinal = 1;
        for (std::size_t i = planned.size(); i-- > 0;) {
            if (covered[i]) {
                continue;
            }
            const SshLineParseResult parsed = parseSshConfigLine(planned[i]);
            if (!parsed.ok || !parsed.hasDirective) {
                continue;
            }
            if (normalizeSshKeyword(parsed.directive.keyword) !=
                normalizeSshKeyword(this->sshParameter)) {
                continue;
            }
            const std::string wrapperId =
                generateSshDisabledMutationId(ordinal++);
            disableSshLine(planned, i, this->policyName, wrapperId);
            newWrapperIds.push_back(wrapperId);
            changed = true;
        }
    }

    if (!changed && hasExistingRecord) {
        this->log("SSH unchanged owned state: " +
                      std::string(compliance.compliance == SshCompliance::NonCompliant
                                      ? "noncompliant: " : "compliance unknown: ") +
                      compliance.error,
                  logLevel::ERROR);
        return false;
    }
    const bool refresh=verified&&hasExistingRecord;
    const fic::rollback::UndoRemoveSshManagedPolicy* previousPayload=hasExistingRecord?
        std::get_if<fic::rollback::UndoRemoveSshManagedPolicy>(&activeRecords.back().undo.payload):nullptr;
    if(hasExistingRecord && (!refresh||activeRecords.size()!=1||activeRecords.back().resource!=resource||
       activeRecords.back().status!=fic::rollback::MutationStatus::Applied||!ownership.blockPresent||!ownership.blockOwned||
       !previousPayload || (previousPayload->ownershipVersion==0&&!previousPayload->disabledMutationIds.empty()))) {
        this->log("SSH REFRESH refused: exact Applied ownership required; legacy ID-only wrappers need manual resolution",logLevel::ERROR);
        return false;
    }
    // Retain all prior wrapper identities and their historical fingerprints.
    // Newly planned wrappers bind their original bytes at creation, never by
    // promoting observed legacy wrapper bodies into historical authority.
    payload.ownershipVersion=1;
    if(previousPayload) {
        payload.disabledMutationIds=previousPayload->disabledMutationIds;
        payload.wrapperFingerprints=previousPayload->wrapperFingerprints;
    }
    payload.disabledMutationIds.insert(payload.disabledMutationIds.end(),newWrapperIds.begin(),newWrapperIds.end());
    SshManagedModel targetModel;
    if(parseSshManagedModel(planned,targetModel,planError)!=SshManagedParseStatus::Ok)return false;
    for(const auto& wrapper:targetModel.disabled)
        if(wrapper.policy==this->policyName && std::find(newWrapperIds.begin(),newWrapperIds.end(),wrapper.mutationId)!=newWrapperIds.end())
            payload.wrapperFingerprints.emplace(wrapper.mutationId,fic::core::ContentDigest::sha256Hex(wrapper.originalLine));
    // Get the exact writer serialization from the shared writer itself.
    SshConfigFileHandler target(sshPath);target.lines()=planned;
    std::string recordError;
    const bool prepared=refresh?
        journal->beginSshRefresh(mutationId,payload,
            fic::core::ContentDigest::sha256Hex(this->sshConfig_->loadSnapshot()->content),
            fic::core::ContentDigest::sha256Hex(target.pendingContent()),recordError):
        fic::rollback::recordPreparedMutation(this->policyRef(),resource,
            fic::rollback::UndoAction{fic::rollback::MutationBackend::Ssh,payload},mutationId,recordError);
    if(!prepared) {this->log("SSH ownership prepare failed: "+recordError,logLevel::ERROR);return false;}
    newRecord=!refresh;

    // ---- Transaction: conditional atomic write -> durability -> verify ->
    //      reload; compensation restores the exact pre-attempt snapshot ----

    SshConfigTransactionHooks hooks;
    hooks.beforeWrite = beforeWriteHook_;
    hooks.beforeRestore = beforeRestoreHook_;
    if (verified) {
        hooks.verifiedAdmission = [&](std::string& error) {
            try {
                if (Adapter::serviceAdmission() != serviceBaseline) throw std::runtime_error("SSH runtime/launch changed before CAS");
                const auto current = Adapter::captureReference(selected,
                    fic::core::ContentDigest::sha256Hex(this->sshConfig_->loadSnapshot()->content));
                if (!sameInputs(current, false)) throw std::runtime_error("SSH inputs changed before CAS");
                return true;
            } catch (const std::exception& e) { error=e.what(); return false; }
        };
        hooks.verifiedActivation = [&](const AtomicTargetState& installed, std::string& error) {
            try {
                if(refresh&&!journal->noteSshPublication(mutationId,installed,true,error))return false;
                if (!AtomicFileWriter::targetStateMatches(sshPath, installed, &error)) return false;
                if (Adapter::serviceAdmission()!=serviceBaseline) throw std::runtime_error("SSH runtime/launch changed after save");
                auto next = Adapter::captureReference(selected, fic::core::ContentDigest::sha256Hex(installed.content));
                if (!sameInputs(next, true)) throw std::runtime_error("foreign SSH input changed after save; provenance retained");
                if (!AtomicFileWriter::targetStateMatches(sshPath, installed, &error)) return false;
                next.expectedService=serviceBaseline;
                next.additionalPolicies=additionalPolicies;
                const auto result=Adapter::activate(next);
                if(refresh) {
                    const auto name=[](fic::service::ssh::ProofState p){return p==fic::service::ssh::ProofState::Proven?"Proven":p==fic::service::ssh::ProofState::NonCompliant?"NonCompliant":"NotProven";};
                    auto facts=result.runtimeEvidence;
                    facts["inputs"]=name(result.inputs);facts["semantics"]=name(result.semantics);facts["persistent"]=name(result.persistent);
                    facts["readiness"]=result.activation.readinessConfirmed?"true":"false";
                    facts["status"]=fic::service::activationStatusName(result.activation.status);
                    facts["adapter_status"]=std::to_string(static_cast<int>(result.status));
                    if(!journal->noteSshRuntime(mutationId,result.success(),facts,error))return false;
                }
                if (!result.success()) { error="Persistent configuration saved; verified activation failed; provenance retained: " + result.diagnostic; return false; }
                return true;
            } catch (const std::exception& e) { error=e.what(); return false; }
        };
    }

    SshConfigTransactionResult transaction = runSshConfigTransaction(
        *this->sshConfig_, runtime, hooks,
        // Plan: apply the planned edits to the live handler state.
        [this, &planned](std::string& error) {
            this->sshConfig_->lines() = planned;
            (void)error;
            return true;
        },
        // Postcondition: the managed block carries the exact policy line and
        // the effective runtime state satisfies the policy (for Port the
        // effective value set must be exactly the configured value).
        [&runtime, &semantics, &expectedValue, this](std::string& error) {
            SshManagedModel model;
            if (parseSshManagedModel(this->sshConfig_->lines(), model, error) !=
                SshManagedParseStatus::Ok) {
                error = "повреждённая структура FIC-маркеров после записи: " +
                        error;
                return false;
            }
            bool found = false;
            for (const SshManagedPolicyBlock& block : model.policies) {
                if (block.name == this->policyName) {
                    found = block.directiveLine ==
                            sshManagedDirectiveLine(this->sshParameter,
                                                    expectedValue);
                    break;
                }
            }
            if (!found) {
                error = "FIC policy-блок политики '" + this->policyName +
                        "' не подтверждён в записанном файле";
                return false;
            }
            return verifyEffectiveValue(runtime, semantics, this->sshParameter,
                                        expectedValue, error);
        },
        "Политика '" + this->policyName + "' применена к sshd_config");

    if (!transaction.ok) {
        bool refreshAbortedNoEffect=false;
        if(refresh) {
            std::string checkpoint;
            if(transaction.provesNoEffect()) {
                refreshAbortedNoEffect=journal->abortSshRefreshNoEffect(mutationId,checkpoint);
                if(!refreshAbortedNoEffect)
                    this->log("SSH no-effect abort failed; ownership retained: "+checkpoint,logLevel::ERROR);
            } else {
                if(transaction.installedTargetState&&journal->usable()) {
                    for(const auto& current:journal->records())if(current.id==mutationId) {
                        const auto* p=std::get_if<fic::rollback::UndoRemoveSshManagedPolicy>(&current.undo.payload);
                        if(p&&p->transition&&static_cast<int>(p->transition->phase)<=static_cast<int>(fic::rollback::SshTransitionPhase::DurablePublished))
                            journal->noteSshPublication(mutationId,*transaction.installedTargetState,
                                transaction.persistentEffect==SshPersistentEffect::DurableInstalled,checkpoint);
                        break;
                    }
                }
                if(journal->usable())journal->failSshRefresh(mutationId,transaction.message.substr(0,4096),checkpoint);
            }
        }
        if (transaction.mayDiscardPrepared(newRecord)) {
            std::string discardError;
            if (!fic::rollback::discardMutation(mutationId, discardError))
                this->log("Ошибка удаления no-effect Prepared: " + discardError, logLevel::WARN);
        } else if(!refreshAbortedNoEffect) {
            this->log("SSH recovery required: unresolved Prepared provenance retained", logLevel::ERROR);
        }
        this->log("Применение политики '" + this->policyName +
                      "' не выполнено: " + transaction.message,
                  logLevel::ERROR);
        return false;
    }

    std::string commitError;
    if (!(refresh?journal->commitSshRefresh(mutationId,commitError):fic::rollback::commitMutation(mutationId, commitError))) {
        this->log("SSH-мутация применена, но запись mutation journal не "
                  "зафиксирована: " + commitError,
              logLevel::ERROR);
        return false;
    }
    newRecord = false;

    this->log(transaction.message, logLevel::INFO);
    return true;
}