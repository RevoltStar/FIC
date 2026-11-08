// Disposable native ALT control probe. Production profile is never narrowed.
#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/RollbackExecutor.h"

json altControlI5(const PlatformProfile& profile,
    const PlatformExecutableResolver& executables, const fs::path& root) {
    need(profile.id == "alt-p11" && fs::exists("/.dockerenv") && geteuid() == 0,
         "native disposable ALT root required");
    const auto& paths = fic::core::FicRuntimePaths::get();
    write(paths.configDir / "IDENTITY_ACCESS.conf",
          "enable_authentication_lockout.status=ENABLE\n"
          "enable_authentication_lockout.value=preauth_required\n"
          "enable_password_history.status=ENABLE\n");
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    need(journal != nullptr, error);
    auto command = [](const std::string& executable, const std::vector<std::string>& args) {
        auto r = ProcessExecutor::execute(executable, args);
        return json{{"started",r.started},{"exit",r.exitCode},{"stdout",r.standardOutput},{"stderr",r.standardError}};
    };
    const std::vector<fs::path> targets = {"/etc/pam.d/system-auth-local-only",
        "/etc/pam.d/system-auth-use_first_pass-local-only"};
    auto bytes = [&]() { json x; for(const auto& path:targets) x[path.string()]=read(path); return x; };
    auto snapshot = [&]() {
        json row; row["targets"]=bytes();
        row["journal"]=read(paths.mutationJournalFile);
        row["system_auth"]=fs::read_symlink("/etc/pam.d/system-auth").string();
        row["use_first_pass"]=fs::read_symlink("/etc/pam.d/system-auth-use_first_pass").string();
        row["system_policy"]=fs::read_symlink("/etc/pam.d/system-policy").string();
        row["capabilities"]=json::array();
        for (auto kind:{PamCapability::AuthenticationLockout,PamCapability::PasswordHistory}) {
            const auto* capability=p::capabilityConfig(profile.pam,kind);
            const auto* scope=p::scopeConfig(profile.pam,capability->scope);
            json member={{"name",pamCapabilityActivationPolicyName(kind)},{"services",scope->services}};
            auto manager=p::createPamTopologyManager(profile.pam,*capability,scope->services,executables,error);
            need(bool(manager),error); p::PamTopologyStatus state; error.clear();
            member["inspect"]=manager->inspect(state,error);
            member["state"]=static_cast<int>(state.state);member["detail"]=error;
            member["physical_mutation_id"]=state.ownershipMutationId ? json(*state.ownershipMutationId) : json(nullptr);
            p::PamConfiguration configuration(profile.pam);p::PamCapabilityVerification proof;
            member["structural"]=p::PamCapabilityVerifier::verify(configuration,profile.pam,
                scope->services,kind,capability->provider,proof,p::PamCapabilityVerificationMode::Structural);
            member["structural_detail"]=p::formatPamCapabilityVerification(proof);
            if(kind==PamCapability::PasswordHistory) {
                const auto* roots=p::scopeConfig(profile.pam,PamScope::EffectivePasswordStack);
                for(bool localOnly:{false,true}) {
                    auto proofPlatform=profile.pam;
                    for(auto& c:proofPlatform.capabilities) if(c.capability==kind && localOnly)
                        c.subjectScope=PamIdentitySubjectScope::LocalUsersOnly;
                    p::PamConfiguration selected(proofPlatform);p::PamCapabilityVerification selectedProof;
                    bool ok=p::PamCapabilityVerifier::verify(selected,proofPlatform,roots->services,kind,
                        capability->provider,selectedProof,p::PamCapabilityVerificationMode::Structural);
                    member[localOnly?"selected_local_proof":"selected_all_proof"]={{"ok",ok},
                        {"detail",p::formatPamCapabilityVerification(selectedProof)}};
                }
            }

            member["active_records"]=journal->activeRecords({"IDENTITY_ACCESS","PAM",pamCapabilityActivationPolicyName(kind)}).size();
            member["graph"]=json::array();
            for(const auto& service:scope->services) {
                json g={{"service",service},{"present",configuration.serviceExists(service)}};
                for(auto group:{p::PamManagementGroup::Auth,p::PamManagementGroup::Password}) {
                    std::vector<p::PamRule> rules;error.clear();
                    bool ok=configuration.collectRules(service,group,rules,error);
                    json graph={{"ok",ok},{"error",error},{"rules",json::array()}};
                    for(const auto& rule:rules) graph["rules"].push_back({{"source",rule.source.string()},
                        {"line",rule.line},{"control",rule.control},{"module",rule.module},{"arguments",rule.arguments}});
                    g[group==p::PamManagementGroup::Auth?"auth":"password"]=graph;
                }
                member["graph"].push_back(g);
            }
            row["capabilities"].push_back(member);
        }
        return row;
    };
    auto apply = [&]() { json result=json::array();
        for(auto kind:{PamCapability::AuthenticationLockout,PamCapability::PasswordHistory}) {
            PamCapabilityActivationPolicyOptions options;
            options.managerFactory=[&](const auto& capability,const auto& services,std::string& why) {
                return p::createPamTopologyManager(profile.pam,capability,services,executables,why);
            };
            PamCapabilityActivationPolicy policy(profile.pam,kind,options);
            result.push_back({{"name",pamCapabilityActivationPolicyName(kind)},{"ok",policy.apply()}});
        } return result;
    };
    fic::rollback::RollbackExecutorDeps deps;deps.pamPlatform=profile.pam;
    deps.pamManagerFactory=[&](const auto& capability,const auto& services,std::string& why) {
        return p::createPamTopologyManager(profile.pam,capability,services,executables,why);
    };
    auto release = [&]() { json result=json::array();
        for(auto kind:{PamCapability::AuthenticationLockout,PamCapability::PasswordHistory}) {
            auto r=fic::rollback::rollbackPolicyBeforeDisable(
                {"IDENTITY_ACCESS","PAM",pamCapabilityActivationPolicyName(kind)},"",deps);
            result.push_back({{"name",pamCapabilityActivationPolicyName(kind)},
                {"ok",r.rollbackCompleted()},{"status",static_cast<int>(r.status)},{"detail",r.message}});
        } return result;
    };
    json result;result["production_profile"]=profile.id;result["scope_narrowed"]=false;
    result["modes_available"]=command("/usr/sbin/control",{"system-auth","list"});
    result["system_policy_modes"]=command("/usr/sbin/control",{"system-policy","list"});
    result["sss_available"]=fs::exists("/etc/pam.d/system-auth-sss");
    result["stock_templates"]=json::object();
    for(const auto& file:fs::directory_iterator("/etc/pam.d")) {
        const auto name=file.path().filename().string();
        if(name.rfind("system-auth",0)==0 || name.rfind("system-check-localuser",0)==0 || name.rfind("system-policy",0)==0)
            result["stock_templates"][name]=read(file.path());
    }

    result["initial_control"]=command("/usr/sbin/control",{"system-auth","local"});
    result["initial"]=snapshot();result["activate"]=apply();result["activated"]=snapshot();
    // Preserve native stock templates and scopes. Missing service packages
    // remain missing; no LDAP/SSSD services are installed by this probe.
    result["modes"]=json::array();
    for(const auto* mode:{"local","multi","ldap","krb5","krb5_ccreds","winbind","pkcs11","local"}) {
        const auto controlBytes=bytes();const auto controlJournal=read(paths.mutationJournalFile);
        json row={{"mode",mode},{"control",command("/usr/sbin/control",{"system-auth",mode})}};
        row["control_status"]=command("/usr/sbin/control",{"system-auth","status"});
        row["policy_status"]=command("/usr/sbin/control",{"system-policy","status"});
        row["before"]=snapshot();row["control_bytes_preserved"]=bytes()==controlBytes;
        row["control_journal_preserved"]=read(paths.mutationJournalFile)==controlJournal;
        const auto beforeBytes=bytes();const auto beforeJournal=read(paths.mutationJournalFile);
        row["facilities"]=json::array();
        const auto diagnosticJournal=fic::core::FicProductPaths::production().mutationJournalFile;
        const bool diagnosticExisted=fs::exists(diagnosticJournal);
        const auto diagnosticBytes=read(diagnosticJournal);

        for(const auto* facility:{"fic-pam-faillock","fic-pam-pwhistory"})
            for(const auto* action:{"status","enabled","disabled"}) {
                row["facilities"].push_back({{"facility",facility},{"action",action},
                    {"result",command("/usr/sbin/control",{facility,action})}});
                need(bytes()==beforeBytes && read(paths.mutationJournalFile)==beforeJournal,
                     "control diagnostic/rejected action mutated PAM/journal");
                need(fs::exists(diagnosticJournal)==diagnosticExisted && read(diagnosticJournal)==diagnosticBytes,
                     "control facility changed default daemon journal");
            }
        row["apply"]=apply();row["after_apply"]=snapshot();
        row["apply_bytes_preserved"]=bytes()==beforeBytes;
        row["apply_journal_preserved"]=read(paths.mutationJournalFile)==beforeJournal;
        row["release"]=release();row["after_release"]=snapshot();
        // Restore the supported stock selection for the next independent
        // case, then use the SAME production policy paths to reacquire.
        row["restore_local"]=command("/usr/sbin/control",{"system-auth","local"});
        row["reacquire"]=apply();row["reacquired"]=snapshot();
        result["modes"].push_back(row);
    }
    // External unsupported selection, not an added trusted alias/control mode.
    write("/etc/pam.d/i5-unsupported",read("/etc/pam.d/system-auth-local"));
    fs::remove("/etc/pam.d/system-auth");fs::create_symlink("i5-unsupported","/etc/pam.d/system-auth");
    result["unsupported_before"]=snapshot();result["unsupported_apply"]=apply();
    result["unsupported_release"]=release();result["unsupported_after"]=snapshot();
    result["unsupported_restore"]=command("/usr/sbin/control",{"system-auth","local"});
    fs::remove("/etc/pam.d/i5-unsupported");
    result["missing_module_activate"]=apply();
    std::vector<fs::path> modules={"/lib64/security/pam_faillock.so","/lib64/security/pam_pwhistory.so"};
    for(const auto& module:modules) fs::rename(module,module.string()+".i5-hidden");
    result["missing_module_before"]=snapshot();
    result["missing_module_release"]=release();
    result["missing_module_after"]=snapshot();
    for(const auto& module:modules) fs::rename(module.string()+".i5-hidden",module);
    result["final_release"]=release();result["final"]=snapshot();
    // Journal crash-state fixtures use the real legacy payload and parser;
    // no marker ID or historical causality receipt is invented.
    result["journal_states"]=json::array();
    for(const auto* phase:{"PreparedBefore","PreparedAfter","RollbackFailed","AppliedAbsent"}) {
        json test={{"phase",phase}};
        if(std::string(phase)=="PreparedBefore") {
            for(auto kind:{PamCapability::AuthenticationLockout,PamCapability::PasswordHistory}) {
                const std::string name=pamCapabilityActivationPolicyName(kind);
                std::optional<fic::rollback::MutationRecord> prior;
                for(const auto& r:journal->records()) if(r.policy.policyName==name) prior=r;
                need(bool(prior),"missing historical native fixture record");
                auto record=*prior;record.id=0;record.status=fic::rollback::MutationStatus::Prepared;
                auto& undo=std::get<fic::rollback::UndoDisablePamCapability>(record.undo.payload);
                need(!undo.hadAppliedProvenance,"BEFORE fixture requires fresh native receipt");
                fic::rollback::MutationId id=0;need(journal->prepareMutation(record,id,error),error);
            }
        } else {
            test["activate"]=apply();
            for(auto kind:{PamCapability::AuthenticationLockout,PamCapability::PasswordHistory}) {
                const auto records=journal->activeRecords({"IDENTITY_ACCESS","PAM",pamCapabilityActivationPolicyName(kind)});
                need(records.size()==1,"expected one active native fixture record");
                if(std::string(phase)=="AppliedAbsent") {
                    const auto* c=p::capabilityConfig(profile.pam,kind);const auto* scope=p::scopeConfig(profile.pam,c->scope);
                    auto manager=p::createPamTopologyManager(profile.pam,*c,scope->services,executables,error);
                    need(manager && manager->disable(error),error); // external physical disappearance fixture
                } else need(journal->setStatus(records[0].id, std::string(phase)=="PreparedAfter"
                    ? fic::rollback::MutationStatus::Prepared : fic::rollback::MutationStatus::RollbackFailed,error),error);
            }
        }
        test["before"]=snapshot();test["apply"]=apply();test["after_apply"]=snapshot();
        test["release"]=release();test["after_release"]=snapshot();
        result["journal_states"].push_back(test);
    }
    result["orphan"]=json::array();
    for(auto kind:{PamCapability::AuthenticationLockout,PamCapability::PasswordHistory}) {
        const auto* c=p::capabilityConfig(profile.pam,kind);const auto* scope=p::scopeConfig(profile.pam,c->scope);
        auto manager=p::createPamTopologyManager(profile.pam,*c,scope->services,executables,error);
        need(manager && manager->enable(error),error);
    }
    const auto orphanBytes=bytes();const auto orphanJournal=read(paths.mutationJournalFile);
    result["orphan_apply"]=apply();result["orphan_release"]=release();
    result["orphan_bytes_preserved"]=bytes()==orphanBytes;
    result["orphan_journal_preserved"]=read(paths.mutationJournalFile)==orphanJournal;

    return result;
}
