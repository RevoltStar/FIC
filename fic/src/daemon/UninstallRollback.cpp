#include "daemon/UninstallRollback.h"
#include "daemon/UninstallReleaseOrder.h"
#include "daemon/PackageReleaseResources.h"
#include "daemon/PackageWritersQuiescence.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/ScopeTransition.h"
#include "rollback/UnrecordedResourceInspection.h"
#include "modules/sysctl/Sysctl.h"
#include "modules/dac/sudo/Sudo.h"
#include "modules/net/ssh/Ssh.h"
#include "modules/firewall/FirewallBackend.h"
#include "modules/identity_access/pam/PamTopologyManagerFactory.h"
#include <fic/core/runtime/PackageState.h>
#include <map>
#include <set>
namespace fic::daemon {
namespace {
using namespace fic::rollback;
std::string group(const PolicyRef& ref) {
    if(ref.moduleName=="IDENTITY_ACCESS"&&(ref.submoduleName=="PAM"||ref.submoduleName=="PAM_CONTAINER"))return "PAM";
    if(ref.moduleName=="OSS"&&ref.submoduleName=="DesktopEnvironment")return "DE";
    if(ref.moduleName=="OSS"&&ref.submoduleName=="DisplayManager")return "DM";
    return formatPolicyRef(ref);
}
std::string resourceHint(const Policy& policy) {
    if(const auto* p=dynamic_cast<const Sysctl*>(&policy))return p->managedResource();
    if(const auto* p=dynamic_cast<const Sudo*>(&policy))return p->managedResource();
    if(const auto* p=dynamic_cast<const Ssh*>(&policy))return p->managedResource();
    if(policy.moduleName=="IDENTITY_ACCESS"&&policy.submoduleName=="SSSD"&&policy.policyName=="sssd_offline_credentials_expiration")return "pam/offline_credentials_expiration";
    if(policy.moduleName=="IDENTITY_ACCESS"&&policy.submoduleName=="KERBEROS"&&policy.policyName=="kerberos_ticket_lifetime")return "libdefaults/ticket_lifetime";
    if(policy.moduleName=="OSS"&&policy.submoduleName=="Grub") {
        if(policy.policyName=="grub_timeout")return "GRUB_TIMEOUT";
        if(policy.policyName=="grub_cmdline_linux")return "GRUB_CMDLINE_LINUX";
        if(policy.policyName=="grub_disable_recovery")return "GRUB_DISABLE_RECOVERY";
    }
    return {};
}
const char* domainName(PackageReleaseDomain domain) {
    switch(domain) {
    case PackageReleaseDomain::DisplayManager:return "DM";
    case PackageReleaseDomain::Desktop:return "DE";
    case PackageReleaseDomain::PamProvider:return "PAM_PROVIDER";
    case PackageReleaseDomain::PamPassword:return "PAM_PASSWORD";
    case PackageReleaseDomain::AltHistoryTopology:return "ALT_PWHISTORY";
    case PackageReleaseDomain::AltFaillockTopology:return "ALT_FAILLOCK";
    }
    return "UNKNOWN";
}
struct Node {
    std::vector<PolicyRef> policies;
    std::set<std::string> dependents;
    bool done=false,ok=false;
};
}
nlohmann::json rollbackAllForUninstall(PolicyRegistry& registry,const DaemonInstanceLock& guard,
    const fic::platform::PlatformProfile& platform,const fic::platform::PlatformExecutableResolver& executables) {
    using json=nlohmann::json;
    json results=json::array();
    const auto failure=[](const std::string& error){return json{{"ok",false},{"message",error}};};
    if(!guard.heldByCurrentProcess()||fic::core::readPackageState().state!=fic::core::PackageState::Uninstalling)
        return failure("rollback all requires daemon admission and proven UNINSTALLING state");
    std::string error;
    const auto fence=fic::core::readPackageState();
    if(fence.state!=fic::core::PackageState::Uninstalling||
       !AtomicFileWriter::ensureTargetDurableIfCurrentState(fic::core::PACKAGE_STATE_FILE,fence.file.targetState,&error))
        return failure("UNINSTALLING durability is unproven: "+error);
    if(!PackageWritersQuiescence(executables).stopAuxiliaryWriters(
            std::chrono::steady_clock::now()+std::chrono::seconds(30),error))
        return failure("auxiliary writer drain failed; no rollback attempted: "+error);
    auto* journal=DaemonMutationJournal::instance().tryGet(error);
    if(!journal){auto result=failure("MutationJournal unavailable; no rollback attempted. Emergency SKIP requires explicit administrator configuration: "+error);
        result["error_code"]="ROLLBACK_STATE_UNPROVEN";return result;}
    if(registry.policyRefs().empty()){auto result=failure("PolicyRegistry unavailable; no rollback attempted");result["error_code"]="ROLLBACK_STATE_UNPROVEN";return result;}
    std::map<std::string,Node> nodes;
    for(const auto& ref:registry.policyRefs())nodes[group(ref)].policies.push_back(ref);
    for(const auto& ref:registry.policyRefs()) {
        for(const auto& dependency:registry.findPolicy(ref)->dependencies()) {
            // Conservative for every configured/disabled owner: recorded
            // ownership is independent of its current enabled status/value.
            if(dependency.strength!=PolicyDependencyStrength::Required)continue;
            if(!registry.findPolicy(dependency.policy))return failure("unknown Required dependency: "+formatPolicyRef(dependency.policy));
            if(group(ref)!=group(dependency.policy))nodes[group(dependency.policy)].dependents.insert(group(ref));
        }
    }
    std::map<std::string,std::set<std::string>> edges;
    for(const auto& [name,node]:nodes)edges[name]=node.dependents;
    std::vector<std::string> releaseOrder;
    if(!uninstallReleaseOrder(edges,releaseOrder,error))return failure(error+"; no rollback attempted");
    auto deps=productionRollbackDeps(platform,executables,&registry);
    // Joint rollback sees the uninstall target, never the saved ENABLE values.
    deps.sudoRequestedState=[](bool& auth,bool& scoped,std::string&){auth=false;scoped=false;return true;};
    deps.pamPasswordRequestedState=[](bool& quality,bool& history,std::string&){quality=false;history=false;return true;};
    deps.sshRequestedState=[](const std::string&,auto& selected,std::string&){selected.clear();return true;};
    deps.sshReleaseContext=SshReleaseContext::Uninstall;
    deps.pamManagerFactory=[&](const fic::platform::PamCapabilityConfig& capability,
        const std::vector<std::string>& services,std::string& detail){
        return fic::identity::pam::createPamTopologyManager(platform.pam,capability,services,executables,detail);
    };
    // Unknown active ownership is never silently omitted. Internal provider
    // containers are handled by the existing domain preflight, which validates
    // exact provider identity/payload and orphan physical state.
    bool unknown=false;
    for(const auto& record:journal->records()) {
        if(!record.isActive()||registry.findPolicy(record.policy))continue;
        if(record.policy.moduleName=="IDENTITY_ACCESS"&&record.policy.submoduleName=="PAM_CONTAINER"&&
           record.undo.backend==MutationBackend::Pam)continue;
        results.push_back({{"policy",formatPolicyRef(record.policy)},{"status","UNSUPPORTED"},
            {"message","active journal record has no registered owner"},{"mutation_id",record.id}});
        unknown=true;
    }
    // Without a known owner/resource relation, independence cannot be proved.
    if(unknown)return json{{"ok",false},{"error_code","ROLLBACK_STATE_UNPROVEN"},{"message","Unknown active ownership; no rollback attempted"},{"results",results}};
    PackageReleaseResources resources(platform,fic::core::FicRuntimePaths::get());
    const auto releaseDomain=[&](PackageReleaseDomain domain) {
        PackageResourceReleaseReport report;
        const bool released=resources.preflight(domain,*journal,report,error)&&
               resources.release(guard,domain,*journal,report,error)&&
               resources.proveReleased(domain,*journal,error);
        results.push_back({{"domain",domainName(domain)},{"status",released?"RELEASED":"FAILED"},
            {"message",error},{"provider",{{"released_records",report.provider.releasedRecords},
                {"containers_deleted",report.provider.containersDeleted},{"containers_detached",report.provider.containersDetached},
                {"containers_retained",report.provider.containersRetained},{"changed_system_state",report.provider.changedSystemState}}},
            {"password",{{"recovered_crash_leftovers",report.password.recoveredCrashLeftovers},
                {"detached_identities",report.password.detachedIdentities},{"changed_system_state",report.password.changedSystemState},
                {"compensated",report.password.compensated},{"compensated_state_proven",report.password.compensatedStateProven}}}});
        if(!released)return false;
        if(domain==PackageReleaseDomain::Desktop||domain==PackageReleaseDomain::DisplayManager) {
            ScopeTransition scope(*journal,domain==PackageReleaseDomain::Desktop?
                ScopeTransition::Domain::Desktop:ScopeTransition::Domain::DisplayManager);
            ScopeTransitionState checkpoint;
            if(!scope.state(checkpoint,error))return false;
            // A scope checkpoint grants no physical ownership. Retire it only
            // after the domain's independent release proof has succeeded.
            if(checkpoint.id&&!journal->setStatus(checkpoint.id,MutationStatus::RolledBack,error))return false;
        }
        return true;
    };
    bool overall=true;
    std::size_t releasedGroups=0,failedGroups=0,blockedGroups=0;
    for(const auto& name:releaseOrder) {
            auto& node=nodes.at(name);
            bool blocked=false;
            for(const auto& dependent:node.dependents) {
                blocked|=nodes.at(dependent).done&&!nodes.at(dependent).ok;
            }
            node.done=true;node.ok=!blocked;
            if(blocked) {
                results.push_back({{"resource_group",name},{"status","BLOCKED_BY_DEPENDENCY"}});
                ++blockedGroups;
                overall=false;continue;
            }
            error.clear();
            if(name=="DE")node.ok=releaseDomain(PackageReleaseDomain::Desktop);
            else if(name=="DM")node.ok=releaseDomain(PackageReleaseDomain::DisplayManager);
            else {
                if(name=="PAM") {
                    if(platform.id=="alt-p11")node.ok=releaseDomain(PackageReleaseDomain::AltHistoryTopology)&&releaseDomain(PackageReleaseDomain::AltFaillockTopology);
                    if(node.ok)node.ok=releaseDomain(PackageReleaseDomain::PamProvider);
                    if(node.ok) {
                        switch(resources.supports(PackageReleaseDomain::PamPassword,error)) {
                        case PackageReleaseSupport::Supported:
                            node.ok=releaseDomain(PackageReleaseDomain::PamPassword);
                            break;
                        case PackageReleaseSupport::NotApplicable:
                            results.push_back({{"domain","PAM_PASSWORD"},{"status","NOT_APPLICABLE"},{"message",error}});
                            break;
                        case PackageReleaseSupport::Error:
                            node.ok=false;
                            results.push_back({{"domain","PAM_PASSWORD"},{"status","FAILED"},{"message",error}});
                            break;
                        }
                    }
                }
                if(node.ok)for(const auto& ref:node.policies) {
                    const auto enrollment=effectiveRollbackEnrollment(ref,deps);
                    if(enrollment==RollbackEnrollment::NotEnrolled) {
                        // An active record under a non-reverting policy is not
                        // an excuse to discard provenance (Scope is joint).
                        bool active=false;for(const auto& record:journal->activeRecords(ref))active|=record.undo.backend!=MutationBackend::Scope;
                        if(!active){results.push_back({{"policy",formatPolicyRef(ref)},{"status","NOT_ENROLLED"}});continue;}
                        results.push_back({{"policy",formatPolicyRef(ref)},{"status","UNSUPPORTED"},{"message","non-reverting policy has unexpected active ownership"}});
                        node.ok=false;continue;
                    }
                    if(enrollment==RollbackEnrollment::Unsupported&&journal->activeRecords(ref).empty()) {
                        results.push_back({{"policy",formatPolicyRef(ref)},{"status","NOTHING_TO_RELEASE"}});continue;
                    }
                    if(journal->activeRecords(ref).empty()&&ref.moduleName=="FIREWALL"&&ref.submoduleName=="HostFiltering") {
                        std::string detail;
                        const bool absent=fic::firewall::FirewallBackend(executables).provePolicyAbsent(ref.policyName,detail);
                        results.push_back({{"policy",formatPolicyRef(ref)},{"status",absent?"NOTHING_TO_RELEASE":"FAILED"},{"message",detail}});
                        node.ok&=absent;continue;
                    }
                    if(journal->activeRecords(ref).empty()&&ref.moduleName=="IDENTITY_ACCESS"&&ref.submoduleName=="SSSD") {
                        bool absent=false;std::string detail;
                        if(!deps.sssdOptions||!fic::identity::sssd::proveManagedSnippetAbsent(deps.sssdOptions().configuration,absent,detail)) {
                            results.push_back({{"policy",formatPolicyRef(ref)},{"status","FAILED"},{"message",detail}});
                            node.ok=false;continue;
                        }
                        if(absent){results.push_back({{"policy",formatPolicyRef(ref)},{"status","NOTHING_TO_RELEASE"}});continue;}
                    }
                    // Preserve ordinary disable semantics while making bulk
                    // no-owner SYSCTL reports account for the artifact itself,
                    // including an empty/header-only orphan.
                    if(ref.moduleName=="SYSCTL"&&journal->activeRecords(ref).empty()) {
                        std::string detail;
                        const auto proof=inspectUnrecordedResource(ref,deps,*journal,detail,ResourceInspectionPhase::UninstallFinal);
                        if(proof!=UnrecordedResourceState::Continue) {
                            const bool absent=proof==UnrecordedResourceState::ProvenEmpty;
                            results.push_back({{"policy",formatPolicyRef(ref)},{"status",absent?"NOTHING_TO_RELEASE":"FAILED"},{"message",detail}});
                            node.ok&=absent;continue;
                        }
                    }
                    const auto report=rollbackPolicyBeforeDisable(ref,resourceHint(*registry.findPolicy(ref)),deps);
                    const bool optionalResource=ref.moduleName=="SYSCTL"||
                        (ref.moduleName=="DAC"&&ref.submoduleName=="SudoEdit")||
                        (ref.moduleName=="NET"&&ref.submoduleName=="SshEdit");
                    results.push_back({{"policy",formatPolicyRef(ref)},{"status",optionalResource&&report.status==RollbackStatus::NothingToDo?
                        "NOTHING_TO_RELEASE":rollbackStatusToString(report.status)},{"message",report.message}});
                    for(const auto& outcome:report.outcomes)
                        results.push_back({{"policy",formatPolicyRef(ref)},{"mutation_id",outcome.id},
                            {"resource",outcome.resource},{"status",rollbackStatusToString(outcome.status)},{"message",outcome.message}});
                    node.ok&=report.rollbackCompleted();
                }
            }
            results.push_back({{"resource_group",name},{"status",node.ok?"RELEASED":"FAILED"},{"message",error}});
            if(node.ok)++releasedGroups;else ++failedGroups;
            overall&=node.ok;
    }
    for(const auto& record:journal->records())if(record.isActive()) {
        overall=false;results.push_back({{"policy",formatPolicyRef(record.policy)},{"status","ACTIVE_RECORD_REMAINS"},{"mutation_id",record.id}});
    }
    std::size_t finalProofFailures=0;
    for(const auto& proof:inspectReleasedOptionalResources(deps,*journal)) {
        // Original per-owner failures/active-record diagnostics remain intact.
        if(proof.state==UnrecordedResourceState::Continue)continue;
        const bool proven=proof.state==UnrecordedResourceState::ProvenEmpty;
        if(!proven){overall=false;++finalProofFailures;}
        results.push_back({{"domain",proof.domain},{"phase","FINAL_PHYSICAL_PROOF"},
            {"status",proven?"RELEASED":"FAILED"},{"message",proof.detail}});
    }
    return json{{"ok",overall},{"message",overall?"FIC ownership release completed":"FIC ownership release incomplete; independent resources attempted"},
        {"summary",{{"groups",nodes.size()},{"released",releasedGroups},{"failed",failedGroups},{"blocked",blockedGroups},
            {"final_physical_failed",finalProofFailures}}},{"results",results}};
}
}
