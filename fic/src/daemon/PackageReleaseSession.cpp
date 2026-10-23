#include "daemon/PackageReleaseSession.h"
#include <array>
#include <unistd.h>
namespace fic::daemon {
namespace {
constexpr std::array<PackageReleaseDomain,4> domains{{PackageReleaseDomain::DisplayManager,
    PackageReleaseDomain::Desktop,PackageReleaseDomain::PamProvider,PackageReleaseDomain::PamPassword}};
constexpr std::array<PackagePhase,4> completed{{PackagePhase::DmReleased,PackagePhase::DeReleased,
    PackagePhase::ProviderReleased,PackagePhase::PasswordReleased}};
bool inspect(PackageLifecycleStore& store,const std::string& id,
    std::optional<PackageLifecycleState>& state,std::string& error) {
    if(!store.inspect(state,error))return false;
    if(!state||state->operationId!=id||state->operation!=PackageOperation::Remove||
       state->phase<PackagePhase::Fencing||state->phase>PackagePhase::PasswordReleased) {
        error="resource release requires matching pending removal, before hook detach";return false;
    }
    return true;
}
bool preview(PackageReleaseResources& resources,fic::rollback::MutationJournal& journal,bool password,bool alt,std::string& error) {
    if(alt)for(const auto domain:{PackageReleaseDomain::AltHistoryTopology,PackageReleaseDomain::AltFaillockTopology}) {
        PackageResourceReleaseReport report;if(!resources.preflight(domain,journal,report,error))return false;
    }
    for(const auto domain:domains) {
        // ALT has no pam-auth-update C2 password package domain. Its password
        // providers are released by the platform provider backend instead.
        if(domain==PackageReleaseDomain::PamPassword&&!password)continue;
        PackageResourceReleaseReport report;if(!resources.preflight(domain,journal,report,error))return false;
    }
    return true;
}
}
bool PackageReleaseSession::preflight(std::string& error) const {
    if(::geteuid()!=0){error="package release preflight requires root";return false;}
    fic::rollback::MutationJournal journal(paths_.mutationJournalFile);
    if(!journal.validatePersistentStateReadOnly(error))return false;
    PackageReleaseResources resources(platform_,paths_);
    const bool password=resources.supports(PackageReleaseDomain::PamPassword,error);
    if(!password&&platform_.id!="alt-p11")return false;
    error.clear();return preview(resources,journal,password,platform_.id=="alt-p11",error);
}
bool PackageReleaseSession::releaseManagedResources(const DaemonInstanceLock& guard,
    const std::string& id,std::string& error) const {
    if(!guard.heldByCurrentProcess()){error="package session requires daemon admission";return false;}
    PackageLifecycleStore store(lifecycle_.fenceFile);std::optional<PackageLifecycleState> state;
    if(!inspect(store,id,state,error))return false;
    PackageUnitMasks masks(lifecycle_.maskDirectory,lifecycle_.systemUnitDirectory);
    std::vector<LegacyWriterImage> images;
    if(!readLegacyWriterInventory(lifecycle_.maskDirectory/id/"writers.json",id,images,error))return false;
    fic::platform::PlatformExecutableResolver executables(platform_.executables);
    PackageWritersQuiescence writers(executables);
    if(!writers.stopAndProve(guard,masks,id,images,
        std::chrono::steady_clock::now()+std::chrono::seconds(30),error))return false;
    if(state->phase==PackagePhase::Fencing) {
        if(!store.advance(guard,*state,PackagePhase::Quiescent,error)||!inspect(store,id,state,error))return false;
    }
    // Fresh witness-aware state is inspected only after admission/quiescence.
    // Missing provenance cannot enter initializeOrLoad's virgin bootstrap path.
    fic::rollback::MutationJournal inspected(paths_.mutationJournalFile);
    if(!inspected.validatePersistentStateReadOnly(error))return false;
    fic::rollback::MutationJournal journal(paths_.mutationJournalFile);
    if(!journal.initializeOrLoad(error))return false;
    PackageReleaseResources resources(platform_,paths_);
    const bool password=resources.supports(PackageReleaseDomain::PamPassword,error);
    if(!password&&platform_.id!="alt-p11")return false;
    error.clear();
    if(!preview(resources,journal,password,platform_.id=="alt-p11",error))return false;
    // Preserve ALT package order: detach password history, then faillock, before
    // releasing managed DM/DE/provider resources. No control-script child is
    // invoked while admission is held. Quiescent is the replay checkpoint if a
    // topology operation crashes; existing managers prove ownership/idempotence.
    if(platform_.id=="alt-p11")for(const auto domain:{PackageReleaseDomain::AltHistoryTopology,PackageReleaseDomain::AltFaillockTopology}) {
        PackageResourceReleaseReport report;
        if(!resources.release(guard,domain,journal,report,error))return false;
    }
    for(std::size_t i=0;i<domains.size();++i) {
        PackageResourceReleaseReport report;
        const bool applicable=domains[i]!=PackageReleaseDomain::PamPassword||password;
        if(applicable&&!resources.release(guard,domains[i],journal,report,error))return false;
        error.clear();
        if(!journal.usable()){error="package release left an indeterminate mutation journal";return false;}
        // Replay already completed domains through their existing idempotent
        // release engines. Crash between physical release and checkpoint cannot
        // skip fresh resource proofs or cause cross-domain compensation.
        if(state->phase<completed[i]) {
            if(!store.advance(guard,*state,completed[i],error)||!inspect(store,id,state,error))return false;
        }
    }
    fic::rollback::MutationJournal finalJournal(paths_.mutationJournalFile);
    return finalJournal.validatePersistentStateReadOnly(error);
}
}
