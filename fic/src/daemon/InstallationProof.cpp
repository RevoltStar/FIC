#include "daemon/InstallationProof.h"
#include "daemon/PackagePamHooks.h"
#include "daemon/PackageStateStore.h"
#include "daemon/PackageWriterProcesses.h"
#include "incident/IncidentStateStore.h"
#include "rollback/MutationJournal.h"
#include "modules/identity_access/pam/PamPasswordPackageRelease.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include <fic/core/config/ConfigSchemaManager.h>
#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>
namespace fic::daemon {
bool checkPackagePasswordTopology(const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,std::string& error) {
    const auto* capability=fic::identity::pam::capabilityConfig(platform.pam,
        fic::platform::PamCapability::PasswordQuality);
    if(!capability||capability->topology!=fic::platform::PamTopologyStrategyKind::PamAuthUpdate)return true;
    fic::rollback::MutationJournal journal(fic::core::FicRuntimePaths::get().mutationJournalFile);
    if(!journal.validatePersistentStateReadOnly(error))return false;
    fic::identity::pam::PamPasswordPackageRelease::Report report;
    return fic::identity::pam::PamPasswordPackageRelease(journal,executables,{}).run(
        fic::identity::pam::PamPasswordPackageRelease::Mode::Preflight,report,error);
}
bool checkPackagePersistentState(std::string& error) {
    const auto& paths=fic::core::FicRuntimePaths::get();
    if(!fic::core::ConfigSchemaManager::verifyConfigs(paths.configDir,error))return false;
    fic::rollback::MutationJournal journal(paths.mutationJournalFile);
    if(!journal.validatePersistentStateReadOnly(error))return false;
    const auto incident=fic::incident::IncidentStateStore().read();
    if(incident.provenance!=fic::incident::IncidentStateStore::Provenance::Proven||!incident.provenState) {
        error="incident infrastructure state is unproven: "+incident.detail;return false;
    }
    return true;
}
bool completePackageInstallation(const DaemonInstanceLock& guard,const fic::platform::PlatformProfile& platform,std::string& error) {
    if(!guard.heldByCurrentProcess()||fic::core::readPackageState().state!=fic::core::PackageState::Installing) {
        error="installation proof requires daemon.lock and INSTALLING";return false;
    }
    if(!checkPackagePersistentState(error)||!PackagePamHooks(platform).proveAttached(error))return false;
    const fic::platform::PlatformExecutableResolver executables(platform.executables);
    if(!checkPackagePasswordTopology(platform,executables,error))return false;
    // Fixed readonly device-schema probe; no dependency on a running device
    // daemon or a second policy engine. Root-controlled executable proof is
    // the same bootstrap trust boundary as package infrastructure operations.
    const auto& paths=fic::core::FicRuntimePaths::get();
    const auto executable=paths.privateBinDir/"fic-dick";
    LegacyWriterImage image;
    if(!captureLegacyWriterImage(executable,image,error))return false;
    ProcessOptions options;options.timeout=std::chrono::seconds(30);options.maxOutputBytes=65536;
    options.clearEnvironment=true;options.environment={{"LANG","C"},{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
    const auto result=ProcessExecutor::execute(executable,{"--maintenance","check-db"},options);
    if(!result.success()){error="device database schema proof failed: "+result.error+" "+result.standardError;return false;}
    // Repeat persistent proofs after the external check. Completion only
    // authorizes later normal startup; no service is started under the lock.
    const auto incident=fic::incident::IncidentStateStore().read();
    if(!incident.provenState||!AtomicFileWriter::ensureTargetDurableIfCurrentState(paths.lockStatusFile.string(),*incident.provenState,&error))return false;
    return checkPackagePersistentState(error)&&PackagePamHooks(platform).proveAttached(error)&&
        checkPackagePasswordTopology(platform,executables,error)&&
        PackageStateStore().completeInstallation(guard,error);
}
}
