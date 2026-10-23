#include "daemon/PackageReleaseResources.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include "modules/oss/display_manager/DisplayManagerConfigTransaction.h"
#include "rollback/ScopeTransition.h"
#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include <grp.h>
namespace fic::daemon {
bool PackageReleaseResources::supports(PackageReleaseDomain domain,std::string& error) const {
    if(domain==PackageReleaseDomain::AltHistoryTopology||domain==PackageReleaseDomain::AltFaillockTopology) {
        if(platform_.id!="alt-p11"){error="ALT topology release requires the ALT p11 platform";return false;}
        error.clear();return true;
    }
    if(domain==PackageReleaseDomain::DisplayManager||domain==PackageReleaseDomain::Desktop||domain==PackageReleaseDomain::PamProvider) {
        error.clear();return true;
    }
    if(domain!=PackageReleaseDomain::PamPassword){error="unknown package release domain";return false;}
    const fic::platform::PamCapabilityConfig *quality=nullptr,*history=nullptr;
    const std::vector<std::string> *qualityServices=nullptr,*historyServices=nullptr;
    const bool qualityResolved=fic::identity::pam::resolveCapability(platform_.pam,
        fic::platform::PamCapability::PasswordQuality,quality,qualityServices,error);
    const bool historyResolved=fic::identity::pam::resolveCapability(platform_.pam,
        fic::platform::PamCapability::PasswordHistory,history,historyServices,error);
    if((qualityResolved&&quality->topology==fic::platform::PamTopologyStrategyKind::PamAuthUpdate)||
       (historyResolved&&history->topology==fic::platform::PamTopologyStrategyKind::PamAuthUpdate)) {
        error.clear();return true;
    }
    error="FIC package password release requires a pam-auth-update password topology; this platform does not provide one";
    return false;
}
bool PackageReleaseResources::preflight(PackageReleaseDomain domain,fic::rollback::MutationJournal& journal,
    PackageResourceReleaseReport& report,std::string& error) const {
    return run(domain,journal,true,report,error);
}
bool PackageReleaseResources::release(const DaemonInstanceLock& guard,PackageReleaseDomain domain,
    fic::rollback::MutationJournal& journal,PackageResourceReleaseReport& report,std::string& error) const {
    if(!guard.heldByCurrentProcess()){error="resource release requires daemon admission";return false;}
    return run(domain,journal,false,report,error);
}
bool PackageReleaseResources::run(PackageReleaseDomain domain,fic::rollback::MutationJournal& journal,
    bool preview,PackageResourceReleaseReport& report,std::string& error) const {
    report={};
    if(!supports(domain,error))return false;
    switch(domain) {
    case PackageReleaseDomain::AltHistoryTopology: {
        using namespace fic::identity::pam;
        const auto* shadow=::getgrnam("shadow");
        if(!shadow){error="ALT pam_pwhistory requires the shadow group";return false;}
        AltPamPasswordHistoryTopologyOptions options;
        options.lockFilePath=paths_.runtimeDir/"pam-alt-pwhistory-topology.lock";
        options.lockDebugLogPath=paths_.lockDebugLogFile;
        options.storageGroup=shadow->gr_gid;
        AltPamPasswordHistoryTopologyManager backend(platform_.pam,std::move(options));
        AltPamPasswordHistoryTopologyState state;
        if(preview)return backend.inspectReadOnly(state,error);
        if(!backend.disable(error)||!backend.status(state,error)||!backend.confirmDurable(error))return false;
        if(state!=AltPamPasswordHistoryTopologyState::Disabled){error="ALT password history remains enabled";return false;}
        return true;
    }
    case PackageReleaseDomain::AltFaillockTopology: {
        using namespace fic::identity::pam;
        AltPamFaillockTopologyOptions options;
        options.lockFilePath=paths_.runtimeDir/"pam-alt-faillock-topology.lock";
        options.lockDebugLogPath=paths_.lockDebugLogFile;
        AltPamFaillockTopologyManager backend(platform_.pam,std::move(options));
        AltPamFaillockTopologyState state;
        if(preview)return backend.inspectReadOnly(state,error);
        if(!backend.disable(error)||!backend.status(state,error)||!backend.confirmDurable(error))return false;
        if(state!=AltPamFaillockTopologyState::Disabled){error="ALT faillock remains enabled";return false;}
        return true;
    }
    case PackageReleaseDomain::DisplayManager: {
        DisplayManagerConfigTransaction backend(executables_,platform_.displayManager);
        return backend.releaseAll(journal,error,true) && (preview ||
            (fic::rollback::ScopeTransition(journal,fic::rollback::ScopeTransition::Domain::DisplayManager)
                .invalidate("DM package release",error)&&backend.releaseAll(journal,error)));
    }
    case PackageReleaseDomain::Desktop: {
        DesktopGlobalConfigReconciler backend({std::make_shared<GnomeSystemBackend>(executables_),
            std::make_shared<FlySystemBackend>()},&journal);
        return backend.releaseAll(journal,error,preview);
    }
    case PackageReleaseDomain::PamProvider: {
        using fic::identity::pam::PamProviderPackageRelease;
        PamProviderPackageRelease::Options options;
        options.lockFilePath=paths_.runtimeDir/"pam-provider-managed.lock";
        options.lockDebugLogPath=paths_.lockDebugLogFile;
        PamProviderPackageRelease backend(journal,platform_.pam,options);
        return backend.run(preview?PamProviderPackageRelease::Mode::Preflight:
            PamProviderPackageRelease::Mode::Release,report.provider,error);
    }
    case PackageReleaseDomain::PamPassword: {
        using fic::identity::pam::PamPasswordPackageRelease;
        PamPasswordPackageRelease::Options options;
        options.lockFilePath=paths_.runtimeDir/"pam-password-package-release.lock";
        options.lockDebugLogPath=paths_.lockDebugLogFile;
        PamPasswordPackageRelease backend(journal,executables_,options);
        return backend.run(preview?PamPasswordPackageRelease::Mode::Preflight:
            PamPasswordPackageRelease::Mode::Release,report.password,error);
    }
    }
    error="unknown package release domain";return false;
}
}
