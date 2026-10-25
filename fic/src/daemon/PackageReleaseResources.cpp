#include "daemon/PackageReleaseResources.h"
#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include "modules/oss/display_manager/DisplayManagerConfigTransaction.h"
#include "rollback/ScopeTransition.h"
#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include <grp.h>
namespace fic::daemon {
bool PackageReleaseResources::preflight(PackageReleaseDomain domain,fic::rollback::MutationJournal& journal,
    PackageResourceReleaseReport& report,std::string& error) const {
    return run(domain,journal,Action::Preflight,report,error);
}
bool PackageReleaseResources::release(const DaemonInstanceLock& guard,PackageReleaseDomain domain,
    fic::rollback::MutationJournal& journal,PackageResourceReleaseReport& report,std::string& error) const {
    if(!guard.heldByCurrentProcess()){error="resource release requires daemon admission";return false;}
    return run(domain,journal,Action::Release,report,error);
}
bool PackageReleaseResources::proveReleased(PackageReleaseDomain domain,fic::rollback::MutationJournal& journal,std::string& error) const {
    PackageResourceReleaseReport report;return run(domain,journal,Action::Proof,report,error);
}
bool PackageReleaseResources::run(PackageReleaseDomain domain,fic::rollback::MutationJournal& journal,
    Action action,PackageResourceReleaseReport& report,std::string& error) const {
    const bool preview=action==Action::Preflight,proof=action==Action::Proof;
    report={};
    if(supports(domain,error)!=PackageReleaseSupport::Supported)return false;
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
        if(preview||proof) {
            if(!backend.inspectReadOnly(state,error))return false;
            if(proof&&state!=AltPamPasswordHistoryTopologyState::Disabled){error="ALT password history remains enabled";return false;}
            return true;
        }
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
        if(preview||proof) {
            if(!backend.inspectReadOnly(state,error))return false;
            if(proof&&state!=AltPamFaillockTopologyState::Disabled){error="ALT faillock remains enabled";return false;}
            return true;
        }
        if(!backend.disable(error)||!backend.status(state,error)||!backend.confirmDurable(error))return false;
        if(state!=AltPamFaillockTopologyState::Disabled){error="ALT faillock remains enabled";return false;}
        return true;
    }
    case PackageReleaseDomain::DisplayManager: {
        DisplayManagerConfigTransaction backend(executables_,platform_.displayManager);
        if(proof) {
            for(const auto* dm:{"SDDM","GDM","LIGHTDM"})if(!backend.verifyReleased(dm,journal,error))return false;
            return true;
        }
        return backend.releaseAll(journal,error,true) && (preview ||
            (fic::rollback::ScopeTransition(journal,fic::rollback::ScopeTransition::Domain::DisplayManager)
                .invalidate("DM package release",error)&&backend.releaseAll(journal,error)));
    }
    case PackageReleaseDomain::Desktop: {
        DesktopGlobalConfigReconciler backend({std::make_shared<GnomeSystemBackend>(executables_),
            std::make_shared<FlySystemBackend>()},&journal);
        if(proof)for(const auto& record:journal.records())if(record.isActive()&&record.undo.backend==fic::rollback::MutationBackend::Desktop) {
            error="DE package release retains active ownership";return false;
        }
        return backend.releaseAll(journal,error,preview||proof);
    }
    case PackageReleaseDomain::PamProvider: {
        using fic::identity::pam::PamProviderPackageRelease;
        PamProviderPackageRelease::Options options;
        options.lockFilePath=paths_.runtimeDir/"pam-provider-managed.lock";
        options.lockDebugLogPath=paths_.lockDebugLogFile;
        PamProviderPackageRelease backend(journal,platform_.pam,options);
        return backend.run(proof?PamProviderPackageRelease::Mode::ProveReleased:preview?PamProviderPackageRelease::Mode::Preflight:
            PamProviderPackageRelease::Mode::Release,report.provider,error);
    }
    case PackageReleaseDomain::PamPassword: {
        using fic::identity::pam::PamPasswordPackageRelease;
        PamPasswordPackageRelease::Options options;
        options.lockFilePath=paths_.runtimeDir/"pam-password-package-release.lock";
        options.lockDebugLogPath=paths_.lockDebugLogFile;
        PamPasswordPackageRelease backend(journal,executables_,options);
        return backend.run(proof?PamPasswordPackageRelease::Mode::ProveReleased:preview?PamPasswordPackageRelease::Mode::Preflight:
            PamPasswordPackageRelease::Mode::Release,report.password,error);
    }
    }
    error="unknown package release domain";return false;
}
}
