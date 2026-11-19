#include "daemon/PackageReleaseResources.h"
#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include "modules/oss/display_manager/DisplayManagerConfigTransaction.h"
#include "rollback/ScopeTransition.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamTopologyManagerFactory.h"
#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "rollback/PamRollback.h"
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
    case PackageReleaseDomain::AltHistoryTopology:
    case PackageReleaseDomain::AltFaillockTopology: {
        using namespace fic::identity::pam;
        using namespace fic::platform;
        using namespace fic::rollback;
        const auto kind = domain == PackageReleaseDomain::AltHistoryTopology
            ? PamCapability::PasswordHistory : PamCapability::AuthenticationLockout;
        const std::string name = pamCapabilityActivationPolicyName(kind);
        const auto records = journal.activeRecords({"IDENTITY_ACCESS", "PAM", name});
        const PamCapabilityConfig* capability = nullptr;
        const std::vector<std::string>* services = nullptr;
        if (!resolveCapability(platform_.pam, kind, capability, services, error))
            return false;
        PamRollbackOptions options;
        options.platform = platform_.pam;
        options.managerFactory = [&](const auto& config, const auto& roots, auto& detail) {
            return createPamTopologyManager(platform_.pam, config, roots, executables_, detail);
        };
        auto backend = options.managerFactory(*capability, *services, error);
        if (!backend) return false;

        PamTopologyStatus state;
        if (proof || records.empty()) {
            if (!backend->inspectForRelease(state, error)) return false;
            if (state.state != PamTopologyState::Disabled) {
                error = "ALT PAM topology remains present without release proof";
                return false;
            }
            return true;
        }

        const auto& record = records.front();
        const auto* undo = std::get_if<UndoDisablePamCapability>(&record.undo.payload);
        if (records.size() != 1 || !record.id || record.resource != "capability/" + name ||
            record.undo.backend != MutationBackend::Pam || !undo ||
            undo->capability != name || !undo->activationIdentifiers.empty() ||
            (undo->topology != PamTopologyKind::AltTcbManaged &&
             undo->topology != PamTopologyKind::AltTcbJournalBoundV1)) {
            error = "ALT PAM package release has ambiguous journal provenance";
            return false;
        }
        if (preview) {
            const bool bound = undo->topology == PamTopologyKind::AltTcbJournalBoundV1;
            // A partial v1 publication is deliberately not a complete
            // inspection proof. The rollback backend validates every present
            // artifact under its write lock before compensating any target.
            if (!backend->inspectForRelease(state, error)) return bound;
            if (state.state == PamTopologyState::Disabled ||
                (state.state == PamTopologyState::Enabled && state.manageable &&
                 (bound ? state.ownershipMutationId == record.id : !state.ownershipMutationId)))
                return true;
            error = "ALT PAM package release physical ownership differs from the journal";
            return false;
        }
        const auto released = undoPamCapability(options, record.id, *undo);
        error = released.message;
        // The subsequent policy rollback retires the record after proving
        // absence again, preserving the existing uninstall ordering.
        return released.state == PamRollbackState::Released ||
               released.state == PamRollbackState::AlreadyReleased;
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
