#include "daemon/PackageReleaseResources.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

namespace fic::daemon {
PackageReleaseSupport PackageReleaseResources::supports(
    PackageReleaseDomain domain, std::string& detail) const {
    using namespace fic::platform;
    using Support=PackageReleaseSupport;
    detail.clear();
    if(domain==PackageReleaseDomain::AltHistoryTopology||domain==PackageReleaseDomain::AltFaillockTopology) {
        if(platform_.id=="alt-p11")return Support::Supported;
        detail="ALT topology release requires the ALT p11 platform";
        return Support::NotApplicable;
    }
    if(domain==PackageReleaseDomain::DisplayManager||domain==PackageReleaseDomain::Desktop||domain==PackageReleaseDomain::PamProvider)
        return Support::Supported;
    if(domain!=PackageReleaseDomain::PamPassword) {
        detail="unknown package release domain";
        return Support::Error;
    }
    const PamCapabilityConfig *quality=nullptr,*history=nullptr;
    const std::vector<std::string> *qualityServices=nullptr,*historyServices=nullptr;
    if(!fic::identity::pam::resolveCapability(platform_.pam,PamCapability::PasswordQuality,
            quality,qualityServices,detail)) {
        detail="PAM password quality capability resolution failed: "+detail;
        return Support::Error;
    }
    if(!fic::identity::pam::resolveCapability(platform_.pam,PamCapability::PasswordHistory,
            history,historyServices,detail)) {
        detail="PAM password history capability resolution failed: "+detail;
        return Support::Error;
    }
    if(quality->topology==PamTopologyStrategyKind::PamAuthUpdate &&
       history->topology==PamTopologyStrategyKind::PamAuthUpdate)
        return Support::Supported;
    // Only the proven native ALT pair excludes the C2 pam-auth-update domain.
    // Missing capabilities/scopes and unexpected mixed topologies are errors.
    if(platform_.id=="alt-p11" && quality->provider==PamProviderKind::PamPasswdqc &&
       quality->topology==PamTopologyStrategyKind::StaticVerifyOnly &&
       history->provider==PamProviderKind::PamPwhistory &&
       history->topology==PamTopologyStrategyKind::AltTcbManaged) {
        detail="ALT p11 native password topology has no C2 pam-auth-update domain";
        return Support::NotApplicable;
    }
    detail="PAM password release requires both pam-auth-update capabilities or the native ALT p11 pair";
    return Support::Error;
}
}
