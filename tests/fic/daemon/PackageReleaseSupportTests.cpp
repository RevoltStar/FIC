#include "daemon/PackageReleaseResources.h"
#include "platform/PlatformProfile.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace fic::daemon;
using namespace fic::platform;
namespace {
void require(bool value,const char* why){if(!value)throw std::runtime_error(why);}
PamCapabilityConfig& capability(PlatformProfile& p,PamCapability which){
    for(auto& c:p.pam.capabilities)if(c.capability==which)return c;
    throw std::runtime_error("fixture capability absent");
}
void check(const PlatformProfile& p,PackageReleaseSupport expected,const char* detail=nullptr){
    fic::core::FicProductPaths paths;
    std::string error="stale";
    const auto result=PackageReleaseResources(p,paths).supports(PackageReleaseDomain::PamPassword,error);
    if(result!=expected)throw std::runtime_error("password release support misclassified: expected="+
        std::to_string(static_cast<int>(expected))+" actual="+std::to_string(static_cast<int>(result))+" detail="+error);
    if(detail)require(error.find(detail)!=std::string::npos,"capability error detail was lost");
    if(expected==PackageReleaseSupport::Supported)require(error.empty(),"supported domain retained stale error");
    else require(!error.empty(),"unsupported/error domain lost its diagnostic");
}
}
int main(){try{
    auto native=makeBuildPlatformProfile();
    check(native,native.id=="alt-p11"?PackageReleaseSupport::NotApplicable:PackageReleaseSupport::Supported);
    auto au=native;
    au.id="debian-12";
    capability(au,PamCapability::PasswordQuality).topology=PamTopologyStrategyKind::PamAuthUpdate;
    capability(au,PamCapability::PasswordHistory).topology=PamTopologyStrategyKind::PamAuthUpdate;
    check(au,PackageReleaseSupport::Supported);
    auto alt=au;alt.id="alt-p11";
    auto& q=capability(alt,PamCapability::PasswordQuality);
    q.provider=PamProviderKind::PamPasswdqc;q.topology=PamTopologyStrategyKind::StaticVerifyOnly;
    auto& h=capability(alt,PamCapability::PasswordHistory);
    h.provider=PamProviderKind::PamPwhistory;h.topology=PamTopologyStrategyKind::AltTcbManaged;
    check(alt,PackageReleaseSupport::NotApplicable);
    // Both resolutions fail: the original bool API returned false here and
    // uninstall silently treated it exactly like the legitimate ALT case.
    auto unavailable=au;unavailable.pam.scopes.clear();
    check(unavailable,PackageReleaseSupport::Error,"unavailable");
    for(auto which:{PamCapability::PasswordQuality,PamCapability::PasswordHistory}) {
        auto missing=au;
        auto& caps=missing.pam.capabilities;
        caps.erase(std::remove_if(caps.begin(),caps.end(),[&](const auto& c){return c.capability==which;}),caps.end());
        check(missing,PackageReleaseSupport::Error,"not configured");
        auto empty=au;
        const auto scope=capability(empty,which).scope;
        for(auto& s:empty.pam.scopes)if(s.scope==scope)s.services.clear();
        check(empty,PackageReleaseSupport::Error,"empty scope");
    }
    auto unknown=alt;unknown.id="debian-12";
    check(unknown,PackageReleaseSupport::Error,"requires both");
    auto mixed=au;capability(mixed,PamCapability::PasswordHistory).topology=PamTopologyStrategyKind::StaticVerifyOnly;
    check(mixed,PackageReleaseSupport::Error,"requires both");
    auto brokenAlt=alt;brokenAlt.pam.scopes.clear();
    check(brokenAlt,PackageReleaseSupport::Error,"unavailable");
    std::cout<<"PASS: supported C2, native ALT exclusion, missing capabilities, unavailable/empty scopes and mixed topology fail-closed\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
