#include "modules/identity_access/pam/PamProviderCatalog.h"

#include "modules/identity_access/pam/PamOptionValueCodec.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <algorithm>

namespace fic::identity::pam {
namespace {

using Feature = fic::platform::PamPolicyFeature;
using Provider = fic::platform::PamProviderKind;
using Capability = fic::platform::PamCapability;

} // namespace

const PamProviderPolicyBinding* pamProviderPolicyBinding(
    Provider provider,
    Feature feature)
{
    const auto& descriptor = pamProviderDescriptor(provider);
    const auto found = std::find_if(
        descriptor.policies.begin(), descriptor.policies.end(),
        [feature](const auto& candidate) {
            return candidate.feature == feature;
        });
    return found == descriptor.policies.end() ? nullptr : &*found;
}

std::optional<Provider> pamProviderForModule(
    Capability capability,
    const std::string& moduleName,
    bool hasUnixRememberArgument)
{
    const auto& values = pamProviderDescriptors();
    const auto found = std::find_if(
        values.begin(), values.end(),
        [&](const auto& candidate) {
            if (candidate.capability != capability ||
                candidate.moduleName != moduleName) {
                return false;
            }
            return candidate.kind != Provider::PamUnixHistory ||
                hasUnixRememberArgument;
        });
    if (found == values.end()) {
        return std::nullopt;
    }
    return found->kind;
}

Capability pamPolicyCapability(Feature feature)
{
    switch (feature) {
    case Feature::PasswordHistoryDepth:
    case Feature::PasswordHistoryEnforceForRoot:
        return Capability::PasswordHistory;
    case Feature::FailedAuthenticationAttempts:
    case Feature::FailedAuthenticationCountingPeriod:
    case Feature::FailedAuthenticationEnforceForRoot:
    case Feature::FailedAuthenticationUnlockTime:
        return Capability::AuthenticationLockout;
    default:
        return Capability::PasswordQuality;
    }
}

fic::platform::PamPolicySupport pamPolicySupport(
    const fic::platform::PamPlatformConfig& platform,
    Feature feature)
{
    const auto* capability = capabilityConfig(
        platform, pamPolicyCapability(feature));
    if (capability == nullptr ||
        pamProviderPolicyBinding(capability->provider, feature) == nullptr) {
        return fic::platform::PamPolicySupport::Unsupported;
    }
    if (capability->topology ==
            fic::platform::PamTopologyStrategyKind::ExternalOptIn ||
        capability->topology ==
            fic::platform::PamTopologyStrategyKind::AltTcbManaged) {
        return fic::platform::PamPolicySupport::RequiresTopologyActivation;
    }
    return fic::platform::PamPolicySupport::Supported;
}

bool encodePamNativeValue(PamNativeValueEncoding encoding,
                          const std::string& logical,
                          std::string& native,
                          std::string& error)
{
    switch (encoding) {
    case PamNativeValueEncoding::Direct:
        if (logical.empty()) {
            error = "PAM native value must not be empty";
            return false;
        }
        native = logical;
        error.clear();
        return true;
    case PamNativeValueEncoding::YesNoInteger:
        return PamOptionValueCodec::encode(
            PamOptionValueEncoding::YesNoInteger, logical, native, error);
    case PamNativeValueEncoding::MinimumCredit:
        return PamOptionValueCodec::encode(
            PamOptionValueEncoding::MinimumCredit, logical, native, error);
    case PamNativeValueEncoding::PasswdqcEnforceForRoot:
        if (logical == "yes") {
            native = "everyone";
        } else if (logical == "no") {
            native = "users";
        } else {
            error = "expected yes or no";
            return false;
        }
        error.clear();
        return true;
    }
    error = "unsupported PAM native value encoding";
    return false;
}

bool decodePamNativeValue(PamNativeValueEncoding encoding,
                          const std::string& native,
                          std::string& logical,
                          std::string& error)
{
    switch (encoding) {
    case PamNativeValueEncoding::Direct:
        if (native.empty()) {
            error = "PAM native value must not be empty";
            return false;
        }
        logical = native;
        error.clear();
        return true;
    case PamNativeValueEncoding::YesNoInteger:
        return PamOptionValueCodec::decode(
            PamOptionValueEncoding::YesNoInteger, native, logical, error);
    case PamNativeValueEncoding::MinimumCredit:
        return PamOptionValueCodec::decode(
            PamOptionValueEncoding::MinimumCredit, native, logical, error);
    case PamNativeValueEncoding::PasswdqcEnforceForRoot:
        if (native == "everyone") {
            logical = "yes";
        } else if (native == "users") {
            logical = "no";
        } else {
            error = "passwdqc enforce value has no exact root-enforcement mapping";
            return false;
        }
        error.clear();
        return true;
    }
    error = "unsupported PAM native value encoding";
    return false;
}

} // namespace fic::identity::pam
