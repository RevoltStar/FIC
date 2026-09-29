#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_CATALOG_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_CATALOG_H

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fic::identity::pam {

enum class PamNativeOptionSyntax {
    Assignment,
    Flag
};

enum class PamNativeValueEncoding {
    Direct,
    YesNoInteger,
    MinimumCredit,
    PasswdqcEnforceForRoot
};

enum class PamExternalConfigMode {
    None,
    Optional,
    Required
};

enum class PamProviderSemanticBackendKind {
    Generic,
    Pwquality,
    Passwdqc,
    // Step 7D: typed pwhistory config evaluator (first-match
    // pam_modutil_search_key semantics + module argv last-wins). The
    // ModuleArguments capability mode (Debian 12) keeps the specialized
    // pwhistoryArguments backend regardless of this descriptor value.
    Pwhistory
};

struct PamProviderPolicyBinding {
    fic::platform::PamPolicyFeature feature =
        fic::platform::PamPolicyFeature::PasswordMinLength;
    std::string option;
    PamNativeOptionSyntax syntax = PamNativeOptionSyntax::Assignment;
    PamNativeValueEncoding encoding = PamNativeValueEncoding::Direct;
    std::vector<std::string> conflictingOptionsWhenDisabled;
};

struct PamProviderDescriptor {
    fic::platform::PamProviderKind kind =
        fic::platform::PamProviderKind::PamFaillock;
    fic::platform::PamCapability capability =
        fic::platform::PamCapability::AuthenticationLockout;
    const char* name = "";
    const char* moduleName = "";
    const char* externalConfigArgument = "";
    PamExternalConfigMode externalConfigMode = PamExternalConfigMode::None;
    fic::platform::PamProviderConfigTopology defaultConfigTopology;
    fic::platform::PamConfigGrammar grammar =
        fic::platform::PamConfigGrammar::KeyValue;
    PamProviderSemanticBackendKind semanticBackend =
        PamProviderSemanticBackendKind::Generic;
    std::vector<PamProviderPolicyBinding> policies;
};

const PamProviderDescriptor& pamProviderDescriptor(
    fic::platform::PamProviderKind provider);

const std::vector<PamProviderDescriptor>& pamProviderDescriptors();

const PamProviderPolicyBinding* pamProviderPolicyBinding(
    fic::platform::PamProviderKind provider,
    fic::platform::PamPolicyFeature feature);

std::optional<fic::platform::PamProviderKind> pamProviderForModule(
    fic::platform::PamCapability capability,
    const std::string& moduleName,
    bool hasUnixRememberArgument = false);

fic::platform::PamPolicySupport pamPolicySupport(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamPolicyFeature feature);

fic::platform::PamCapability pamPolicyCapability(
    fic::platform::PamPolicyFeature feature);

bool encodePamNativeValue(PamNativeValueEncoding encoding,
                          const std::string& logical,
                          std::string& native,
                          std::string& error);

bool decodePamNativeValue(PamNativeValueEncoding encoding,
                          const std::string& native,
                          std::string& logical,
                          std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_CATALOG_H
