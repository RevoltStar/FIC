#include "modules/identity_access/pam/PamProviderConfigFile.h"

#include "modules/identity_access/pam/PasswdqcConfigFile.h"

#include <utility>

namespace fic::identity::pam {
namespace {

PamOptionKeyMatchMode keyMatchMode(const PamProviderDescriptor& provider) {
    return provider.semanticBackend == PamProviderSemanticBackendKind::Pwquality
        ? PamOptionKeyMatchMode::AsciiCaseInsensitive
        : PamOptionKeyMatchMode::CaseSensitive;
}

bool isPasswdqc(const PamProviderDescriptor& provider) {
    return provider.semanticBackend == PamProviderSemanticBackendKind::Passwdqc;
}

} // namespace

bool PamProviderConfigFile::hasExpectedState(
    const PamProviderDescriptor& provider,
    const PamProviderPolicyBinding& binding,
    const std::filesystem::path& path,
    const std::string& expectedValue,
    bool expectedFlagEnabled,
    std::string& error) {
    if (isPasswdqc(provider)) {
        return PasswdqcConfigFile::hasOnlyValue(
            path, binding.option, expectedValue, error);
    }
    const auto matchMode = keyMatchMode(provider);
    return binding.syntax == PamNativeOptionSyntax::Assignment
        ? PamOptionFile::hasOnlyValue(
              path, binding.option, expectedValue, error, matchMode)
        : PamOptionFile::hasFlag(
              path, binding.option, expectedFlagEnabled, error, matchMode);
}

bool PamProviderConfigFile::setExpectedState(
    const PamProviderDescriptor& provider,
    const PamProviderPolicyBinding& binding,
    const std::filesystem::path& path,
    const std::string& expectedValue,
    bool expectedFlagEnabled,
    std::string& error,
    PamOptionFile::Writer writer) {
    if (isPasswdqc(provider)) {
        return PasswdqcConfigFile::setValue(
            path, binding.option, expectedValue, error, std::move(writer));
    }
    const auto matchMode = keyMatchMode(provider);
    return binding.syntax == PamNativeOptionSyntax::Assignment
        ? PamOptionFile::setValue(
              path, binding.option, expectedValue, error,
              std::move(writer), matchMode)
        : PamOptionFile::setFlag(
              path, binding.option, expectedFlagEnabled, error,
              std::move(writer), matchMode);
}

bool PamProviderConfigFile::verifyNoActiveDirectives(
    const PamProviderDescriptor& provider,
    const std::filesystem::path& path,
    const std::vector<std::string>& directives,
    std::string& error) {
    return PamOptionFile::verifyNoActiveDirectives(
        path, directives, error, keyMatchMode(provider));
}

} // namespace fic::identity::pam
