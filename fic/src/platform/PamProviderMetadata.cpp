#include "modules/identity_access/pam/PamProviderCatalog.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace fic::identity::pam {
namespace {

using Capability = fic::platform::PamCapability;
using Feature = fic::platform::PamPolicyFeature;
using Grammar = fic::platform::PamConfigGrammar;
using Semantic = PamProviderSemanticBackendKind;

fic::platform::PamProviderConfigTopology primaryConfig(
    const std::filesystem::path& path,
    std::vector<std::filesystem::path> dropIns = {},
    fic::platform::PamExplicitConfigSemantics explicitConfig =
        fic::platform::PamExplicitConfigSemantics::Unsupported)
{
    fic::platform::PamProviderConfigTopology topology;
    topology.primaryPath = path;
    topology.dropInDirectories = std::move(dropIns);
    topology.explicitConfig = explicitConfig;
    return topology;
}
using Provider = fic::platform::PamProviderKind;

PamProviderPolicyBinding assignment(
    Feature feature,
    const char* option,
    PamNativeValueEncoding encoding = PamNativeValueEncoding::Direct)
{
    return {feature, option, PamNativeOptionSyntax::Assignment, encoding, {}};
}

PamProviderPolicyBinding flag(
    Feature feature,
    const char* option,
    std::vector<std::string> conflicts = {})
{
    return {feature, option, PamNativeOptionSyntax::Flag,
            PamNativeValueEncoding::Direct, std::move(conflicts)};
}

} // namespace

const std::vector<PamProviderDescriptor>& pamProviderDescriptors()
{
    static const std::vector<PamProviderDescriptor> values{
        {Provider::PamFaillock, Capability::AuthenticationLockout,
         "pam_faillock", "pam_faillock.so", "conf",
         PamExternalConfigMode::Optional,
         primaryConfig(
             "/etc/security/faillock.conf", {},
             fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology),
         Grammar::KeyValue, Semantic::Generic,
         {assignment(Feature::FailedAuthenticationAttempts, "deny"),
          assignment(Feature::FailedAuthenticationCountingPeriod,
                     "fail_interval"),
          flag(Feature::FailedAuthenticationEnforceForRoot,
               "even_deny_root", {"root_unlock_time"}),
          assignment(Feature::FailedAuthenticationUnlockTime, "unlock_time")}},
        {Provider::PamPwquality, Capability::PasswordQuality,
         "pam_pwquality", "pam_pwquality.so", "",
         PamExternalConfigMode::None,
         primaryConfig(
             "/etc/security/pwquality.conf",
             {"/etc/security/pwquality.conf.d"}),
         Grammar::KeyValue, Semantic::Pwquality,
         {assignment(Feature::PasswordMinLength, "minlen"),
          assignment(Feature::PasswordMinClasses, "minclass"),
          assignment(Feature::PasswordCheckUsername, "usercheck",
                     PamNativeValueEncoding::YesNoInteger),
          assignment(Feature::PasswordCheckGecos, "gecoscheck",
                     PamNativeValueEncoding::YesNoInteger),
          flag(Feature::PasswordQualityEnforceForRoot, "enforce_for_root"),
          assignment(Feature::PasswordMinChangedCharacters, "difok"),
          assignment(Feature::PasswordMinLowercase, "lcredit",
                     PamNativeValueEncoding::MinimumCredit),
          assignment(Feature::PasswordMinUppercase, "ucredit",
                     PamNativeValueEncoding::MinimumCredit),
          assignment(Feature::PasswordMinDigits, "dcredit",
                     PamNativeValueEncoding::MinimumCredit),
          assignment(Feature::PasswordMinOther, "ocredit",
                     PamNativeValueEncoding::MinimumCredit)}},
        {Provider::PamPasswdqc, Capability::PasswordQuality,
         "pam_passwdqc", "pam_passwdqc.so", "config",
         PamExternalConfigMode::Required, {}, Grammar::Passwdqc,
         Semantic::Passwdqc,
         {assignment(Feature::PasswordQualityEnforceForRoot, "enforce",
                     PamNativeValueEncoding::PasswdqcEnforceForRoot),
          assignment(Feature::PasswdqcStrengthThresholds, "min"),
          assignment(Feature::PasswdqcPassphraseWords, "passphrase"),
          assignment(Feature::PasswdqcMatchLength, "match"),
          assignment(Feature::PasswdqcSimilarPassword, "similar"),
          assignment(Feature::PasswdqcRetryCount, "retry")}},
        {Provider::PamPwhistory, Capability::PasswordHistory,
         "pam_pwhistory", "pam_pwhistory.so", "conf",
         PamExternalConfigMode::Optional,
         primaryConfig(
             "/etc/security/pwhistory.conf", {},
             fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology),
         Grammar::KeyValue, Semantic::Generic,
         {assignment(Feature::PasswordHistoryDepth, "remember"),
          flag(Feature::PasswordHistoryEnforceForRoot, "enforce_for_root")}},
        {Provider::PamTally2, Capability::AuthenticationLockout,
         "pam_tally2", "pam_tally2.so", "",
         PamExternalConfigMode::None, {}, Grammar::KeyValue,
         Semantic::Generic, {}},
        {Provider::PamTally, Capability::AuthenticationLockout,
         "pam_tally", "pam_tally.so", "",
         PamExternalConfigMode::None, {}, Grammar::KeyValue,
         Semantic::Generic, {}},
        {Provider::PamCracklib, Capability::PasswordQuality,
         "pam_cracklib", "pam_cracklib.so", "",
         PamExternalConfigMode::None, {}, Grammar::KeyValue,
         Semantic::Generic, {}},
        {Provider::PamUnixHistory, Capability::PasswordHistory,
         "pam_unix remember", "pam_unix.so", "",
         PamExternalConfigMode::None, {}, Grammar::KeyValue,
         Semantic::Generic, {}}
    };
    return values;
}

const PamProviderDescriptor& pamProviderDescriptor(Provider provider)
{
    const auto& values = pamProviderDescriptors();
    const auto found = std::find_if(
        values.begin(), values.end(), [provider](const auto& candidate) {
            return candidate.kind == provider;
        });
    if (found == values.end()) {
        throw std::logic_error("unknown PAM provider descriptor");
    }
    return *found;
}

} // namespace fic::identity::pam
