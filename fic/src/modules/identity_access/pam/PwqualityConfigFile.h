#ifndef FIC_IDENTITY_ACCESS_PAM_PWQUALITY_CONFIG_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_PWQUALITY_CONFIG_FILE_H

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <string>
#include <vector>

namespace fic::identity::pam {

struct PwqualityEffectiveState {
    int difok = 1;
    int minlen = 8;
    int dcredit = 0;
    int ucredit = 0;
    int lcredit = 0;
    int ocredit = 0;
    int minclass = 0;
    int maxrepeat = 0;
    int maxclassrepeat = 0;
    int maxsequence = 0;
    int gecoscheck = 0;
    int dictcheck = 1;
    int usercheck = 1;
    int usersubstr = 0;
    int enforcing = 1;
    int retry = 1;
    bool enforceForRoot = false;
    bool localUsersOnly = false;
    std::string badwords;
    std::string dictpath;

    bool managedValue(const std::string& option,
                      std::string& value,
                      std::string& error) const;
};

class PwqualityConfigEvaluator {
public:
    static bool evaluateInvocation(
        const std::vector<std::string>& arguments,
        const std::filesystem::path& source,
        std::size_t line,
        const fic::platform::PamProviderConfigTopology& topology,
        PwqualityEffectiveState& state,
        std::string& error);

    static bool evaluateInvocationWithManagedOption(
        const std::vector<std::string>& arguments,
        const std::filesystem::path& source,
        std::size_t line,
        const fic::platform::PamProviderConfigTopology& topology,
        const std::string& option,
        const std::string& expectedValue,
        PwqualityEffectiveState& state,
        std::string& error);

    static bool evaluateInvocationWithManagedFlag(
        const std::vector<std::string>& arguments,
        const std::filesystem::path& source,
        std::size_t line,
        const fic::platform::PamProviderConfigTopology& topology,
        const std::string& flag,
        bool expectedEnabled,
        PwqualityEffectiveState& state,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PWQUALITY_CONFIG_FILE_H
