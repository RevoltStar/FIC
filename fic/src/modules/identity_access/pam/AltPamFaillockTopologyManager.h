#ifndef FIC_ALT_PAM_FAILLOCK_TOPOLOGY_MANAGER_H
#define FIC_ALT_PAM_FAILLOCK_TOPOLOGY_MANAGER_H

#include "platform/PlatformProfile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <string>

namespace fic::identity::pam {

enum class AltPamFaillockTopologyState {
    Disabled,
    Enabled
};

struct AltPamFaillockTopologyOptions {
    std::filesystem::path lockFilePath;
    std::filesystem::path lockDebugLogPath;
    AtomicWriteOptions writeOptions;
    std::function<bool(const std::string&,
                       const std::string&,
                       const AtomicWriteOptions&,
                       std::string*)> writer;
    std::function<bool(std::string&)> semanticVerifier;
};

class AltPamFaillockTopologyManager {
public:
    inline static constexpr const char* PREAUTH_BEGIN =
        "# BEGIN FIC pam_faillock preauth";
    inline static constexpr const char* PREAUTH_RULE =
        "auth\trequisite\tpam_faillock.so preauth";
    inline static constexpr const char* ORIGINAL_AUTH_PREFIX =
        "# FIC ORIGINAL pam_tcb hex=";
    inline static constexpr const char* PREAUTH_END =
        "# END FIC pam_faillock preauth";
    inline static constexpr const char* AUTHFAIL_BEGIN =
        "# BEGIN FIC pam_faillock authfail";
    inline static constexpr const char* AUTHFAIL_RULE =
        "auth\t[default=die]\tpam_faillock.so authfail";
    inline static constexpr const char* AUTHFAIL_END =
        "# END FIC pam_faillock authfail";
    inline static constexpr const char* ACCOUNT_BEGIN =
        "# BEGIN FIC pam_faillock account";
    inline static constexpr const char* ACCOUNT_RULE =
        "account\trequired\tpam_faillock.so";
    inline static constexpr const char* ACCOUNT_END =
        "# END FIC pam_faillock account";

    AltPamFaillockTopologyManager(
        fic::platform::PamPlatformConfig platformConfig,
        AltPamFaillockTopologyOptions options);

    bool status(AltPamFaillockTopologyState& state, std::string& error);
    bool enable(std::string& error);
    bool disable(std::string& error);

private:
    fic::platform::PamPlatformConfig platformConfig_;
    AltPamFaillockTopologyOptions options_;

    bool verifySemanticEffectiveness(std::string& error) const;
};

std::string altPamFaillockTopologyStateName(
    AltPamFaillockTopologyState state);

} // namespace fic::identity::pam

#endif // FIC_ALT_PAM_FAILLOCK_TOPOLOGY_MANAGER_H
