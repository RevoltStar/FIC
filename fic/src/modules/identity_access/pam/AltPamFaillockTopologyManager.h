#ifndef FIC_ALT_PAM_FAILLOCK_TOPOLOGY_MANAGER_H
#define FIC_ALT_PAM_FAILLOCK_TOPOLOGY_MANAGER_H

#include "platform/PlatformProfile.h"
#include "modules/identity_access/pam/PamTopologyManager.h"

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

class AltPamFaillockTopologyManager final : public PamTopologyManager {
public:
    // Preauth strategies keep the original pam_tcb rule shape: the FIC
    // preauth block stores the original rule (hex encoded) and re-adds it as
    // a sufficient authenticator after the preauth rule.
    inline static constexpr const char* PREAUTH_BEGIN =
        "# BEGIN FIC pam_faillock preauth";
    inline static constexpr const char* PREAUTH_RULE_REQUISITE =
        "auth\trequisite\tpam_faillock.so preauth";
    inline static constexpr const char* PREAUTH_RULE_REQUIRED =
        "auth\trequired\tpam_faillock.so preauth";
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
    // authsucc strategy: the original pam_tcb anchor is replaced by a
    // jump-style rule that skips the authfail accounting on success and
    // falls into it on failure; success accounting terminates the block.
    inline static constexpr const char* AUTHSUCC_ANCHOR_BEGIN =
        "# BEGIN FIC pam_faillock authsucc anchor";
    inline static constexpr const char* AUTHSUCC_ANCHOR_RULE_PREFIX =
        "auth\t[success=1 default=bad]\t";
    inline static constexpr const char* AUTHSUCC_ANCHOR_END =
        "# END FIC pam_faillock authsucc anchor";
    inline static constexpr const char* AUTHSUCC_BEGIN =
        "# BEGIN FIC pam_faillock authsucc rule";
    inline static constexpr const char* AUTHSUCC_RULE =
        "auth\t[success=ok default=bad]\tpam_faillock.so authsucc";
    inline static constexpr const char* AUTHSUCC_END =
        "# END FIC pam_faillock authsucc rule";

    AltPamFaillockTopologyManager(
        fic::platform::PamPlatformConfig platformConfig,
        AltPamFaillockTopologyOptions options);

    bool status(AltPamFaillockTopologyState& state, std::string& error);
    bool inspect(PamTopologyStatus& status, std::string& error) override;
    bool canEnable(std::string& error) const override;
    bool enable(std::string& error) override;
    bool disable(std::string& error) override;

    bool canEnableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const override;
    bool enableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) override;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    AltPamFaillockTopologyOptions options_;

    bool status(AltPamFaillockTopologyState& state,
                std::optional<fic::platform::PamFaillockStrategy>& strategy,
                std::string& error);
    bool verifySemanticEffectiveness(std::string& error) const;
};

std::string altPamFaillockTopologyStateName(
    AltPamFaillockTopologyState state);

} // namespace fic::identity::pam

#endif // FIC_ALT_PAM_FAILLOCK_TOPOLOGY_MANAGER_H
