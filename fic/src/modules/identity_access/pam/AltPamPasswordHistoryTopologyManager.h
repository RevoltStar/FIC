#ifndef FIC_ALT_PAM_PASSWORD_HISTORY_TOPOLOGY_MANAGER_H
#define FIC_ALT_PAM_PASSWORD_HISTORY_TOPOLOGY_MANAGER_H

#include "modules/identity_access/pam/PamTopologyManager.h"
#include "platform/PlatformProfile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <string>

#include <sys/types.h>

namespace fic::identity::pam {

enum class AltPamPasswordHistoryTopologyState { Disabled, Enabled };

struct AltPamPasswordHistoryTopologyOptions {
    std::filesystem::path lockFilePath;
    std::filesystem::path lockDebugLogPath;
    std::filesystem::path stateDirectory = "/var/lib/fic-pwhistory";
    std::filesystem::path historyFile = "/var/lib/fic-pwhistory/opasswd";
    std::filesystem::path transactionLockFile =
        "/var/lib/fic-pwhistory/.lock";
    uid_t storageOwner = 0;
    gid_t storageGroup = 0;
    AtomicWriteOptions writeOptions;
    std::function<bool(const std::string&, const std::string&,
                       const AtomicWriteOptions&, std::string*)> writer;
    std::function<bool(std::string&)> semanticVerifier;
};

class AltPamPasswordHistoryTopologyManager final : public PamTopologyManager {
public:
    inline static constexpr const char* BEGIN =
        "# BEGIN FIC pam_pwhistory transaction";
    inline static constexpr const char* LOCK_RULE =
        "password\trequisite\tpam_fic_pwtxn.so begin timeout=15";
    inline static constexpr const char* HISTORY_RULE =
        "password\trequisite\tpam_pwhistory.so use_authtok conf=/etc/security/fic-pwhistory.conf";
    inline static constexpr const char* UNLOCK_RULE =
        "password\trequired\tpam_fic_pwtxn.so end";
    inline static constexpr const char* END =
        "# END FIC pam_pwhistory transaction";

    AltPamPasswordHistoryTopologyManager(
        fic::platform::PamPlatformConfig platformConfig,
        AltPamPasswordHistoryTopologyOptions options);

    bool prepareStorage(std::string& error) const;
    bool status(AltPamPasswordHistoryTopologyState& state,
                std::string& error);
    bool inspect(PamTopologyStatus& status, std::string& error) override;
    bool canEnable(std::string& error) const override;
    bool enable(std::string& error) override;
    bool disable(std::string& error) override;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    AltPamPasswordHistoryTopologyOptions options_;

    bool verifySemanticEffectiveness(std::string& error) const;
};

std::string altPamPasswordHistoryTopologyStateName(
    AltPamPasswordHistoryTopologyState state);

} // namespace fic::identity::pam

#endif
