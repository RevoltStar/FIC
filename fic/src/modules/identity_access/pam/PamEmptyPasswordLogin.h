#ifndef FIC_PAM_EMPTY_PASSWORD_LOGIN_H
#define FIC_PAM_EMPTY_PASSWORD_LOGIN_H

#include "platform/PlatformProfile.h"
#include <cstdint>

namespace fic::rollback {
class MutationJournal;
}

namespace fic::identity::pam {

inline constexpr char emptyPasswordPolicy[] = "deny_empty_password_login";
inline constexpr char emptyPasswordHook[] = "fic-empty-password-hook";
inline constexpr char emptyPasswordSlot[] = "fic-empty-password";
inline constexpr char emptyPasswordNeutral[] =
    "# FIC empty-password slot v1 neutral\n"
    "auth optional pam_deny.so\n";

bool applyEmptyPasswordLogin(const fic::platform::PamPlatformConfig& platform,
                             fic::rollback::MutationJournal& journal,
                             std::string& error);

bool releaseEmptyPasswordLogin(const fic::platform::PamPlatformConfig& platform,
                               std::uint64_t id,
                               bool& changed, std::string& error);

// Read-only pre-attach validation. Only the exact neutral slot or an exact
// physical witness bound to a single active record can be attached.
bool proveEmptyPasswordSlot(const fic::platform::PamPlatformConfig& platform,
                            const fic::rollback::MutationJournal& journal,
                            std::string& error);

} // namespace fic::identity::pam
#endif
