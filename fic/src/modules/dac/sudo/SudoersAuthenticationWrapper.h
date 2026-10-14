#pragma once
#include "SudoersDisabledWrapper.h"
#include <tuple>
namespace fic::sudoers {
inline constexpr const char* kAuthenticationPolicy = "sudo_require_authentication";
inline constexpr const char* kAuthenticationResource = "sudoers/authentication";
struct AuthenticationProof {
    std::string wrapperId, canonicalPath, originalDigest, replacementDigest;
    bool operator==(const AuthenticationProof& x) const {
        return std::tie(wrapperId, canonicalPath, originalDigest, replacementDigest) ==
               std::tie(x.wrapperId, x.canonicalPath, x.originalDigest, x.replacementDigest);
    }
};
struct AuthenticationWrapper {
    std::string id, original, replacement;
    std::size_t first = 0, last = 0;
    bool scoped = false;
    AuthenticationProof proof(const std::filesystem::path& path) const;
};
bool parseAuthenticationWrappers(const std::vector<SudoPhysicalLine>& lines,
    std::vector<AuthenticationWrapper>& wrappers, std::string& error);
std::vector<SudoPhysicalLine> makeAuthenticationWrapper(
    const std::string& id, const std::string& original, const std::string& replacement);
}
