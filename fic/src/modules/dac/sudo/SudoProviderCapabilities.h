#ifndef FIC_SUDO_PROVIDER_CAPABILITIES_H
#define FIC_SUDO_PROVIDER_CAPABILITIES_H

#include "platform/PlatformExecutableResolver.h"

#include <filesystem>
#include <string>

namespace fic::sudoers {
enum class SudoProvider { Unknown, Classic, Rust };
enum class SudoCapabilityGuarantee { Unknown, Configurable, VerifiedByConstruction };

struct SudoProviderCapabilities {
    SudoProvider provider = SudoProvider::Unknown;
    std::string version;
    std::filesystem::path executable;
    std::filesystem::path validator;
    std::filesystem::path mainPath;
    SudoCapabilityGuarantee envReset = SudoCapabilityGuarantee::Unknown;
    SudoCapabilityGuarantee exemptGroupDisabled = SudoCapabilityGuarantee::Unknown;
    // Set only by a supported version/semantics contract. Native continuation
    // gates still have to prove command argument preservation independently.
    bool continuationArgumentsProven = false;
};

// Pure version admission is testable without privileged utility execution.
bool classifySudoProviderVersion(const std::string& output,
                                SudoProviderCapabilities& capabilities,
                                std::string& error);
bool detectSudoProviderCapabilities(
    const fic::platform::SudoPlatformConfig& config,
    const fic::platform::PlatformExecutableResolver& executables,
    SudoProviderCapabilities& capabilities, std::string& error,
    bool verifyExecutableHash = true);
} // namespace fic::sudoers
#endif
