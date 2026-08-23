#ifndef FIC_IDENTITY_ACCESS_PAM_CONFIGURATION_H
#define FIC_IDENTITY_ACCESS_PAM_CONFIGURATION_H

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace fic::identity::pam {

enum class PamManagementGroup {
    Auth,
    Account,
    Password,
    Session
};

enum class PamIncludeKind {
    None,
    Include,
    Substack,
    IncludeAll
};

struct PamRule {
    std::filesystem::path source;
    std::size_t line = 0;
    PamManagementGroup group = PamManagementGroup::Auth;
    std::string control;
    std::string module;
    std::vector<std::string> arguments;
    PamIncludeKind includeKind = PamIncludeKind::None;
    std::string includeTarget;
};

// Structured effective stack used by the control-flow analyzer. Includes are
// expanded in place. A substack remains one parent entry and owns its expanded
// child stack, matching Linux-PAM jump and termination boundaries.
struct PamStackEntry {
    PamRule rule;
    std::vector<PamStackEntry> substack;

    bool isSubstack() const {
        return rule.includeKind == PamIncludeKind::Substack;
    }
};

struct PamEffectiveStack {
    std::string service;
    PamManagementGroup group = PamManagementGroup::Auth;
    std::vector<PamStackEntry> entries;
    std::set<std::filesystem::path> sourceFiles;
};

class PamConfiguration {
public:
    explicit PamConfiguration(fic::platform::PamPlatformConfig platformConfig);

    bool serviceExists(const std::string& service) const;
    bool existingServices(const std::vector<std::string>& services,
                          std::vector<std::string>& existing,
                          std::string& error) const;

    bool collectRules(const std::string& service,
                      PamManagementGroup group,
                      std::vector<PamRule>& rules,
                      std::string& error,
                      std::set<std::filesystem::path>* sourceFiles = nullptr);

    bool buildEffectiveStack(const std::string& service,
                             PamManagementGroup group,
                             PamEffectiveStack& stack,
                             std::string& error);

private:
    struct ParsedService {
        std::filesystem::path path;
        std::vector<PamRule> rules;
    };

    fic::platform::PamPlatformConfig platformConfig_;
    std::map<std::string, ParsedService> cache_;

    bool resolveServicePath(const std::string& service,
                            bool& exists,
                            std::filesystem::path& path,
                            std::string& error) const;
    bool parseService(const std::string& service,
                      const ParsedService*& parsed,
                      std::string& error);
    bool buildEffectiveStackRecursive(
        const std::string& service,
        PamManagementGroup group,
        std::vector<PamStackEntry>& entries,
        std::set<std::string>& recursionStack,
        std::size_t depth,
        std::size_t& entryCount,
        std::set<std::filesystem::path>& sourceFiles,
        std::string& error);
};

std::string pamManagementGroupName(PamManagementGroup group);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_CONFIGURATION_H
