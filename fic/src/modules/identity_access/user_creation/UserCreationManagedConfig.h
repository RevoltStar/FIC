#ifndef FIC_USER_CREATION_MANAGED_CONFIG_H
#define FIC_USER_CREATION_MANAGED_CONFIG_H

#include "platform/PlatformProfile.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::user_creation {

enum class ConfigKind { UseraddDefaults, Adduser };

struct Assignment {
    std::string key;
    std::string line;
    bool operator==(const Assignment& other) const {
        return key == other.key && line == other.line;
    }
};

struct PolicyBlock {
    std::string policyName;
    std::vector<Assignment> assignments;
    std::string raw;
};

struct ManagedConfigModel {
    bool blockPresent = false;
    std::size_t blockOffset = 0;
    std::size_t blockLength = 0;
    std::vector<PolicyBlock> policies;
};

struct PolicyRoute {
    ConfigKind kind = ConfigKind::UseraddDefaults;
    std::string path;
    std::vector<std::string> keys;
};

constexpr const char* kBlockBegin =
    "#@FIC_USER_CREATION_BLOCK_BEGIN version=1@";
constexpr const char* kBlockEnd = "#@FIC_USER_CREATION_BLOCK_END@";
constexpr const char* kMarkerIntroducer = "#@FIC_";

bool policyRoute(const fic::platform::UserCreationPlatformConfig& platform,
                 const std::string& policyName, PolicyRoute& route,
                 std::string& error);

bool parseManagedConfig(const std::string& content, ConfigKind kind,
                        ManagedConfigModel& model, std::string& error);

std::string canonicalPolicyBlock(const std::string& policyName,
                                 const std::vector<Assignment>& assignments);

bool upsertPolicyBlock(const std::string& content, ConfigKind kind,
                       const std::string& policyName,
                       const std::vector<Assignment>& assignments,
                       std::string& result, bool& changed,
                       std::string& error);

bool removePolicyBlock(const std::string& content, ConfigKind kind,
                       const std::string& policyName,
                       const std::vector<Assignment>& expected,
                       std::string& result, bool& removed,
                       std::string& error);

const PolicyBlock* findPolicyBlock(const ManagedConfigModel& model,
                                   const std::string& policyName);

// Returns the value seen by the native last-wins consumer. nullopt means no
// valid assignment. Malformed target-looking lines fail closed.
bool effectiveValue(const std::string& content, ConfigKind kind,
                    fic::platform::UseraddDefaultsLookupSemantics semantics,
                    const std::string& key,
                    std::optional<std::string>& value,
                    std::string& error);

bool effectiveAssignmentsMatch(
    const std::string& content, ConfigKind kind,
    fic::platform::UseraddDefaultsLookupSemantics semantics,
    const std::vector<Assignment>& expected, std::string& error);

} // namespace fic::identity::user_creation

#endif
