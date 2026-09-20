#ifndef FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_H
#define FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_H

#include "platform/PlatformProfile.h"

#include <optional>
#include <string>

namespace fic::identity::pam {

enum class PamTopologyState {
    Disabled,
    Enabled,
    Broken,
    Unavailable
};

struct PamTopologyStatus {
    PamTopologyState state = PamTopologyState::Unavailable;
    bool manageable = false;
    // Active pam_faillock integration strategy. Set when the inspected
    // capability is AuthenticationLockout and the topology is enabled;
    // nullopt means the topology is not strategy-aware or not enabled.
    std::optional<fic::platform::PamFaillockStrategy> activeStrategy;
    std::string detail;
};

class PamTopologyManager {
public:
    virtual ~PamTopologyManager() = default;

    virtual bool inspect(PamTopologyStatus& status,
                         std::string& error) = 0;
    virtual bool canEnable(std::string& error) const = 0;
    virtual bool enable(std::string& error) = 0;
    virtual bool disable(std::string& error) = 0;

    // A persisted active record can prove ownership of a shared native
    // activation identifier; FIC-specific identifiers need no such hint.
    virtual void setJournalProvenance(bool) {}

    // Confirm that the native persistent state used for the latest proof is
    // durable before closing a Prepared journal record. ALT managers use
    // AtomicFileWriter; pam-auth-update must prove its external writes.
    virtual bool confirmDurable(std::string& error) const {
        error = "PAM topology manager has no durability proof";
        return false;
    }

    // Strategy-aware faillock activation. Base implementations reject the
    // operation: only faillock topology managers with declared strategies
    // override them. A strategy transition must be atomic: inspect the
    // current topology, snapshot it, build the candidate, apply, re-read,
    // verify the postcondition, and only then commit; on failure restore
    // the snapshot instead of leaving a mixed topology.
    virtual bool canEnableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const;
    virtual bool enableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_H
