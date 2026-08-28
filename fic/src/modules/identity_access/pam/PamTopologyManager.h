#ifndef FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_H
#define FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_H

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
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_TOPOLOGY_MANAGER_H
