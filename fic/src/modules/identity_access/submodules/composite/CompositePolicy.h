#ifndef FIC_IDENTITY_ACCESS_COMPOSITE_POLICY_H
#define FIC_IDENTITY_ACCESS_COMPOSITE_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/submodules/composite/ConfigurationParticipant.h"

#include <memory>
#include <vector>

class CompositePolicy : public IdentityAccessPolicy {
public:
    ~CompositePolicy() override = default;
    bool apply() final;

protected:
    CompositePolicy();

    // Concrete composite policies add subsystem-specific participants in their
    // constructor. Participants are configuration adapters, not nested Policy
    // objects, so the outer policy remains the sole owner of policy metadata.
    void addParticipant(
        std::unique_ptr<fic::identity::ConfigurationParticipant> participant);

private:
    std::vector<std::unique_ptr<fic::identity::ConfigurationParticipant>>
        participants_;
};

#endif // FIC_IDENTITY_ACCESS_COMPOSITE_POLICY_H
