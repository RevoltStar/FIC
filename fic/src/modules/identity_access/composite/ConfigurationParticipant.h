#ifndef FIC_IDENTITY_ACCESS_CONFIGURATION_PARTICIPANT_H
#define FIC_IDENTITY_ACCESS_CONFIGURATION_PARTICIPANT_H

#include "modules/identity_access/composite/ConfigurationTransaction.h"

#include <memory>
#include <string>

namespace fic::identity {

struct ConfigurationPreparationResult {
    std::unique_ptr<PreparedConfigurationChange> change;
    std::string error;

    bool ok() const noexcept {
        return change != nullptr;
    }
};

// A participant describes one subsystem-specific configuration edit. It may
// inspect and snapshot the system during prepare(), but it must not mutate it.
// This keeps all composite preflight work ahead of the first persistent write.
class ConfigurationParticipant {
public:
    virtual ~ConfigurationParticipant() = default;

    virtual std::string id() const = 0;
    virtual ConfigurationPreparationResult prepare(
        const std::string& expectedValue) = 0;
};

} // namespace fic::identity

#endif // FIC_IDENTITY_ACCESS_CONFIGURATION_PARTICIPANT_H
