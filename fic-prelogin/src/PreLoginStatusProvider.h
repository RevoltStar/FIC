#pragma once
#include "PreLoginSystemdIntegration.h"
#include <fic/ipc/FicIpcClient.h>
namespace fic::prelogin {
class PreLoginStatusProvider final : public StatusProvider {
public:
    PreLoginStatusProvider();
    // Explicit fixture seam; production never accepts an endpoint argument.
    PreLoginStatusProvider(std::string path, uid_t uid);
    Observation read() override;
private:
    ipc::Client client_;
    PreLoginSystemdIntegration systemd_;
};
}
