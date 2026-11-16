#pragma once
#include "PreLoginController.h"
struct sd_bus;
namespace fic::prelogin {
class PreLoginSystemdIntegration {
public:
    // Explicit bus-opening seam for isolated peers; production uses system bus.
    using OpenBus = std::function<int(sd_bus**)>;
    explicit PreLoginSystemdIntegration(OpenBus openBus = {});
    SystemdStatus observe() const;
    static bool proveBrokerOnly(std::string& error);
private:
    OpenBus openBus_;
};
class PreLoginPowerController final : public PowerController {
public:
    bool execute(Action action, std::string& error) override;
};
}
