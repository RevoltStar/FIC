#pragma once
#include "PreLoginController.h"
namespace fic::prelogin {
class PreLoginSystemdIntegration {
public:
    SystemdStatus observe() const;
    static bool proveBrokerOnly(std::string& error);
};
class PreLoginPowerController final : public PowerController {
public:
    bool execute(Action action, std::string& error) override;
};
}
