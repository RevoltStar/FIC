#pragma once
#include "PreLoginController.h"
namespace fic::prelogin {
class PreLoginSystemdIntegration {
public:
    SystemdStatus observe() const;
};
class PreLoginPowerController final : public PowerController {
public:
    bool execute(Action action, std::string& error) override;
};
}
