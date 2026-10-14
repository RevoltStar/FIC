#pragma once

#include "modules/global/GLOBAL.h"
#include <functional>

class GLOBAL_lock_exempt_fic_members final : public Global {
public:
    using StatusReader = std::function<std::optional<bool>(std::string&)>;
    explicit GLOBAL_lock_exempt_fic_members(StatusReader reader = {});
    bool apply() override;
private:
    StatusReader reader_;
};
