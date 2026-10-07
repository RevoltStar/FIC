#pragma once

#include "modules/global/GLOBAL.h"

class GLOBAL_incident_response_mode final : public Global {
public:
    GLOBAL_incident_response_mode();
    bool apply() override;
};
