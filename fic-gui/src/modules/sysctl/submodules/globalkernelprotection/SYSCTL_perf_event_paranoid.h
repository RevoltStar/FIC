#ifndef SYSCTL_PERF_EVENT_PARANOID_H
#define SYSCTL_PERF_EVENT_PARANOID_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

class SYSCTL_perf_event_paranoid : public GlobalKernelProtection
{
public:
    SYSCTL_perf_event_paranoid();
    bool check_and_fix() override;
};

#endif // SYSCTL_PERF_EVENT_PARANOID_H
