#ifndef DC_H
#define DC_H

#include <fic/policy/Policy.h>
#include <fic/core/config/ConfigFileHandler.h>
#include <iostream>

// Общие настройки контроля устройств. Само дерево устройств и исполнение
// обслуживает fic-dick device daemon.
class DC : public Policy
{
protected:
    explicit DC(const std::string& policy);
    
public:
    bool apply () override;
};

class DC_block_usb_storage : public DC
{
public:
    DC_block_usb_storage();
};

class DC_block_printers_scanners : public DC
{
public:
    DC_block_printers_scanners();
};

class DC_block_optical_drives : public DC
{
public:
    DC_block_optical_drives();
};

// Detector setting for the missing-permanent-device runtime event.
//
// This is NOT a Policy::violation_severity: violation_severity reacts to a
// POLICY APPLY failure, while this setting decides the reaction to a runtime
// FACT reported by the device daemon (a permanent obligation whose device is
// gone). The two mechanisms are independent, which is why this policy keeps
// its own violation_severity at NONE: an apply failure of the detector setting
// itself must not trigger the reaction it configures.
//
// The value is a severity token: NONE | SOFT | STANDARD | HARD | ISOLATE.
// NONE means the detector never escalates; the other values are passed to
// IncidentController::raise() by the main daemon, which owns the incident
// state, audit, notification and containment semantics (OFF/PASSIVE/ACTIVE).
//
// An invalid configured value fails closed: PossibleListPolicyTypeValue
// rejects it, so getValue() returns nullopt and the daemon must not guess a
// lower reaction.
class DC_permanent_device_missing_severity : public DC
{
public:
    DC_permanent_device_missing_severity();
};

#endif // D_H
