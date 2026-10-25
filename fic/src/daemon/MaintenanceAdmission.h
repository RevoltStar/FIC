#ifndef FIC_MAINTENANCE_ADMISSION_H
#define FIC_MAINTENANCE_ADMISSION_H
#include <string>
namespace fic::daemon {
enum class MaintenanceIntent { ReadOnly, ExclusiveMutation, Invalid };
inline MaintenanceIntent maintenanceIntent(const std::string& command, const std::string& action) {
    if (command == "check-config" || command == "check-persistent" || command == "wait-daemon" ||
        command == "incident-pam-verify" || command == "incident-pam-prove-detached" ||
        command == "validate-pam-slots-before-attach") return MaintenanceIntent::ReadOnly;
    if (command == "incident-pam-alt") {
        if (action == "status") return MaintenanceIntent::ReadOnly;
        if (action == "attach" || action == "detach") return MaintenanceIntent::ExclusiveMutation;
        return MaintenanceIntent::Invalid;
    }
    if (command == "initialize-journal" || command == "complete-install" ||
        command == "ensure-config" || command == "ensure-config-first-install" ||
        command == "incident-init" || command == "bootstrap-pam-password-slots")
        return MaintenanceIntent::ExclusiveMutation;
    if (command == "pam-alt-faillock" || command == "pam-alt-pwhistory") {
        if (action == "status") return MaintenanceIntent::ReadOnly;
        if (command == "pam-alt-pwhistory" && action == "prepare")
            return MaintenanceIntent::ExclusiveMutation;
        return MaintenanceIntent::Invalid;
    }
    return MaintenanceIntent::Invalid;
}
inline bool installationMaintenanceCommand(const std::string& command,const std::string& action) {
    return command=="ensure-config"||command=="ensure-config-first-install"||command=="incident-init"||
        command=="bootstrap-pam-password-slots"||command=="initialize-journal"||command=="complete-install"||
        (command=="incident-pam-alt"&&action=="attach")||(command=="pam-alt-pwhistory"&&action=="prepare");
}
inline bool requiresInstanceLock(MaintenanceIntent intent) {
    return intent == MaintenanceIntent::ExclusiveMutation;
}
}
#endif
