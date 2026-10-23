#ifndef FIC_MAINTENANCE_ADMISSION_H
#define FIC_MAINTENANCE_ADMISSION_H
#include <string>
namespace fic::daemon {
enum class MaintenanceIntent { ReadOnly, ResourceSerialized, ExclusiveMutation, PackageMutation, Invalid };
inline MaintenanceIntent maintenanceIntent(const std::string& command, const std::string& action) {
    if (command == "check-config" || command == "wait-daemon" ||
        command == "incident-pam-verify" || command == "incident-pam-prove-detached" ||
        command == "validate-pam-slots-before-attach") return MaintenanceIntent::ReadOnly;
    if (command == "dm-prerm-prepare" || command == "desktop-prerm-prepare" ||
        command == "pam-provider-prerm-prepare" || command == "pam-password-prerm-prepare") {
        if (action == "preflight") return MaintenanceIntent::ReadOnly;
        if (action == "release") return MaintenanceIntent::PackageMutation;
        return MaintenanceIntent::Invalid;
    }
    if (command == "incident-pam-alt") {
        if (action == "status") return MaintenanceIntent::ReadOnly;
        if (action == "attach" || action == "detach") return MaintenanceIntent::ExclusiveMutation;
        return MaintenanceIntent::Invalid;
    }
    if (command == "ensure-config" || command == "ensure-config-first-install" ||
        command == "incident-init" || command == "bootstrap-pam-password-slots")
        return MaintenanceIntent::ExclusiveMutation;
    if (command == "pam-alt-faillock" || command == "pam-alt-pwhistory") {
        if (action == "status") return MaintenanceIntent::ResourceSerialized;
        if (action == "enable" || action == "disable" ||
            (command == "pam-alt-pwhistory" && action == "prepare"))
            return MaintenanceIntent::ExclusiveMutation;
        return MaintenanceIntent::Invalid;
    }
    return MaintenanceIntent::Invalid;
}
inline bool requiresInstanceLock(MaintenanceIntent intent) {
    return intent == MaintenanceIntent::ExclusiveMutation || intent == MaintenanceIntent::PackageMutation;
}
}
#endif
