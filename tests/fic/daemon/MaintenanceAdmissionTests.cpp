#include "daemon/MaintenanceAdmission.h"
#include <iostream>
#include <stdexcept>
using namespace fic::daemon;
void expect(const std::string& command, const std::string& action, MaintenanceIntent expected) {
    if (maintenanceIntent(command, action) != expected) throw std::runtime_error(command + "/" + action);
}
int main() {
    try {
        for (const auto* domain : {"dm-prerm-prepare", "desktop-prerm-prepare", "pam-provider-prerm-prepare", "pam-password-prerm-prepare"}) {
            expect(domain, "preflight", MaintenanceIntent::ReadOnly);
            expect(domain, "release", MaintenanceIntent::PackageMutation);
            expect(domain, "force", MaintenanceIntent::Invalid);
        }
        for (const auto* command : {"check-config", "wait-daemon", "incident-pam-verify", "incident-pam-prove-detached", "validate-pam-slots-before-attach"})
            expect(command, "", MaintenanceIntent::ReadOnly);
        for (const auto* command : {"ensure-config", "ensure-config-first-install", "incident-init", "bootstrap-pam-password-slots"})
            expect(command, "", MaintenanceIntent::ExclusiveMutation);
        expect("incident-pam-alt", "status", MaintenanceIntent::ReadOnly);
        expect("incident-pam-alt", "attach", MaintenanceIntent::ExclusiveMutation);
        expect("incident-pam-alt", "detach", MaintenanceIntent::ExclusiveMutation);
        expect("incident-pam-alt", "force", MaintenanceIntent::Invalid);
        for(const auto* command:{"pam-alt-faillock","pam-alt-pwhistory"}) {
            expect(command,"status",MaintenanceIntent::ResourceSerialized);
            expect(command,"enable",MaintenanceIntent::ExclusiveMutation);
            expect(command,"disable",MaintenanceIntent::ExclusiveMutation);
            expect(command,"force",MaintenanceIntent::Invalid);
        }
        expect("pam-alt-pwhistory","prepare",MaintenanceIntent::ExclusiveMutation);
        expect("pam-alt-faillock","prepare",MaintenanceIntent::Invalid);
        expect("future-command", "release", MaintenanceIntent::Invalid);
        for (auto intent : {MaintenanceIntent::ReadOnly, MaintenanceIntent::ResourceSerialized, MaintenanceIntent::Invalid})
            if (requiresInstanceLock(intent)) throw std::runtime_error("unexpected global lock");
        if (!requiresInstanceLock(MaintenanceIntent::ExclusiveMutation) || !requiresInstanceLock(MaintenanceIntent::PackageMutation))
            throw std::runtime_error("missing mutation lock");
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
