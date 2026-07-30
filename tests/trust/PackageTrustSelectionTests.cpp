#include "trust/PackageTrustSelection.h"

#include <cassert>
#include <sstream>
#include <vector>

int main() {
    using fic::platform::ExecutableId;
    const fic::platform::PlatformExecutables executables{
        {
            {ExecutableId::Systemctl,
             {"/usr/bin/systemctl", "/bin/systemctl"}},
            {ExecutableId::Udevadm,
             {"/usr/bin/udevadm", "/usr/sbin/udevadm",
              "/bin/udevadm", "/sbin/udevadm"}},
        }
    };

    std::istringstream unrelated(
        "/usr/bin/synaptic\n"
        "/usr/lib/libvte.so\n");
    assert(fic::trust::selectAffectedExecutableIds(
               executables, unrelated).empty());

    std::istringstream affected(
        "/usr/bin/systemctl\n"
        "/bin/systemctl\n"
        "/usr/sbin/udevadm\r\n"
        "usr/bin/systemctl\n"
        "/usr/bin/../bin/systemctl\n");
    const std::vector<ExecutableId> selected =
        fic::trust::selectAffectedExecutableIds(executables, affected);
    assert(selected.size() == 2);
    assert(selected[0] == ExecutableId::Systemctl);
    assert(selected[1] == ExecutableId::Udevadm);

    return 0;
}
