#ifndef FIC_PACKAGE_WRITER_UNITS_H
#define FIC_PACKAGE_WRITER_UNITS_H
#include <array>
namespace fic::daemon {
// Keep fencing, stop requests and cgroup proofs on the same closed inventory.
inline constexpr std::array<const char*,5> PackageWriterUnits{{
    "fic.service","fic-device.service","fic-notify.service",
    "fic_get_device_info.service","fic_get_device_udev_info.service"}};
}
#endif
