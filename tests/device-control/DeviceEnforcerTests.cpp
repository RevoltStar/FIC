#include "core/DeviceEnforcerSysfs.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void expect(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FakeSysfs {
public:
    FakeSysfs()
        : root_(fs::temp_directory_path() /
                ("fic-device-enforcer-test-" + std::to_string(::getpid())))
    {
        fs::remove_all(root_);
        fs::create_directories(root_ / "bus/scsi");
        fs::create_directories(root_ / "bus/pci");
        fs::create_directories(root_ / "bus/block");
        fs::create_directories(root_ / "devices");
    }

    ~FakeSysfs()
    {
        fs::remove_all(root_);
    }

    const fs::path& root() const
    {
        return root_;
    }

    fs::path pathForDevpath(const std::string& devpath) const
    {
        return root_ / devpath.substr(1);
    }

    void createAttribute(const fs::path& path) const
    {
        fs::create_directories(path.parent_path());
        std::ofstream(path).close();
    }

    void markSubsystem(const fs::path& devicePath,
                       const std::string& subsystem) const
    {
        fs::create_directories(devicePath);
        const fs::path target = root_ / "bus" / subsystem;
        fs::create_directory_symlink(fs::relative(target, devicePath),
                                     devicePath / "subsystem");
    }

    static std::string readAttribute(const fs::path& path)
    {
        std::ifstream input(path);
        return std::string(std::istreambuf_iterator<char>(input),
                           std::istreambuf_iterator<char>());
    }

private:
    fs::path root_;
};

const std::string kControllerDevpath =
    "/devices/pci0000:00/0000:00:14.0";
const std::string kBlockDevpath =
    kControllerDevpath +
    "/usb1/1-2/host6/target6:0:0/6:0:0:0/block/sdb";

void testBlockUsesScsiDeleteAndNeverPciRemove()
{
    FakeSysfs sysfs;
    const fs::path controller = sysfs.pathForDevpath(kControllerDevpath);
    const fs::path scsiDevice = sysfs.pathForDevpath(
        kControllerDevpath + "/usb1/1-2/host6/target6:0:0/6:0:0:0");
    const fs::path blockDevice = sysfs.pathForDevpath(kBlockDevpath);
    const fs::path pciRemove = controller / "remove";
    const fs::path scsiDelete = scsiDevice / "delete";

    sysfs.markSubsystem(controller, "pci");
    sysfs.createAttribute(pciRemove);
    sysfs.markSubsystem(scsiDevice, "scsi");
    sysfs.createAttribute(scsiDelete);
    fs::create_directories(blockDevice);

    std::string details;
    const bool enforced = fic::device_control::internal::enforceDenyThroughSysfs(
        "block", kBlockDevpath, {sysfs.root()}, details);

    expect(enforced, "block DENY did not use the valid SCSI delete target");
    expect(FakeSysfs::readAttribute(scsiDelete) == "1",
           "SCSI delete target was not written");
    expect(FakeSysfs::readAttribute(pciRemove).empty(),
           "block DENY wrote the parent PCI remove target");
    expect(details.find(scsiDelete.string()) != std::string::npos,
           "block DENY details do not identify the SCSI delete target");
}

void testBlockWithoutSafeDeleteFailsClosed()
{
    FakeSysfs sysfs;
    const fs::path controller = sysfs.pathForDevpath(kControllerDevpath);
    const fs::path wrongDeleteParent = sysfs.pathForDevpath(
        kControllerDevpath + "/usb1/1-2/host6/target6:0:0/6:0:0:0");
    const fs::path blockDevice = sysfs.pathForDevpath(kBlockDevpath);
    const fs::path pciRemove = controller / "remove";
    const fs::path wrongDelete = wrongDeleteParent / "delete";

    sysfs.markSubsystem(controller, "pci");
    sysfs.createAttribute(pciRemove);
    sysfs.markSubsystem(wrongDeleteParent, "block");
    sysfs.createAttribute(wrongDelete);
    fs::create_directories(blockDevice);

    std::string details;
    const bool enforced = fic::device_control::internal::enforceDenyThroughSysfs(
        "block", kBlockDevpath, {sysfs.root()}, details);

    expect(!enforced, "block DENY accepted a non-SCSI delete target");
    expect(FakeSysfs::readAttribute(wrongDelete).empty(),
           "block DENY wrote a delete target from the wrong subsystem");
    expect(FakeSysfs::readAttribute(pciRemove).empty(),
           "failed block DENY wrote the parent PCI remove target");
    expect(details.find("PCI remove fallback is prohibited") != std::string::npos,
           "fail-closed block DENY details are not explicit");
}

void testPciDeviceStillUsesPciRemove()
{
    FakeSysfs sysfs;
    const fs::path controller = sysfs.pathForDevpath(kControllerDevpath);
    const fs::path pciRemove = controller / "remove";

    sysfs.markSubsystem(controller, "pci");
    sysfs.createAttribute(pciRemove);

    std::string details;
    const bool enforced = fic::device_control::internal::enforceDenyThroughSysfs(
        "pci", kControllerDevpath, {sysfs.root()}, details);

    expect(enforced, "PCI DENY did not use its own remove target");
    expect(FakeSysfs::readAttribute(pciRemove) == "1",
           "PCI remove target was not written");
}

void testPciDeviceDoesNotUseParentPciRemove()
{
    FakeSysfs sysfs;
    const std::string childDevpath = kControllerDevpath + "/0000:00:14.1";
    const fs::path controller = sysfs.pathForDevpath(kControllerDevpath);
    const fs::path child = sysfs.pathForDevpath(childDevpath);
    const fs::path parentRemove = controller / "remove";

    sysfs.markSubsystem(controller, "pci");
    sysfs.createAttribute(parentRemove);
    sysfs.markSubsystem(child, "pci");

    std::string details;
    const bool enforced = fic::device_control::internal::enforceDenyThroughSysfs(
        "pci", childDevpath, {sysfs.root()}, details);

    expect(!enforced, "PCI DENY climbed to a parent PCI remove target");
    expect(FakeSysfs::readAttribute(parentRemove).empty(),
           "PCI DENY wrote a parent PCI remove target");
}

void testUsbAuthorizedEnforcementIsPreserved()
{
    FakeSysfs sysfs;
    const std::string usbDevpath = kControllerDevpath + "/usb1/1-2";
    const fs::path usbDevice = sysfs.pathForDevpath(usbDevpath);
    const fs::path authorized = usbDevice / "authorized";

    sysfs.createAttribute(authorized);

    std::string details;
    const bool enforced = fic::device_control::internal::enforceDenyThroughSysfs(
        "usb", usbDevpath, {sysfs.root()}, details);

    expect(enforced, "USB DENY no longer uses the authorized target");
    expect(FakeSysfs::readAttribute(authorized) == "0",
           "USB authorized target was not written with 0");
}

} // namespace

int main()
{
    testBlockUsesScsiDeleteAndNeverPciRemove();
    testBlockWithoutSafeDeleteFailsClosed();
    testPciDeviceStillUsesPciRemove();
    testPciDeviceDoesNotUseParentPciRemove();
    testUsbAuthorizedEnforcementIsPreserved();
    return 0;
}
