#include "policy/DevicePolicyCompiler.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/process/ProcessExecutor.h>
#include <fic/device-db/DB.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace {

DeviceInfo addDevice(DB& db,
                     int parentId,
                     const std::string& hash,
                     const std::string& devpath,
                     const std::string& subsystem)
{
    DeviceInfo device;
    device.device_hash = hash;
    device.devpath = devpath;
    device.subsystem = subsystem;
    device.device_type = subsystem;
    device.parent_id = parentId;
    device.control_level = "allowed";
    device.control_explicit = false;
    device.ignore_hierarchy = false;
    device.boot_id = "test-boot";
    device.notes = "compiler test";
    device.children_control = "inherit";
    device.id = db.addDevice(device);
    assert(device.id > 0);
    return device;
}

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream input(path);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

} // namespace

int main()
{
    namespace fs = std::filesystem;
    using namespace fic::device_control;

    const fs::path root = fs::temp_directory_path() /
        ("fic-device-policy-compiler-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "log");
    fs::create_directories(root / "data");

    auto productPaths = fic::core::FicProductPaths::production();
    productPaths.privateBinDir = root / "bin";
    productPaths.configDir = root / "config";
    productPaths.languageDir = root / "lang";
    productPaths.logDir = root / "log";
    productPaths.notifyDir = root / "notify";
    productPaths.dataDir = root / "data";
    productPaths.shareDir = root / "share";
    productPaths.imageDir = root / "image";
    productPaths.runtimeDir = root / "run";
    productPaths.lockStatusFile = root / "lockstatus";
    productPaths.commandHashFile = root / "data/commandhash.txt";
    productPaths.deviceDatabaseFile = root / "data/devices.db";
    productPaths.deviceDatabaseLockFile = root / "log/devices.lock";
    productPaths.lockDebugLogFile = root / "log/db-lock.log";
    std::string error;
    assert(productPaths.validate(error));
    assert(fic::core::FicRuntimePaths::initialize(productPaths, error));

    DB db({
        productPaths.deviceDatabaseFile,
        productPaths.deviceDatabaseLockFile,
        productPaths.lockDebugLogFile,
        false
    });
    assert(db.initializeDatabase());
    const DeviceInfo devicesRoot = db.getDeviceByPath("/devices");
    assert(devicesRoot.id > 0);

    DeviceInfo hierarchyRoot = addDevice(
        db, devicesRoot.id, "root", "/devices/pci-test", "pci");
    assert(db.updateDeviceChildrenControl(hierarchyRoot.id, "deny"));
    hierarchyRoot = db.getDeviceById(hierarchyRoot.id);

    DeviceInfo parent = addDevice(
        db, hierarchyRoot.id, "parent", "/devices/pci-test/usb1", "usb");
    assert(db.updateDeviceChildrenControl(parent.id, "allow"));
    parent = db.getDeviceById(parent.id);

    // A non-udev ancestor can still govern a future udev descendant.
    DeviceInfo nonUdevAncestor = addDevice(
        db, hierarchyRoot.id, "host", "/devices/pci-test/host0", "scsi");
    assert(db.updateDeviceChildrenControl(nonUdevAncestor.id, "deny"));

    DeviceInfo child = addDevice(
        db, parent.id, "child", "/devices/pci-test/usb1/1-1", "usb");
    assert(db.updateDeviceControl(child.id, "blocked", true, false, "inherit"));

    DeviceInfo directAllow = addDevice(
        db, parent.id, "direct-allow", "/devices/pci-test/usb1/1-3", "usb");
    assert(db.updateDeviceControl(directAllow.id, "allowed", true, false, "inherit"));

    DeviceInfo permanent = addDevice(
        db, parent.id, "permanent", "/devices/pci-test/usb1/1-4", "usb");
    assert(db.updateDeviceControl(permanent.id, "permanent", true, false, "inherit"));

    DeviceInfo identity = addDevice(
        db, parent.id, "identity", "/devices/pci-test/usb1/1-2", "usb");
    assert(db.addDeviceAttribute(identity.id, "DEVTYPE", "usb_device"));
    assert(db.addDeviceAttribute(identity.id, "ID_VENDOR_ID", "1234"));
    assert(db.addDeviceAttribute(identity.id, "ID_MODEL_ID", "5678"));
    assert(db.addDeviceAttribute(identity.id, "ID_SERIAL", "safe-serial"));
    assert(db.updateDeviceControl(identity.id, "allowed", true, true, "inherit"));

    DeviceInfo escapedIdentity = addDevice(
        db, parent.id, "escaped-identity", "/devices/pci-test/usb1/1-5", "usb");
    assert(db.addDeviceAttribute(escapedIdentity.id, "DEVTYPE", "usb_device"));
    assert(db.addDeviceAttribute(escapedIdentity.id, "ID_VENDOR_ID", "abcd"));
    assert(db.addDeviceAttribute(escapedIdentity.id, "ID_MODEL_ID", "ef01"));
    assert(db.addDeviceAttribute(escapedIdentity.id, "ID_SERIAL", "quoted\"\\serial"));
    assert(db.updateDeviceControl(
        escapedIdentity.id, "ignored", true, true, "inherit"));
    assert(db.updateDeviceCategoryPolicyState({"all", "disabled", "disabled"}));

    DevicePolicyCompiler compiler({"/opt/fic/bin/fic-dick"});
    const DevicePolicyCompilation first = compiler.compile(db);
    assert(first.ok);
    const DevicePolicyCompilation second = compiler.compile(db);
    assert(second.ok);
    assert(first.rules == second.rules);
    assert(first.rules.find("ENV{DEVPATH}==\"/devices/pci-test/*\", ENV{FIC_INHERITED_LEVEL}=\"DENY\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{DEVPATH}==\"/devices/pci-test/usb1/*\", ENV{FIC_INHERITED_LEVEL}=\"ALLOW\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{DEVPATH}==\"/devices/pci-test/host0/*\", ENV{FIC_INHERITED_LEVEL}=\"DENY\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{DEVPATH}==\"/devices/pci-test/usb1/1-1\", ENV{FIC_DIRECT_MATCH}=\"1\", ENV{FIC_DEVICE_LEVEL}=\"DENY\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{DEVPATH}==\"/devices/pci-test/usb1/1-3\", ENV{FIC_DIRECT_MATCH}=\"1\", ENV{FIC_DEVICE_LEVEL}=\"ALLOW\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{DEVPATH}==\"/devices/pci-test/usb1/1-4\", ENV{FIC_DIRECT_MATCH}=\"1\", ENV{FIC_DEVICE_LEVEL}=\"PERMANENT\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{ID_SERIAL}==\"safe-serial\"") != std::string::npos);
    assert(first.rules.find("ENV{ID_SERIAL}==\"quoted\\\"\\\\serial\"") != std::string::npos);
    assert(first.rules.find("ENV{FIC_DIRECT_MATCH}==\"1\", ENV{FIC_EFFECTIVE_LEVEL}") !=
           std::string::npos);
    assert(first.rules.find("ENV{FIC_EFFECTIVE_LEVEL}==\"PERMANENT\", ENV{FIC_CONNECTION_LEVEL}=\"ALLOW\"") !=
           std::string::npos);
    assert(first.rules.find("ENV{FIC_EFFECTIVE_LEVEL}==\"IGNORE\", ENV{FIC_CONNECTION_LEVEL}=\"ALLOW\"") !=
           std::string::npos);
    assert(first.rules.find("ACTION==\"remove\"") != std::string::npos);
    assert(first.rules.find("ACTION==\"remove\"") < first.rules.find("# ADD/CHANGE FILTER"));
    assert(first.rules.find("fic-dick enforce") != std::string::npos);
    assert(first.rules.find("fic-dick udev") != std::string::npos);
    assert(first.rules.find("block_usb_storage:all") != std::string::npos);

    // Persisted explicit static rules must not affect any section of the udev file.
    // Exercise every level and all three collector subsystems, including a
    // defensive managed DEVPATH/children_control case.
    for (const auto* subsystem : {"cpu", "board", "memory"}) {
        for (const auto* level : {"allowed", "blocked", "permanent", "ignored"}) {
            const std::string hash = std::string(subsystem) + "-" + level;
            const std::string path = hash == "cpu-blocked"
                ? "/devices/pci-test/cpu-placeholder" : "/" + std::string(subsystem) + "_list/" + hash;
            DeviceInfo staticDevice = addDevice(db, devicesRoot.id, hash, path, subsystem);
            assert(db.updateDeviceControl(staticDevice.id, level, true, true, "inherit"));
            if (hash == "cpu-blocked")
                assert(db.updateDeviceChildrenControl(staticDevice.id, "deny"));
            const DeviceInfo saved = db.getDeviceById(staticDevice.id);
            assert(saved.control_explicit && saved.ignore_hierarchy && saved.control_level == level);
            const DevicePolicyCompilation afterStatic = compiler.compile(db);
            assert(afterStatic.ok);
            assert(afterStatic.rules == first.rules);
        }
    }
    assert(db.updateDeviceControl(nonUdevAncestor.id, "blocked", true, true, "deny"));
    const DevicePolicyCompilation afterNonUdevDirect = compiler.compile(db);
    assert(afterNonUdevDirect.ok && afterNonUdevDirect.rules == first.rules);

    std::string escaped;
    assert(DevicePolicyCompiler::escapeUdevValue("serial\"\\\n, rule", escaped, error));
    assert(escaped == "serial\\\"\\\\\\x0a, rule");

    const fs::path active = root / "rules/99-fic-devices.rules";
    DevicePolicyActivator activator({active, "/bin/true"});
    assert(activator.activate(first.rules, error));
    assert(readFile(active) == first.rules);
    assert(!fs::exists(active.string() + ".tmp"));
    const auto udevHelp = ProcessExecutor::execute("/usr/bin/udevadm", {"--help"});
    if (udevHelp.success() && udevHelp.standardOutput.find("verify") != std::string::npos) {
        const ProcessResult verification = ProcessExecutor::execute(
            "/usr/bin/udevadm", {"verify", active.string()});
        assert(verification.success());
    }

    DevicePolicyActivator failingActivator({active, "/bin/false"});
    assert(!failingActivator.activate("candidate that must be rolled back\n", error));
    assert(readFile(active) == first.rules);

    // A later USB change can still compile and activate with the static rules
    // already stored in the same database.
    assert(db.updateDeviceControl(child.id, "allowed", true, false, "inherit"));
    const DevicePolicyCompilation afterUsb = compiler.compile(db);
    assert(afterUsb.ok && afterUsb.rules != first.rules);
    assert(afterUsb.rules.find("ENV{DEVPATH}==\"/devices/pci-test/usb1/1-1\", ENV{FIC_DIRECT_MATCH}=\"1\", ENV{FIC_DEVICE_LEVEL}=\"ALLOW\"") !=
           std::string::npos);
    assert(activator.activate(afterUsb.rules, error));
    assert(readFile(active) == afterUsb.rules);

    DeviceInfo unsafe = addDevice(
        db, parent.id, "unsafe", "/devices/pci-test/usb1/1-6", "usb");
    assert(db.addDeviceAttribute(unsafe.id, "DEVTYPE", "usb_interface"));
    assert(db.updateDeviceControl(unsafe.id, "blocked", true, true, "inherit"));
    const DevicePolicyCompilation failed = compiler.compile(db);
    assert(!failed.ok);
    assert(failed.error.find("identity rule cannot be compiled") != std::string::npos);
    assert(readFile(active) == afterUsb.rules);

    fs::remove_all(root);
    return 0;
}
