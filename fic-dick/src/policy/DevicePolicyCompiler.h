#ifndef FIC_DEVICE_POLICY_COMPILER_H
#define FIC_DEVICE_POLICY_COMPILER_H

#include <fic/device-db/DB.h>

#include <filesystem>
#include <string>

namespace fic::device_control {

struct DevicePolicyCompilerOptions {
    std::string ficDickPath;
};

struct DevicePolicyCompilation {
    bool ok = false;
    std::string rules;
    std::string error;
};

class DevicePolicyCompiler {
public:
    explicit DevicePolicyCompiler(DevicePolicyCompilerOptions options);

    DevicePolicyCompilation compile(DB& db) const;

    static bool escapeUdevValue(const std::string& value,
                                std::string& escaped,
                                std::string& error);

private:
    DevicePolicyCompilerOptions options_;
};

struct DevicePolicyActivatorOptions {
    std::filesystem::path activeRulesPath;
    std::string udevadmPath;
};

class DevicePolicyActivator {
public:
    explicit DevicePolicyActivator(DevicePolicyActivatorOptions options);

    bool activate(const std::string& rules, std::string& error) const;

private:
    DevicePolicyActivatorOptions options_;
};

} // namespace fic::device_control

#endif
