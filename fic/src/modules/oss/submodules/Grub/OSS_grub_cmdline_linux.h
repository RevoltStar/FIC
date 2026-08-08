#ifndef FIC_OSS_GRUB_CMDLINE_LINUX_H
#define FIC_OSS_GRUB_CMDLINE_LINUX_H

#include "modules/oss/submodules/Grub.h"

#include <string>

class OSS_grub_cmdline_linux : public Grub {
public:
    OSS_grub_cmdline_linux(
        fic::platform::GrubPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);

    bool applyGrub(const std::string& expectedValue) override;
};

#endif // FIC_OSS_GRUB_CMDLINE_LINUX_H
