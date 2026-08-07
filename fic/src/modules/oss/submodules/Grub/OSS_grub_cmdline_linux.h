#ifndef FIC_OSS_GRUB_CMDLINE_LINUX_H
#define FIC_OSS_GRUB_CMDLINE_LINUX_H

#include "modules/oss/submodules/Grub.h"

#include <string>

class OSS_grub_cmdline_linux : public Grub {
public:
    explicit OSS_grub_cmdline_linux(fic::platform::GrubPlatformConfig platformConfig);

    bool applyGrub(const std::string& expectedValue) override;
};

#endif // FIC_OSS_GRUB_CMDLINE_LINUX_H