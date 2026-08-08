#ifndef FIC_OSS_GRUB_TIMEOUT_H
#define FIC_OSS_GRUB_TIMEOUT_H

#include "modules/oss/submodules/Grub.h"

#include <string>

class OSS_grub_timeout : public Grub {
public:
    OSS_grub_timeout(
        fic::platform::GrubPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);

    bool applyGrub(const std::string& expectedValue) override;
};

#endif // FIC_OSS_GRUB_TIMEOUT_H
