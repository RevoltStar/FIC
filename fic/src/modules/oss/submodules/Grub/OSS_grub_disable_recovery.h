#ifndef FIC_OSS_GRUB_DISABLE_RECOVERY_H
#define FIC_OSS_GRUB_DISABLE_RECOVERY_H

#include "modules/oss/submodules/Grub.h"

#include <string>

class OSS_grub_disable_recovery : public Grub {
public:
    OSS_grub_disable_recovery(
        fic::platform::GrubPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);

    bool applyGrub(const std::string& expectedValue) override;
};

#endif // FIC_OSS_GRUB_DISABLE_RECOVERY_H
