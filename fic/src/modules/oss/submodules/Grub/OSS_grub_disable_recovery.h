#ifndef FIC_OSS_GRUB_DISABLE_RECOVERY_H
#define FIC_OSS_GRUB_DISABLE_RECOVERY_H

#include "modules/oss/submodules/Grub.h"

#include <string>

class OSS_grub_disable_recovery : public Grub {
public:
    explicit OSS_grub_disable_recovery(fic::platform::GrubPlatformConfig platformConfig);

    bool applyGrub(const std::string& expectedValue) override;
};

#endif // FIC_OSS_GRUB_DISABLE_RECOVERY_H