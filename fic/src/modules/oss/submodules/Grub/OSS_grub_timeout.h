#ifndef FIC_OSS_GRUB_TIMEOUT_H
#define FIC_OSS_GRUB_TIMEOUT_H

#include "modules/oss/submodules/Grub.h"

#include <string>

class OSS_grub_timeout : public Grub {
public:
    explicit OSS_grub_timeout(fic::platform::GrubPlatformConfig platformConfig);

    bool applyGrub(const std::string& expectedValue) override;
};

#endif // FIC_OSS_GRUB_TIMEOUT_H