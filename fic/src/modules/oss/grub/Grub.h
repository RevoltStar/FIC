#ifndef FIC_OSS_GRUB_H
#define FIC_OSS_GRUB_H

#include "modules/oss/OSS.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <functional>
#include <string>
#include <utility>

class Grub : public OSS {
public:
    ~Grub() override = default;

    bool apply() final;

protected:
    Grub(fic::platform::GrubPlatformConfig platformConfig,
         const fic::platform::PlatformExecutableResolver& executables,
         bool enforceOwnership = true);

    bool applyGrubValue(
        const std::string& grubKey,
        const std::string& expectedValue,
        const std::function<std::string(const std::string&)>& normalizeExpected = {}
    );

    fic::platform::GrubPlatformConfig platformConfig_;
    const fic::platform::PlatformExecutableResolver& executables_;
    bool enforceOwnership_;

    virtual bool applyGrub(const std::string& expectedValue) = 0;
};

#endif // FIC_OSS_GRUB_H
