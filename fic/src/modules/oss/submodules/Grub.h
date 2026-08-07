#ifndef FIC_OSS_GRUB_H
#define FIC_OSS_GRUB_H

#include "modules/oss/OSS.h"
#include "platform/PlatformProfile.h"

#include <functional>
#include <string>
#include <utility>

class Grub : public OSS {
public:
    ~Grub() override = default;

    bool apply() final;

protected:
    explicit Grub(fic::platform::GrubPlatformConfig platformConfig);

    bool applyGrubValue(
        const std::string& grubKey,
        const std::string& expectedValue,
        const std::function<std::string(const std::string&)>& normalizeExpected = {}
    );

    fic::platform::GrubPlatformConfig platformConfig_;

    virtual bool applyGrub(const std::string& expectedValue) = 0;
};

#endif // FIC_OSS_GRUB_H
