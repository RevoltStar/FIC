#ifndef FIC_OSS_GRUB_H
#define FIC_OSS_GRUB_H

#include "modules/oss/OSS.h"

#include <string>

class Grub : public OSS {
public:
    ~Grub() override = default;

    bool apply() final;

protected:
    Grub();

    virtual bool applyGrub(const std::string& expectedValue) = 0;
};

#endif // FIC_OSS_GRUB_H
