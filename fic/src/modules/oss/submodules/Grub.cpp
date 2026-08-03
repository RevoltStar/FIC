#include "modules/oss/submodules/Grub.h"

#include <mutex>

namespace {

std::mutex grubConfigurationMutex;

} // namespace

Grub::Grub()
    : OSS() {
    this->submoduleName = "Grub";
}

bool Grub::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(grubConfigurationMutex);
    return this->applyGrub(*value);
}
