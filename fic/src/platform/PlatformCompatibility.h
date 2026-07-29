#ifndef FIC_PLATFORM_COMPATIBILITY_H
#define FIC_PLATFORM_COMPATIBILITY_H

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <map>
#include <string>

namespace fic::platform {

using OsReleaseValues = std::map<std::string, std::string>;

bool validatePlatformProfile(const PlatformProfile& profile, std::string& error);

bool readOsRelease(const std::filesystem::path& path,
                   OsReleaseValues& values,
                   std::string& error);

bool isHostCompatible(const PlatformProfile& profile,
                      const OsReleaseValues& values,
                      std::string& error);

bool validateHostCompatibility(
    const PlatformProfile& profile,
    const std::filesystem::path& osReleasePath,
    std::string& error);

} // namespace fic::platform

#endif // FIC_PLATFORM_COMPATIBILITY_H
