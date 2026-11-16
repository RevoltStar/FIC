#pragma once
#include "platform/PlatformProfile.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace fic::platform {
PlatformProfile makeDebian12SddmTestProfile();
PlatformProfile makeDebian13SddmTestProfile();
PlatformProfile makeUbuntu2404SddmTestProfile();
PlatformProfile makeUbuntu2604SddmTestProfile();
PlatformProfile makeAltP11SddmTestProfile();
}
inline std::vector<fic::platform::PlatformProfile> sddmTestProfiles() {
    using namespace fic::platform;
    return {makeDebian12SddmTestProfile(), makeDebian13SddmTestProfile(),
            makeUbuntu2404SddmTestProfile(), makeUbuntu2604SddmTestProfile()};
}
inline std::string nativeSddmFixture() {
    const auto path = std::filesystem::path(__FILE__).parent_path() /
        "../modules/identity_access/pam/fixtures/ubuntu-sddm.pam";
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read native SDDM fixture");
    return {std::istreambuf_iterator<char>(input), {}};
}
