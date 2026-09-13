#include "platform/PlatformProfile.h"

#include <algorithm>
#include <cctype>

namespace fic::platform {
namespace {

std::string toLower(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (char c : value) {
        result.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

} // namespace

std::string pamFaillockStrategyName(PamFaillockStrategy strategy) {
    switch (strategy) {
    case PamFaillockStrategy::PreauthRequisite:
        return "preauth_requisite";
    case PamFaillockStrategy::PreauthRequired:
        return "preauth_required";
    case PamFaillockStrategy::Authsucc:
        return "authsucc";
    }
    return "unknown";
}

std::optional<PamFaillockStrategy> parsePamFaillockStrategy(
    const std::string& name) {
    const std::string normalized = toLower(name);
    if (normalized == "preauth_requisite") {
        return PamFaillockStrategy::PreauthRequisite;
    }
    if (normalized == "preauth_required") {
        return PamFaillockStrategy::PreauthRequired;
    }
    if (normalized == "authsucc") {
        return PamFaillockStrategy::Authsucc;
    }
    return std::nullopt;
}

bool supportsPamFaillockStrategy(
    const PamCapabilityConfig& capability,
    PamFaillockStrategy strategy) {
    return std::find(
               capability.supportedFaillockStrategies.begin(),
               capability.supportedFaillockStrategies.end(),
               strategy) !=
        capability.supportedFaillockStrategies.end();
}

} // namespace fic::platform