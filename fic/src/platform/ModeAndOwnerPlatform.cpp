#include "platform/PlatformProfile.h"

#include <stdexcept>

namespace fic::platform {
namespace {

using Dac = DacPlatformConfig;

bool sameMetadata(const FileMetadata& left, const FileMetadata& right) {
    return left.owner == right.owner && left.group == right.group &&
           left.permissions == right.permissions;
}

Dac::PathContract contract(const ModeAndOwnerPathProfiles& rule,
                           const FileMetadata& metadata) {
    Dac::PathContract result;
    result.metadata = metadata;
    result.required = rule.required;
    result.allowedFinalSymlinkTargets = rule.allowedFinalSymlinkTargets;
    for (const ModeAndOwnerProviderProfileTarget& target :
         rule.providerManagedFinalSymlinkTargets) {
        const FileMetadata& targetMetadata =
            &metadata == &rule.system ? target.system : target.strict;
        result.providerTargets.push_back(
            {target.path, target.provider, targetMetadata});
    }
    return result;
}

} // namespace

Dac::Object makeModeAndOwnerPathObject(
    std::string id,
    const ModeAndOwnerPathProfiles& profiles) {
    Dac::StaticPathObject target;
    target.path = profiles.path;
    target.profiles.emplace(
        Dac::Profile::System,
        contract(profiles, profiles.system));
    if (!sameMetadata(profiles.strict, profiles.system)) {
        target.profiles.emplace(
            Dac::Profile::Strict,
            contract(profiles, profiles.strict));
    }
    return {std::move(id), std::move(target)};
}

Dac::Object makeModeAndOwnerTcbObject(
    std::string id,
    const TcbCredentialStorageConfig& profiles) {
    Dac::TcbCredentialTreeObject target;
    TcbCredentialStorageConfig system = profiles;
    bool differs = system.rootPermissions != system.rootSystemPermissions ||
        system.entryDirectoryPermissions !=
            system.entryDirectorySystemPermissions;
    system.rootPermissions = system.rootSystemPermissions;
    system.entryDirectoryPermissions =
        system.entryDirectorySystemPermissions;
    for (TcbCredentialFileRule& file : system.files) {
        differs = differs || file.permissions != file.systemPermissions;
        file.permissions = file.systemPermissions;
    }
    target.profiles.emplace(Dac::Profile::System, std::move(system));
    if (differs) {
        target.profiles.emplace(Dac::Profile::Strict, profiles);
    }
    return {std::move(id), std::move(target)};
}

void appendModeAndOwnerObjects(
    DacPlatformConfig& config,
    const std::vector<ModeAndOwnerPathProfiles>& paths,
    const std::vector<std::string>& pathIds,
    const std::vector<ModeAndOwnerPathProfiles>& commands,
    const std::vector<std::string>& commandIds,
    const std::optional<TcbCredentialStorageConfig>& tcb) {
    if (paths.size() != pathIds.size() || commands.size() != commandIds.size()) {
        throw std::logic_error("DAC logical object id count mismatch");
    }
    for (std::size_t i = 0; i < paths.size(); ++i) {
        config.modeAndOwnerObjects.push_back(
            makeModeAndOwnerPathObject(pathIds[i], paths[i]));
    }
    for (std::size_t i = 0; i < commands.size(); ++i) {
        config.modeAndOwnerObjects.push_back(
            makeModeAndOwnerPathObject(commandIds[i], commands[i]));
    }
    if (tcb) {
        config.modeAndOwnerObjects.push_back(
            makeModeAndOwnerTcbObject("tcb_credentials", *tcb));
    }
}

} // namespace fic::platform
