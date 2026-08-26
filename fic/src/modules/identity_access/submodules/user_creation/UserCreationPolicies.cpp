#include "modules/identity_access/submodules/user_creation/UserCreationPolicies.h"

#include "modules/identity_access/configuration/AdduserConfigFileHandler.h"
#include "modules/identity_access/configuration/LoginDefsFileHandler.h"
#include "modules/identity_access/configuration/LocalGroupDatabase.h"
#include "modules/identity_access/configuration/UseraddDefaultsFileHandler.h"

#include <cerrno>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {

constexpr const char* kSubmodule = "USER_CREATION";

bool isNormalizedAbsolutePath(const std::string& value) {
    if (value.empty() || value.find_first_of(" \t\r\n") != std::string::npos) {
        return false;
    }
    const std::filesystem::path path(value);
    return path.is_absolute() && path != path.root_path() &&
        path.lexically_normal() == path;
}

class PathPolicyTypeValue final : public PolicyTypeValue {
public:
    explicit PathPolicyTypeValue(std::string defaultValue) {
        this->defaultValue = std::move(defaultValue);
    }
    PolicyEditorSpec getEditorSpec() const override { return {"lineedit"}; }
    bool validate(const std::string& value) override {
        return isNormalizedAbsolutePath(value);
    }
    std::string getPolicyRestrictionInfo() override {
        return "normalized absolute path other than /";
    }
    std::string postProcessingValue(const std::string& value) override {
        return value;
    }
    std::string reverse_postProcessingValue(const std::string& value) override {
        return value;
    }
};

class GroupNamePolicyTypeValue final : public PolicyTypeValue {
public:
    explicit GroupNamePolicyTypeValue(std::string defaultValue) {
        this->defaultValue = std::move(defaultValue);
    }
    PolicyEditorSpec getEditorSpec() const override { return {"lineedit"}; }
    bool validate(const std::string& value) override {
        return fic::identity::isValidLocalGroupName(value);
    }
    std::string getPolicyRestrictionInfo() override {
        return "existing local group name (numeric GID is not accepted)";
    }
    std::string postProcessingValue(const std::string& value) override {
        return value;
    }
    std::string reverse_postProcessingValue(const std::string& value) override {
        return value;
    }
};

bool lstatType(const std::filesystem::path& path, mode_t type) {
    struct stat status {};
    return ::lstat(path.c_str(), &status) == 0 &&
        (status.st_mode & S_IFMT) == type;
}

bool statType(const std::filesystem::path& path, mode_t type) {
    struct stat status {};
    return ::stat(path.c_str(), &status) == 0 &&
        (status.st_mode & S_IFMT) == type;
}

bool shellIsListed(
    const std::filesystem::path& shellsPath,
    const std::string& shell) {
    struct stat status {};
    if (::lstat(shellsPath.c_str(), &status) != 0) return errno == ENOENT;
    if (!S_ISREG(status.st_mode)) return false;
    std::ifstream stream(shellsPath);
    if (!stream.is_open()) return false;
    std::string line;
    while (std::getline(stream, line)) {
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        const std::size_t first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos) continue;
        const std::size_t last = line.find_last_not_of(" \t\r");
        if (line.substr(first, last - first + 1) == shell) return true;
    }
    return false;
}

std::string trimCopy(std::string value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseLogicalGroupList(
    const std::string& value,
    std::vector<std::string>& groups) {
    groups.clear();
    if (value.empty()) return true;
    std::set<std::string> unique;
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find(',', start);
        const std::string group = trimCopy(value.substr(
            start, end == std::string::npos ? std::string::npos : end - start));
        if (!fic::identity::isValidLocalGroupName(group) ||
            !unique.insert(group).second) {
            return false;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    groups.assign(unique.begin(), unique.end());
    return true;
}

bool parseNativeGroupList(
    const std::string& value,
    char delimiter,
    std::vector<std::string>& groups) {
    if (value.empty()) return false;
    std::string logical;
    if (delimiter == ' ') {
        std::istringstream input(value);
        std::string group;
        while (input >> group) {
            if (!logical.empty()) logical += ',';
            logical += group;
        }
    } else {
        logical = value;
    }
    if (logical.find_first_of(" \t\r\n") != std::string::npos) return false;
    return parseLogicalGroupList(logical, groups) && !groups.empty();
}

std::string joinGroups(
    const std::vector<std::string>& groups,
    char delimiter) {
    std::string result;
    for (std::size_t i = 0; i < groups.size(); ++i) {
        if (i != 0) result += delimiter;
        result += groups[i];
    }
    return result;
}

} // namespace

GroupListPolicyTypeValue::GroupListPolicyTypeValue() {
    defaultValue = "[]";
}

PolicyEditorSpec GroupListPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "textedit";
    spec.textDelimiter = ",";
    return spec;
}

bool GroupListPolicyTypeValue::validate(const std::string& value) {
    std::vector<std::string> groups;
    return parseLogicalGroupList(value, groups);
}

std::string GroupListPolicyTypeValue::getPolicyRestrictionInfo() {
    return "comma-separated unique local group names; empty list is allowed";
}

std::string GroupListPolicyTypeValue::postProcessingValue(
    const std::string& value) {
    std::vector<std::string> groups;
    if (!parseLogicalGroupList(value, groups)) return {};
    return json(groups).dump();
}

std::string GroupListPolicyTypeValue::reverse_postProcessingValue(
    const std::string& value) {
    const json stored = json::parse(value);
    if (!stored.is_array()) {
        throw std::runtime_error("Expected a JSON array of group names");
    }
    std::vector<std::string> groups;
    for (const auto& item : stored) groups.push_back(item.get<std::string>());
    return joinGroups(groups, ',');
}

UserCreationOptionPolicy::UserCreationOptionPolicy(
    const std::string& policyName,
    const std::string& key,
    Backend backend,
    Semantic semantic,
    fic::platform::UserCreationPlatformConfig platform,
    std::unique_ptr<PolicyTypeValue> valueType,
    AtomicWriteOptions options)
    : IdentityAccessPolicy(kSubmodule), key_(key), backend_(backend),
      semantic_(semantic), platform_(std::move(platform)),
      writeOptions_(std::move(options)) {
    writeOptions_.createIfMissing = false;
    writeOptions_.rejectSymlink = true;
    this->policyName = policyName;
    this->policyTypeValue = std::move(valueType);
}

bool UserCreationOptionPolicy::validateNativeValue(
    const std::string& value) const {
    switch (semantic_) {
    case Semantic::Directory:
        return isNormalizedAbsolutePath(value) && lstatType(value, S_IFDIR);
    case Semantic::Shell:
        return isNormalizedAbsolutePath(value) && statType(value, S_IFREG) &&
            ::access(value.c_str(), X_OK) == 0 &&
            (!platform_.requireListedShellWhenShellsFileExists ||
             shellIsListed(platform_.shellsPath, value));
    case Semantic::Boolean:
        return value == "yes" || value == "no";
    case Semantic::Group:
        return fic::identity::isValidLocalGroupName(value) &&
            fic::identity::localGroupExistsExactlyOnce(
                platform_.groupPath, value);
    }
    return false;
}

bool UserCreationOptionPolicy::applyUseraddDefault(const std::string& value) {
    FileHandlerOptions options;
    options.writeOptions = writeOptions_;
    fic::identity::UseraddDefaultsFileHandler file(
        platform_.useraddDefaultsPath.string(), options);
    if (!file.loadConfig()) return false;
    const auto current = file.lookup(key_);
    if (current.state == fic::identity::UseraddDefaultsValueState::Duplicate ||
        current.state == fic::identity::UseraddDefaultsValueState::Malformed) {
        log("Ambiguous useradd defaults parameter: " + key_, logLevel::ERROR);
        return false;
    }
    if (current.state == fic::identity::UseraddDefaultsValueState::Unique &&
        current.value == value) return true;
    if (!file.setValue(key_, value) || !file.saveAndReload()) return false;
    const auto after = file.lookup(key_);
    return after.state == fic::identity::UseraddDefaultsValueState::Unique &&
        after.value == value;
}

bool UserCreationOptionPolicy::applyLoginDefsDefault(const std::string& value) {
    FileHandlerOptions options;
    options.writeOptions = writeOptions_;
    fic::identity::LoginDefsFileHandler file(
        platform_.loginDefsPath.string(), options);
    if (!file.loadConfig()) return false;
    const auto current = file.lookup(key_);
    if (current.state == fic::identity::LoginDefsValueState::Duplicate ||
        current.state == fic::identity::LoginDefsValueState::Malformed) {
        log("Ambiguous login.defs parameter: " + key_, logLevel::ERROR);
        return false;
    }
    if (current.state == fic::identity::LoginDefsValueState::Unique &&
        current.value == value) return true;
    if (!file.setValue(key_, value) || !file.saveAndReload()) return false;
    const auto after = file.lookup(key_);
    return after.state == fic::identity::LoginDefsValueState::Unique &&
        after.value == value;
}

bool UserCreationOptionPolicy::apply() {
    const auto expected = getValue();
    if (!expected.has_value()) return false;
    if (platform_.provider !=
        fic::platform::UserCreationProviderKind::ShadowUseradd) {
        log("Unsupported user creation provider", logLevel::ERROR);
        return false;
    }
    const std::lock_guard<std::mutex> lock(configurationMutex());
    if (!validateNativeValue(*expected)) {
        log("Unsafe or unavailable user creation value for " + policyName,
            logLevel::ERROR);
        return false;
    }
    return backend_ == Backend::UseraddDefaults
        ? applyUseraddDefault(*expected)
        : applyLoginDefsDefault(*expected);
}

UserHomeBaseDirectoryPolicy::UserHomeBaseDirectoryPolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : UserCreationOptionPolicy(
          "user_home_base_directory", "HOME", Backend::UseraddDefaults,
          Semantic::Directory, platform,
          std::make_unique<PathPolicyTypeValue>(
              platform.policyDefaults.homeBaseDirectory),
          std::move(options)) {}

UserCreateHomePolicy::UserCreateHomePolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : UserCreationOptionPolicy(
          "user_create_home", "CREATE_HOME", Backend::LoginDefs,
          Semantic::Boolean, platform,
          std::make_unique<PossibleListPolicyTypeValue>(
              std::vector<std::string>{
                  platform.policyDefaults.createHome,
                  platform.policyDefaults.createHome == "yes" ? "no" : "yes"}),
          std::move(options)) {}

UserSkeletonDirectoryPolicy::UserSkeletonDirectoryPolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : UserCreationOptionPolicy(
          "user_skeleton_directory", "SKEL", Backend::UseraddDefaults,
          Semantic::Directory, platform,
          std::make_unique<PathPolicyTypeValue>(
              platform.policyDefaults.skeletonDirectory),
          std::move(options)) {}

UserDefaultShellPolicy::UserDefaultShellPolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : UserCreationOptionPolicy(
          "user_default_shell", "SHELL", Backend::UseraddDefaults,
          Semantic::Shell, platform,
          std::make_unique<PathPolicyTypeValue>(platform.policyDefaults.defaultShell),
          std::move(options)) {}

UserCreatePrivateGroupPolicy::UserCreatePrivateGroupPolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : UserCreationOptionPolicy(
          "user_create_private_group", "USERGROUPS_ENAB", Backend::LoginDefs,
          Semantic::Boolean, platform,
          std::make_unique<PossibleListPolicyTypeValue>(
              std::vector<std::string>{
                  platform.policyDefaults.createPrivateGroup,
                  platform.policyDefaults.createPrivateGroup == "yes" ? "no" : "yes"}),
          std::move(options)) {}

UserDefaultPrimaryGroupPolicy::UserDefaultPrimaryGroupPolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : UserCreationOptionPolicy(
          "user_default_primary_group", "GROUP", Backend::UseraddDefaults,
          Semantic::Group, platform,
          std::make_unique<GroupNamePolicyTypeValue>(
              platform.policyDefaults.defaultPrimaryGroup),
          std::move(options)) {}

UserDefaultSupplementaryGroupsPolicy::UserDefaultSupplementaryGroupsPolicy(
    fic::platform::UserCreationPlatformConfig platform,
    AtomicWriteOptions options)
    : IdentityAccessPolicy(kSubmodule), platform_(std::move(platform)),
      writeOptions_(std::move(options)) {
    writeOptions_.createIfMissing = false;
    writeOptions_.rejectSymlink = true;
    policyName = "user_default_supplementary_groups";
    policyTypeValue = std::make_unique<GroupListPolicyTypeValue>();
}

bool UserDefaultSupplementaryGroupsPolicy::applyShadowUseraddDefaults(
    const std::vector<std::string>& groups) {
    FileHandlerOptions options;
    options.writeOptions = writeOptions_;
    fic::identity::UseraddDefaultsFileHandler file(
        platform_.useraddDefaultsPath.string(), options);
    if (!file.loadConfig()) return false;
    const auto current = file.lookup("GROUPS");
    if (current.state == fic::identity::UseraddDefaultsValueState::Duplicate ||
        current.state == fic::identity::UseraddDefaultsValueState::Malformed) {
        log("Ambiguous useradd defaults parameter: GROUPS", logLevel::ERROR);
        return false;
    }
    if (groups.empty()) {
        if (current.state == fic::identity::UseraddDefaultsValueState::Missing) {
            return true;
        }
        if (!file.removeValue("GROUPS") || !file.saveAndReload()) return false;
        return file.lookup("GROUPS").state ==
            fic::identity::UseraddDefaultsValueState::Missing;
    }

    if (current.state == fic::identity::UseraddDefaultsValueState::Unique) {
        std::vector<std::string> actual;
        if (!parseNativeGroupList(current.value, ',', actual)) {
            log("Invalid native GROUPS value", logLevel::ERROR);
            return false;
        }
        if (actual == groups) return true;
    }
    const std::string expected = joinGroups(groups, ',');
    if (!file.setValue("GROUPS", expected) || !file.saveAndReload()) return false;
    const auto after = file.lookup("GROUPS");
    if (after.state != fic::identity::UseraddDefaultsValueState::Unique) {
        return false;
    }
    std::vector<std::string> actual;
    return parseNativeGroupList(after.value, ',', actual) && actual == groups;
}

bool UserDefaultSupplementaryGroupsPolicy::applyDebianAdduser(
    const std::vector<std::string>& groups) {
    FileHandlerOptions options;
    options.writeOptions = writeOptions_;
    fic::identity::AdduserConfigFileHandler file(
        platform_.adduserConfigPath.string(), options);
    if (!file.loadConfig()) return false;
    const auto enabled = file.lookup("ADD_EXTRA_GROUPS");
    const auto nativeGroups = file.lookup("EXTRA_GROUPS");
    const auto ambiguous = [](fic::identity::AdduserConfigValueState state) {
        return state == fic::identity::AdduserConfigValueState::Duplicate ||
            state == fic::identity::AdduserConfigValueState::Malformed;
    };
    if (ambiguous(enabled.state) || ambiguous(nativeGroups.state)) {
        log("Ambiguous adduser supplementary-groups configuration",
            logLevel::ERROR);
        return false;
    }

    bool currentEnabled = false;
    if (enabled.state == fic::identity::AdduserConfigValueState::Unique) {
        if (enabled.value.empty()) return false;
        currentEnabled = enabled.value != "0";
    }
    std::vector<std::string> actual;
    if (nativeGroups.state == fic::identity::AdduserConfigValueState::Unique &&
        !nativeGroups.value.empty() &&
        !parseNativeGroupList(nativeGroups.value, ' ', actual)) {
        log("Invalid native EXTRA_GROUPS value", logLevel::ERROR);
        return false;
    }
    if (groups.empty() &&
        enabled.state == fic::identity::AdduserConfigValueState::Unique &&
        !currentEnabled) {
        return true;
    }
    if (!groups.empty() && currentEnabled && actual == groups) return true;

    if (!file.setSupplementaryGroups(!groups.empty(), groups) ||
        !file.saveAndReload()) {
        return false;
    }
    const auto afterEnabled = file.lookup("ADD_EXTRA_GROUPS");
    if (afterEnabled.state != fic::identity::AdduserConfigValueState::Unique ||
        afterEnabled.value != (groups.empty() ? "0" : "1")) {
        return false;
    }
    if (groups.empty()) return true;
    const auto afterGroups = file.lookup("EXTRA_GROUPS");
    actual.clear();
    return afterGroups.state == fic::identity::AdduserConfigValueState::Unique &&
        parseNativeGroupList(afterGroups.value, ' ', actual) && actual == groups;
}

bool UserDefaultSupplementaryGroupsPolicy::apply() {
    if (platform_.supplementaryGroupsProvider ==
        fic::platform::UserSupplementaryGroupsProviderKind::Unsupported) {
        log("Default supplementary groups are unsupported by this platform provider",
            logLevel::ERROR);
        return false;
    }
    std::optional<std::string> expected;
    try {
        expected = getValue();
    } catch (const std::exception& error) {
        log("Invalid serialized supplementary group list: " +
                std::string(error.what()),
            logLevel::ERROR);
        return false;
    }
    if (!expected.has_value()) return false;
    std::vector<std::string> groups;
    if (!parseLogicalGroupList(*expected, groups)) return false;

    const std::lock_guard<std::mutex> lock(configurationMutex());
    for (const std::string& group : groups) {
        if (!fic::identity::localGroupExistsExactlyOnce(
                platform_.groupPath, group)) {
            log("Unavailable local supplementary group: " + group,
                logLevel::ERROR);
            return false;
        }
    }
    if (platform_.supplementaryGroupsProvider ==
        fic::platform::UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults) {
        return applyShadowUseraddDefaults(groups);
    }
    if (platform_.supplementaryGroupsProvider ==
        fic::platform::UserSupplementaryGroupsProviderKind::DebianAdduser) {
        return applyDebianAdduser(groups);
    }
    return false;
}
