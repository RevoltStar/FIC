#include "modules/identity_access/submodules/user_creation/UserCreationPolicies.h"

#include "modules/identity_access/configuration/LoginDefsFileHandler.h"
#include "modules/identity_access/configuration/UseraddDefaultsFileHandler.h"

#include <cerrno>
#include <cctype>
#include <fstream>
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

bool isValidGroupName(const std::string& value) {
    if (value.empty() || value.size() > 32 ||
        std::isdigit(static_cast<unsigned char>(value.front())) != 0 ||
        (std::isalpha(static_cast<unsigned char>(value.front())) == 0 &&
         value.front() != '_')) {
        return false;
    }
    for (std::size_t i = 1; i < value.size(); ++i) {
        const char character = value[i];
        if (std::isalnum(static_cast<unsigned char>(character)) != 0 ||
            character == '_' || character == '-') {
            continue;
        }
        if (character == '$' && i + 1 == value.size()) continue;
        return false;
    }
    return true;
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
        return isValidGroupName(value);
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

bool localGroupExists(
    const std::filesystem::path& path,
    const std::string& expected) {
    if (!lstatType(path, S_IFREG)) return false;
    std::ifstream stream(path);
    if (!stream.is_open()) return false;
    std::size_t matches = 0;
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        std::size_t first = line.find(':');
        std::size_t second = first == std::string::npos
            ? std::string::npos : line.find(':', first + 1);
        std::size_t third = second == std::string::npos
            ? std::string::npos : line.find(':', second + 1);
        if (first == std::string::npos || second == std::string::npos ||
            third == std::string::npos || line.find(':', third + 1) !=
                std::string::npos) {
            return false;
        }
        const std::string name = line.substr(0, first);
        const std::string gid = line.substr(second + 1, third - second - 1);
        if (!isValidGroupName(name) || gid.empty()) return false;
        for (char character : gid) {
            if (std::isdigit(static_cast<unsigned char>(character)) == 0) {
                return false;
            }
        }
        if (name == expected) ++matches;
    }
    return stream.eof() && matches == 1;
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

} // namespace

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
        return isValidGroupName(value) &&
            localGroupExists(platform_.groupPath, value);
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
