#ifndef FIC_IDENTITY_USER_CREATION_POLICIES_H
#define FIC_IDENTITY_USER_CREATION_POLICIES_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "platform/PlatformProfile.h"

#include <fic/core/AtomicFileWriter.h>

#include <memory>
#include <string>

class UserCreationOptionPolicy : public IdentityAccessPolicy {
public:
    bool apply() override;

protected:
    enum class Backend { UseraddDefaults, LoginDefs };
    enum class Semantic { Directory, Shell, Boolean, Group };

    UserCreationOptionPolicy(
        const std::string& policyName,
        const std::string& key,
        Backend backend,
        Semantic semantic,
        fic::platform::UserCreationPlatformConfig platform,
        std::unique_ptr<PolicyTypeValue> valueType,
        AtomicWriteOptions options = {});

private:
    bool validateNativeValue(const std::string& value) const;
    bool applyUseraddDefault(const std::string& value);
    bool applyLoginDefsDefault(const std::string& value);

    std::string key_;
    Backend backend_;
    Semantic semantic_;
    fic::platform::UserCreationPlatformConfig platform_;
    AtomicWriteOptions writeOptions_;
};

class UserHomeBaseDirectoryPolicy final : public UserCreationOptionPolicy {
public:
    explicit UserHomeBaseDirectoryPolicy(
        fic::platform::UserCreationPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class UserCreateHomePolicy final : public UserCreationOptionPolicy {
public:
    explicit UserCreateHomePolicy(
        fic::platform::UserCreationPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class UserSkeletonDirectoryPolicy final : public UserCreationOptionPolicy {
public:
    explicit UserSkeletonDirectoryPolicy(
        fic::platform::UserCreationPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class UserDefaultShellPolicy final : public UserCreationOptionPolicy {
public:
    explicit UserDefaultShellPolicy(
        fic::platform::UserCreationPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class UserCreatePrivateGroupPolicy final : public UserCreationOptionPolicy {
public:
    explicit UserCreatePrivateGroupPolicy(
        fic::platform::UserCreationPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class UserDefaultPrimaryGroupPolicy final : public UserCreationOptionPolicy {
public:
    explicit UserDefaultPrimaryGroupPolicy(
        fic::platform::UserCreationPlatformConfig platform,
        AtomicWriteOptions options = {});
};

#endif
