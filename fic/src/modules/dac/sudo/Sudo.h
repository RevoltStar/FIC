#ifndef SUDOEDIT_H
#define SUDOEDIT_H

#include "modules/dac/DAC.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "modules/dac/sudo/SudoProviderCapabilities.h"

#include <memory>
#include <string>
#include <utility>

class SudoersParam {
public:
    SudoersParam(std::string sectionName, size_t lineNumber)
        : sectionName_(std::move(sectionName)), lineNumber_(lineNumber) {}
    virtual ~SudoersParam() = default;

    virtual std::string getParamString() const = 0;
    virtual std::string getType() const { return sectionName_; }
    size_t getLineNumber() const { return lineNumber_; }

protected:
    std::string sectionName_;
    size_t lineNumber_;
};

class SingleDefaultsSudoersParam : public SudoersParam {
public:
    SingleDefaultsSudoersParam(std::string sectionName,
                               std::string group,
                               std::string scope,
                               std::string key,
                               size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber),
          group_(std::move(group)),
          scope_(std::move(scope)),
          key_(std::move(key)) {}

    std::string getParamString() const override;
    const std::string& getKey() const { return key_; }
    const std::string& getGroup() const { return group_; }
    const std::string& getScope() const { return scope_; }

private:
    std::string group_;
    std::string scope_;
    std::string key_;
};

class KeyValueDefaultsSudoersParam : public SudoersParam {
public:
    KeyValueDefaultsSudoersParam(std::string sectionName,
                                 std::string group,
                                 std::string scope,
                                 std::string key,
                                 std::string operation,
                                 std::string value,
                                 size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber),
          group_(std::move(group)),
          scope_(std::move(scope)),
          key_(std::move(key)),
          operation_(std::move(operation)),
          value_(std::move(value)) {}

    std::string getParamString() const override;
    const std::string& getKey() const { return key_; }
    const std::string& getValue() const { return value_; }
    const std::string& getGroup() const { return group_; }
    const std::string& getScope() const { return scope_; }
    const std::string& getOperator() const { return operation_; }

private:
    std::string group_;
    std::string scope_;
    std::string key_;
    std::string operation_;
    std::string value_;
};

class Sudo : public DAC {
protected:
    std::unique_ptr<SudoersParam> sudoParameter;
    fic::platform::SudoPlatformConfig platformConfig_;
    const fic::platform::PlatformExecutableResolver& executables_;

    bool applyRequireAuthentication();
    bool verifyProviderWitness(const fic::sudoers::SudoProviderCapabilities& current,
                               std::string& error) const;
    mutable std::mutex capabilityMutex_;
    mutable std::optional<fic::sudoers::SudoProviderCapabilities> dependencyProvider_;

public:
    Sudo(fic::platform::SudoPlatformConfig platformConfig,
         const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
    bool supportsDependencyCapability(const std::string& name) const override {
        return name == "exempt_group";
    }
    bool requiresDependencyCapability(const std::string& name) const override;
    ~Sudo() override;

    // Managed resource identifier for the rollback system (the sudoers
    // Defaults key), empty when the parameter type has no managed key.
    std::string managedResource() const {
        if (!sudoParameter) {
            return {};
        }
        if (const auto* keyValue = dynamic_cast<const KeyValueDefaultsSudoersParam*>(
                sudoParameter.get())) {
            return keyValue->getKey();
        }
        if (const auto* single = dynamic_cast<const SingleDefaultsSudoersParam*>(
                sudoParameter.get())) {
            return single->getKey();
        }
        return {};
    }
};

#endif // SUDOEDIT_H
