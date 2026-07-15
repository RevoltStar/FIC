#ifndef SUDOEDIT_H
#define SUDOEDIT_H

#include "modules/dac/DAC.h"

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

    bool applyRequireAuthentication();

public:
    Sudo();
    bool apply() override;
    ~Sudo() override;
};

#endif // SUDOEDIT_H
