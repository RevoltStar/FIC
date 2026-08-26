#ifndef FIC_IDENTITY_ACCESS_CONFIGURATION_TRANSACTION_H
#define FIC_IDENTITY_ACCESS_CONFIGURATION_TRANSACTION_H

#include <memory>
#include <string>
#include <vector>

namespace fic::identity {

struct ConfigurationStepResult {
    bool ok = false;
    bool changed = false;
    std::string message;

    static ConfigurationStepResult success(bool changed = false);
    static ConfigurationStepResult failure(std::string message);
};

// A prepared change owns the original snapshot and the fully validated
// candidate. Preparing every participant must finish before the transaction is
// executed. Implementations must make rollback methods safe after a partially
// completed commit or activation attempt. commitPersistent() must compare the
// target with its prepared snapshot immediately before writing and fail on an
// external edit. rollbackPersistent() must likewise avoid overwriting an
// external edit made after commit; it reports a recovery failure instead. The
// shared daemon mutex cannot protect against administrators or package tools.
class PreparedConfigurationChange {
public:
    virtual ~PreparedConfigurationChange() = default;

    virtual std::string id() const = 0;
    virtual bool needsCommit() const noexcept = 0;
    virtual bool needsActivation() const noexcept = 0;

    virtual ConfigurationStepResult commitPersistent() = 0;
    virtual ConfigurationStepResult verifyPersistent() = 0;
    virtual ConfigurationStepResult activate() = 0;
    virtual ConfigurationStepResult verifyEffective() = 0;

    virtual ConfigurationStepResult rollbackPersistent() = 0;
    virtual ConfigurationStepResult restoreRuntimeAfterRollback() = 0;
    virtual ConfigurationStepResult verifyRollback() = 0;
};

struct ConfigurationTransactionResult {
    bool ok = false;
    std::string error;
    std::vector<std::string> recoveryErrors;
};

class ConfigurationTransaction {
public:
    static ConfigurationTransactionResult execute(
        std::vector<std::unique_ptr<PreparedConfigurationChange>> changes);
};

} // namespace fic::identity

#endif // FIC_IDENTITY_ACCESS_CONFIGURATION_TRANSACTION_H
