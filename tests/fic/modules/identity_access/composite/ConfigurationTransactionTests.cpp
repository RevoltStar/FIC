#include "modules/identity_access/composite/ConfigurationTransaction.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using fic::identity::ConfigurationStepResult;
using fic::identity::ConfigurationTransaction;
using fic::identity::PreparedConfigurationChange;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FakeChange final : public PreparedConfigurationChange {
public:
    FakeChange(std::string identifier,
               std::vector<std::string>& events,
               bool commitNeeded = true,
               bool activationNeeded = true)
        : identifier_(std::move(identifier)),
          events_(events),
          commitNeeded_(commitNeeded),
          activationNeeded_(activationNeeded) {
    }

    std::string failStep;
    std::string unchangedStep;
    std::string throwStep;
    std::string recoveryFailStep;
    std::string recoveryThrowStep;

    std::string id() const override {
        return identifier_;
    }

    bool needsCommit() const noexcept override {
        return commitNeeded_;
    }

    bool needsActivation() const noexcept override {
        return activationNeeded_;
    }

    ConfigurationStepResult commitPersistent() override {
        return run("commit");
    }

    ConfigurationStepResult verifyPersistent() override {
        return run("verify-persistent");
    }

    ConfigurationStepResult activate() override {
        return run("activate");
    }

    ConfigurationStepResult verifyEffective() override {
        return run("verify-effective");
    }

    ConfigurationStepResult rollbackPersistent() override {
        return runRecovery("rollback-persistent");
    }

    ConfigurationStepResult restoreRuntimeAfterRollback() override {
        return runRecovery("restore-runtime");
    }

    ConfigurationStepResult verifyRollback() override {
        return runRecovery("verify-rollback");
    }

private:
    ConfigurationStepResult run(const std::string& step) {
        events_.push_back(identifier_ + ":" + step);
        if (throwStep == step) {
            throw std::runtime_error("injected exception");
        }
        if (failStep == step) {
            return ConfigurationStepResult::failure("injected failure");
        }
        if (unchangedStep == step) {
            return ConfigurationStepResult::success(false);
        }
        return ConfigurationStepResult::success(true);
    }

    ConfigurationStepResult runRecovery(const std::string& step) {
        events_.push_back(identifier_ + ":" + step);
        if (recoveryThrowStep == step) {
            throw std::runtime_error("injected recovery exception");
        }
        if (recoveryFailStep == step) {
            return ConfigurationStepResult::failure(
                "injected recovery failure");
        }
        return ConfigurationStepResult::success(true);
    }

    std::string identifier_;
    std::vector<std::string>& events_;
    bool commitNeeded_;
    bool activationNeeded_;
};

using Changes =
    std::vector<std::unique_ptr<PreparedConfigurationChange>>;

FakeChange& addChange(Changes& changes,
                      std::vector<std::string>& events,
                      const std::string& id,
                      bool commitNeeded = true,
                      bool activationNeeded = true) {
    auto change = std::make_unique<FakeChange>(
        id, events, commitNeeded, activationNeeded);
    FakeChange& reference = *change;
    changes.push_back(std::move(change));
    return reference;
}

void requireEvents(const std::vector<std::string>& actual,
                   const std::vector<std::string>& expected,
                   const std::string& message) {
    require(actual == expected, message);
}

void testSuccessfulTransaction() {
    std::vector<std::string> events;
    Changes changes;
    addChange(changes, events, "kerberos");
    addChange(changes, events, "sssd");

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(result.ok, result.error);
    require(result.recoveryErrors.empty(), "successful transaction recovered");
    requireEvents(
        events,
        {
            "kerberos:commit", "sssd:commit",
            "kerberos:verify-persistent", "sssd:verify-persistent",
            "kerberos:activate", "sssd:activate",
            "kerberos:verify-effective", "sssd:verify-effective"
        },
        "successful transaction order is incorrect");
}

void testCommitFailureRollsBackInReverseOrder() {
    std::vector<std::string> events;
    Changes changes;
    addChange(changes, events, "kerberos");
    FakeChange& sssd = addChange(changes, events, "sssd");
    sssd.failStep = "commit";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "commit failure must fail the transaction");
    requireEvents(
        events,
        {
            "kerberos:commit", "sssd:commit",
            "sssd:rollback-persistent", "kerberos:rollback-persistent",
            "sssd:verify-rollback", "kerberos:verify-rollback"
        },
        "commit rollback order is incorrect");
}

void testUnchangedCommitIsNotRolledBack() {
    std::vector<std::string> events;
    Changes changes;
    FakeChange& kerberos = addChange(changes, events, "kerberos");
    kerberos.unchangedStep = "commit";
    FakeChange& sssd = addChange(changes, events, "sssd");
    sssd.failStep = "commit";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "commit failure must fail the transaction");
    requireEvents(
        events,
        {
            "kerberos:commit", "sssd:commit",
            "sssd:rollback-persistent", "sssd:verify-rollback"
        },
        "unchanged persistent state must not be overwritten by recovery");
}

void testPersistentVerificationFailureRollsBackAllCommits() {
    std::vector<std::string> events;
    Changes changes;
    addChange(changes, events, "kerberos");
    FakeChange& sssd = addChange(changes, events, "sssd");
    sssd.failStep = "verify-persistent";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "persistent verification failure must fail");
    requireEvents(
        events,
        {
            "kerberos:commit", "sssd:commit",
            "kerberos:verify-persistent", "sssd:verify-persistent",
            "sssd:rollback-persistent", "kerberos:rollback-persistent",
            "sssd:verify-rollback", "kerberos:verify-rollback"
        },
        "persistent verification rollback order is incorrect");
}

void testActivationFailureRestoresPersistentAndRuntimeState() {
    std::vector<std::string> events;
    Changes changes;
    addChange(changes, events, "kerberos");
    FakeChange& sssd = addChange(changes, events, "sssd");
    sssd.failStep = "activate";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "activation failure must fail the transaction");
    requireEvents(
        events,
        {
            "kerberos:commit", "sssd:commit",
            "kerberos:verify-persistent", "sssd:verify-persistent",
            "kerberos:activate", "sssd:activate",
            "sssd:rollback-persistent", "kerberos:rollback-persistent",
            "sssd:restore-runtime", "kerberos:restore-runtime",
            "sssd:verify-rollback", "kerberos:verify-rollback"
        },
        "activation recovery order is incorrect");
}

void testEffectiveVerificationFailureRestoresAllChangedState() {
    std::vector<std::string> events;
    Changes changes;
    addChange(changes, events, "kerberos");
    FakeChange& sssd = addChange(changes, events, "sssd");
    sssd.failStep = "verify-effective";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "effective verification failure must fail");
    requireEvents(
        events,
        {
            "kerberos:commit", "sssd:commit",
            "kerberos:verify-persistent", "sssd:verify-persistent",
            "kerberos:activate", "sssd:activate",
            "kerberos:verify-effective", "sssd:verify-effective",
            "sssd:rollback-persistent", "kerberos:rollback-persistent",
            "sssd:restore-runtime", "kerberos:restore-runtime",
            "sssd:verify-rollback", "kerberos:verify-rollback"
        },
        "effective verification recovery is incomplete");
}

void testRuntimeOnlyFailureIsVerifiedAfterRecovery() {
    std::vector<std::string> events;
    Changes changes;
    FakeChange& kerberos = addChange(
        changes, events, "kerberos", false, true);
    kerberos.failStep = "activate";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "runtime-only activation failure must fail");
    requireEvents(
        events,
        {
            "kerberos:verify-persistent", "kerberos:activate",
            "kerberos:restore-runtime", "kerberos:verify-rollback"
        },
        "runtime-only recovery is incomplete");
}

void testUnchangedActivationIsNotRestored() {
    std::vector<std::string> events;
    Changes changes;
    FakeChange& kerberos = addChange(changes, events, "kerberos", false, true);
    kerberos.unchangedStep = "activate";
    FakeChange& sssd = addChange(changes, events, "sssd", false, true);
    sssd.failStep = "activate";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "activation failure must fail the transaction");
    requireEvents(
        events,
        {
            "kerberos:verify-persistent", "sssd:verify-persistent",
            "kerberos:activate", "sssd:activate",
            "sssd:restore-runtime", "sssd:verify-rollback"
        },
        "unchanged runtime state must not be restored during recovery");
}

void testNoOpStillVerifiesPostconditions() {
    std::vector<std::string> events;
    Changes changes;
    addChange(changes, events, "nss", false, false);

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(result.ok, result.error);
    requireEvents(
        events,
        {"nss:verify-persistent", "nss:verify-effective"},
        "no-op transaction must only verify postconditions");
}

void testRecoveryFailuresAreReported() {
    std::vector<std::string> events;
    Changes changes;
    FakeChange& kerberos = addChange(changes, events, "kerberos");
    kerberos.failStep = "verify-persistent";
    kerberos.recoveryFailStep = "rollback-persistent";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "primary failure must be preserved");
    require(
        result.recoveryErrors.size() == 1,
        "rollback failure must be reported separately");
    require(
        result.recoveryErrors.front().find("persistent rollback") !=
            std::string::npos,
        "rollback failure diagnostic is incomplete");
}

void testStepAndRecoveryExceptionsAreContained() {
    std::vector<std::string> events;
    Changes changes;
    FakeChange& kerberos = addChange(changes, events, "kerberos");
    kerberos.throwStep = "verify-persistent";
    kerberos.recoveryThrowStep = "rollback-persistent";

    const auto result = ConfigurationTransaction::execute(std::move(changes));
    require(!result.ok, "step exception must fail the transaction");
    require(
        result.error.find("threw an exception") != std::string::npos,
        "primary exception diagnostic is missing");
    require(
        result.recoveryErrors.size() == 1 &&
            result.recoveryErrors.front().find("threw an exception") !=
                std::string::npos,
        "recovery exception must be contained and reported");
}

void testInvalidChangeSetsFailBeforeMutation() {
    std::vector<std::string> events;
    Changes duplicateChanges;
    addChange(duplicateChanges, events, "pam");
    addChange(duplicateChanges, events, "pam");
    const auto duplicateResult =
        ConfigurationTransaction::execute(std::move(duplicateChanges));
    require(!duplicateResult.ok, "duplicate change IDs must fail");
    require(events.empty(), "invalid transaction must not mutate state");

    Changes emptyChanges;
    const auto emptyResult =
        ConfigurationTransaction::execute(std::move(emptyChanges));
    require(!emptyResult.ok, "empty transaction must fail");
}

} // namespace

int main() {
    try {
        testSuccessfulTransaction();
        testCommitFailureRollsBackInReverseOrder();
        testUnchangedCommitIsNotRolledBack();
        testPersistentVerificationFailureRollsBackAllCommits();
        testActivationFailureRestoresPersistentAndRuntimeState();
        testEffectiveVerificationFailureRestoresAllChangedState();
        testRuntimeOnlyFailureIsVerifiedAfterRecovery();
        testUnchangedActivationIsNotRestored();
        testNoOpStillVerifiesPostconditions();
        testRecoveryFailuresAreReported();
        testStepAndRecoveryExceptionsAreContained();
        testInvalidChangeSetsFailBeforeMutation();
    } catch (const std::exception& error) {
        std::cerr << "ConfigurationTransactionTests failed: "
                  << error.what() << '\n';
        return 1;
    }

    std::cout << "ConfigurationTransactionTests passed\n";
    return 0;
}
