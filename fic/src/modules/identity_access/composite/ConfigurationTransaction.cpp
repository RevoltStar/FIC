#include "modules/identity_access/composite/ConfigurationTransaction.h"

#include <algorithm>
#include <exception>
#include <set>
#include <utility>

namespace fic::identity {
namespace {

std::string stepError(const std::string& id,
                      const std::string& step,
                      const ConfigurationStepResult& result) {
    std::string message = id + ": " + step + " failed";
    if (!result.message.empty()) {
        message += ": " + result.message;
    }
    return message;
}

template <typename Callback>
ConfigurationStepResult invokeStep(Callback&& callback,
                                   const std::string& id,
                                   const std::string& step) {
    try {
        return callback();
    } catch (const std::exception& error) {
        return ConfigurationStepResult::failure(
            id + ": " + step + " threw an exception: " + error.what());
    } catch (...) {
        return ConfigurationStepResult::failure(
            id + ": " + step + " threw an unknown exception");
    }
}

void recordRecoveryFailure(ConfigurationTransactionResult& result,
                           const std::string& id,
                           const std::string& step,
                           const ConfigurationStepResult& recovery) {
    if (!recovery.ok) {
        result.recoveryErrors.push_back(stepError(id, step, recovery));
    }
}

void recover(
    std::vector<std::unique_ptr<PreparedConfigurationChange>>& changes,
    const std::vector<std::string>& identifiers,
    const std::vector<std::size_t>& persistentRecovery,
    const std::vector<std::size_t>& runtimeRecovery,
    ConfigurationTransactionResult& result) {
    for (auto iterator = persistentRecovery.rbegin();
         iterator != persistentRecovery.rend(); ++iterator) {
        auto& change = *changes[*iterator];
        const std::string& id = identifiers[*iterator];
        const auto rollback = invokeStep(
            [&change]() { return change.rollbackPersistent(); },
            id,
            "persistent rollback");
        recordRecoveryFailure(
            result, id, "persistent rollback", rollback);
    }

    for (auto iterator = runtimeRecovery.rbegin();
         iterator != runtimeRecovery.rend(); ++iterator) {
        auto& change = *changes[*iterator];
        const std::string& id = identifiers[*iterator];
        const auto restore = invokeStep(
            [&change]() { return change.restoreRuntimeAfterRollback(); },
            id,
            "runtime restoration");
        recordRecoveryFailure(
            result, id, "runtime restoration", restore);
    }

    std::vector<std::size_t> recoveryParticipants = persistentRecovery;
    for (const std::size_t index : runtimeRecovery) {
        if (std::find(
                recoveryParticipants.begin(),
                recoveryParticipants.end(),
                index) == recoveryParticipants.end()) {
            recoveryParticipants.push_back(index);
        }
    }
    for (auto iterator = recoveryParticipants.rbegin();
         iterator != recoveryParticipants.rend(); ++iterator) {
        auto& change = *changes[*iterator];
        const std::string& id = identifiers[*iterator];
        const auto verification = invokeStep(
            [&change]() { return change.verifyRollback(); },
            id,
            "rollback verification");
        recordRecoveryFailure(
            result, id, "rollback verification", verification);
    }
}

} // namespace

ConfigurationStepResult ConfigurationStepResult::success(bool changed) {
    return {true, changed, {}};
}

ConfigurationStepResult ConfigurationStepResult::failure(std::string message) {
    return {false, false, std::move(message)};
}

ConfigurationTransactionResult ConfigurationTransaction::execute(
    std::vector<std::unique_ptr<PreparedConfigurationChange>> changes) {
    ConfigurationTransactionResult result;
    if (changes.empty()) {
        result.error = "composite transaction contains no prepared changes";
        return result;
    }

    std::set<std::string> uniqueIdentifiers;
    std::vector<std::string> identifiers;
    identifiers.reserve(changes.size());
    for (const auto& change : changes) {
        if (change == nullptr) {
            result.error = "composite transaction contains a null change";
            return result;
        }
        std::string identifier;
        try {
            identifier = change->id();
        } catch (const std::exception& error) {
            result.error =
                "prepared change id threw an exception: " +
                std::string(error.what());
            return result;
        } catch (...) {
            result.error =
                "prepared change id threw an unknown exception";
            return result;
        }
        if (identifier.empty()) {
            result.error = "composite transaction contains an unnamed change";
            return result;
        }
        if (!uniqueIdentifiers.insert(identifier).second) {
            result.error = "duplicate prepared change identifier: " + identifier;
            return result;
        }
        identifiers.push_back(std::move(identifier));
    }

    // Recovery includes successful steps only when they actually changed
    // state. A failed step is always included because it may have failed after
    // a partial write or runtime action.
    std::vector<std::size_t> persistentRecovery;
    std::vector<std::size_t> runtimeRecovery;

    auto failAndRecover = [&](std::string error) {
        result.error = std::move(error);
        recover(
            changes,
            identifiers,
            persistentRecovery,
            runtimeRecovery,
            result);
        return result;
    };

    for (std::size_t index = 0; index < changes.size(); ++index) {
        auto& change = *changes[index];
        if (!change.needsCommit()) {
            continue;
        }
        const std::string& id = identifiers[index];
        const auto commit = invokeStep(
            [&change]() { return change.commitPersistent(); },
            id,
            "persistent commit");
        if (!commit.ok) {
            persistentRecovery.push_back(index);
            return failAndRecover(stepError(id, "persistent commit", commit));
        }
        if (commit.changed) {
            persistentRecovery.push_back(index);
        }
    }

    for (std::size_t index = 0; index < changes.size(); ++index) {
        auto& change = *changes[index];
        const std::string& id = identifiers[index];
        const auto verification = invokeStep(
            [&change]() { return change.verifyPersistent(); },
            id,
            "persistent verification");
        if (!verification.ok) {
            return failAndRecover(
                stepError(id, "persistent verification", verification));
        }
    }

    for (std::size_t index = 0; index < changes.size(); ++index) {
        auto& change = *changes[index];
        if (!change.needsActivation()) {
            continue;
        }
        const std::string& id = identifiers[index];
        const auto activation = invokeStep(
            [&change]() { return change.activate(); }, id, "activation");
        if (!activation.ok) {
            runtimeRecovery.push_back(index);
            return failAndRecover(stepError(id, "activation", activation));
        }
        if (activation.changed) {
            runtimeRecovery.push_back(index);
        }
    }

    for (std::size_t index = 0; index < changes.size(); ++index) {
        auto& change = *changes[index];
        const std::string& id = identifiers[index];
        const auto verification = invokeStep(
            [&change]() { return change.verifyEffective(); },
            id,
            "effective verification");
        if (!verification.ok) {
            return failAndRecover(
                stepError(id, "effective verification", verification));
        }
    }

    result.ok = true;
    return result;
}

} // namespace fic::identity
