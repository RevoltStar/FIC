#include "modules/identity_access/composite/CompositePolicy.h"

#include <exception>
#include <mutex>
#include <set>
#include <stdexcept>
#include <utility>

CompositePolicy::CompositePolicy()
    : IdentityAccessPolicy("COMPOSITE") {
}

void CompositePolicy::addParticipant(
    std::unique_ptr<fic::identity::ConfigurationParticipant> participant) {
    if (participant == nullptr) {
        throw std::invalid_argument(
            "composite configuration participant must not be null");
    }
    participants_.push_back(std::move(participant));
}

bool CompositePolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());

    if (participants_.empty()) {
        this->log(
            "Composite identity policy " + this->policyName +
                " has no configuration participants",
            logLevel::ERROR);
        return false;
    }

    std::vector<std::unique_ptr<fic::identity::PreparedConfigurationChange>>
        changes;
    changes.reserve(participants_.size());
    std::set<std::string> identifiers;
    for (auto& participant : participants_) {
        std::string identifier;
        try {
            identifier = participant->id();
        } catch (const std::exception& error) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + ": participant id threw an exception: " +
                    error.what(),
                logLevel::ERROR);
            return false;
        } catch (...) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName +
                    ": participant id threw an unknown exception",
                logLevel::ERROR);
            return false;
        }

        if (identifier.empty() || !identifiers.insert(identifier).second) {
            const std::string reason = identifier.empty()
                ? "unnamed configuration participant"
                : "duplicate configuration participant: " + identifier;
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + ": " + reason,
                logLevel::ERROR);
            return false;
        }

        fic::identity::ConfigurationPreparationResult prepared;
        try {
            prepared = participant->prepare(*value);
        } catch (const std::exception& error) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + "/" + identifier + ": " + error.what(),
                logLevel::ERROR);
            return false;
        } catch (...) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + "/" + identifier +
                    ": unknown exception",
                logLevel::ERROR);
            return false;
        }

        if (!prepared.ok()) {
            const std::string reason = prepared.error.empty()
                ? "participant did not return a prepared change"
                : prepared.error;
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + "/" + identifier + ": " + reason,
                logLevel::ERROR);
            return false;
        }
        std::string preparedIdentifier;
        try {
            preparedIdentifier = prepared.change->id();
        } catch (const std::exception& error) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + "/" + identifier +
                    ": prepared change id threw an exception: " +
                    error.what(),
                logLevel::ERROR);
            return false;
        } catch (...) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + "/" + identifier +
                    ": prepared change id threw an unknown exception",
                logLevel::ERROR);
            return false;
        }
        if (preparedIdentifier != identifier) {
            this->log(
                "Composite identity policy preflight failed for " +
                    this->policyName + "/" + identifier +
                    ": prepared change identifier does not match participant",
                logLevel::ERROR);
            return false;
        }
        changes.push_back(std::move(prepared.change));
    }

    auto result = fic::identity::ConfigurationTransaction::execute(
        std::move(changes));
    if (!result.ok) {
        std::string message =
            "Composite identity policy failed for " + this->policyName +
            ": " + result.error;
        for (const auto& recoveryError : result.recoveryErrors) {
            message += "; recovery error: " + recoveryError;
        }
        this->log(std::move(message), logLevel::ERROR);
        return false;
    }

    this->log(
        "Composite identity policy " + this->policyName +
            " was applied and verified",
        logLevel::INFO);
    return true;
}
