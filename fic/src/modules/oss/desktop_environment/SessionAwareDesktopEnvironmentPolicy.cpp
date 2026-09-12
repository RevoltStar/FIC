#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

#include <algorithm>
#include <set>
#include <utility>

SessionAwareDesktopEnvironmentPolicy::SessionAwareDesktopEnvironmentPolicy(
    ControlledDesktopEnvironmentScope& scope,
    std::shared_ptr<GraphicalSessionInventory> inventory)
    : scope_(scope), inventory_(std::move(inventory))
{
}

SessionApplicability SessionAwareDesktopEnvironmentPolicy::sessionApplicability(
    DesktopEnvironmentKind desktop,
    std::string& error)
{
    DesktopEnvironmentSet controlled;
    if (!scope_.controlledDesktopEnvironments(controlled, error) ||
        controlled.empty()) {
        if (error.empty()) {
            error = "controlled_desktop_environments is empty (UNCONFIGURED)";
        }
        return SessionApplicability::Unsupported;
    }
    if (controlled.find(desktop) == controlled.end() || !relevantTo(desktop)) {
        error.clear();
        return SessionApplicability::NotApplicable;
    }
    if (modeFor(desktop) == EnforcementMode::Unsupported) {
        error = std::string(policyName) + " has no backend for controlled desktop " +
            DesktopEnvironmentBackend::kindName(desktop);
        return SessionApplicability::Unsupported;
    }
    error.clear();
    return SessionApplicability::Applicable;
}

EnforcementMode SessionAwareDesktopEnvironmentPolicy::enforcementMode(
    DesktopEnvironmentKind desktop) const
{
    return relevantTo(desktop) ? modeFor(desktop) : EnforcementMode::Unsupported;
}

void SessionAwareDesktopEnvironmentPolicy::setGlobalEnforcementResults(
    PolicyGlobalEnforcementResults results)
{
    globalResults_ = std::move(results);
}

SessionReconcileResult SessionAwareDesktopEnvironmentPolicy::reconcileSession(
    const SessionReconcileContext& context,
    const PolicyGlobalEnforcementResult& globalResult)
{
    std::string error;
    const SessionApplicability applicability =
        sessionApplicability(context.target.desktop, error);
    if (applicability == SessionApplicability::NotApplicable) {
        return {SessionReconcileStatus::NotApplicable, {}};
    }
    if (applicability == SessionApplicability::Unsupported) {
        return {SessionReconcileStatus::Unsupported, std::move(error)};
    }
    const EnforcementMode mode = modeFor(context.target.desktop);
    if (mode == EnforcementMode::MandatoryGlobal &&
        (!globalResult.hasRequirement || !globalResult.verified)) {
        return {SessionReconcileStatus::GlobalEnforcementFailed,
                globalResult.diagnostic.empty()
                    ? std::string("MandatoryGlobal policy has no verified global requirement")
                    : globalResult.diagnostic};
    }
    if (!prepare(error)) {
        return {mode == EnforcementMode::MandatoryGlobal
                    ? SessionReconcileStatus::MandatoryGlobalRuntimeWarning
                    : SessionReconcileStatus::SessionOnlyFailed,
                std::move(error)};
    }
    if (!reconcileControlledSession(context, error)) {
        return {mode == EnforcementMode::MandatoryGlobal
                    ? SessionReconcileStatus::MandatoryGlobalRuntimeWarning
                    : SessionReconcileStatus::SessionOnlyFailed,
                std::move(error)};
    }
    return {mode == EnforcementMode::MandatoryGlobal
                ? SessionReconcileStatus::MandatoryGlobalConverged
                : SessionReconcileStatus::SessionOnlyConverged,
            {}};
}

bool SessionAwareDesktopEnvironmentPolicy::apply()
{
    DesktopEnvironmentSet controlled;
    std::string error;
    if (!scope_.controlledDesktopEnvironments(controlled, error)) {
        log(error, logLevel::ERROR);
        return false;
    }
    if (controlled.empty()) {
        log("controlled_desktop_environments is empty (UNCONFIGURED)",
            logLevel::ERROR);
        return false;
    }
    const bool prepared = prepare(error);
    const std::string preparationError = error;

    bool success = true;
    bool hasSessionOnly = false;
    std::set<DesktopEnvironmentKind> globallyEnforced;
    for (const DesktopEnvironmentKind desktop : controlled) {
        if (!relevantTo(desktop)) continue;
        const EnforcementMode mode = modeFor(desktop);
        if (mode == EnforcementMode::Unsupported) {
            log(std::string(policyName) +
                    " has no backend for controlled desktop " +
                    DesktopEnvironmentBackend::kindName(desktop),
                logLevel::ERROR);
            success = false;
        } else if (mode == EnforcementMode::SessionOnly) {
            log(std::string("controlled desktop ") +
                    DesktopEnvironmentBackend::kindName(desktop) +
                    ": mode=session-only",
                logLevel::DEBUG);
            hasSessionOnly = true;
            if (!prepared) {
                log("Session preparation failed: " + preparationError,
                    logLevel::ERROR);
                success = false;
            }
        } else {
            log(std::string("controlled desktop ") +
                    DesktopEnvironmentBackend::kindName(desktop) +
                    ": mode=mandatory-global",
                logLevel::DEBUG);
            const auto result = globalResults_.find(desktop);
            if (result == globalResults_.end() ||
                !result->second.hasRequirement || !result->second.verified) {
                const std::string diagnostic = result == globalResults_.end() ||
                        result->second.diagnostic.empty()
                    ? "no verified global requirement"
                    : result->second.diagnostic;
                log(std::string("Mandatory global enforcement failed for ") +
                        DesktopEnvironmentBackend::kindName(desktop) + ": " +
                        diagnostic,
                    logLevel::ERROR);
                success = false;
            } else {
                globallyEnforced.insert(desktop);
                if (!prepared) {
                    log("Session preparation warning after verified global enforcement: " +
                            preparationError,
                        logLevel::WARN);
                }
            }
        }
    }

    std::vector<ClassifiedGraphicalSession> sessions;
    const bool inventoryComplete = inventory_->currentSessions(sessions, error);
    if (!inventoryComplete) {
        log("Failed to enumerate graphical sessions: " + error,
            hasSessionOnly ? logLevel::ERROR : logLevel::WARN);
        return hasSessionOnly ? false : success;
    }

    std::set<DesktopEnvironmentKind> seenSessionOnly;
    for (const ClassifiedGraphicalSession& session : sessions) {
        if (!session.classified()) {
            log("Ignoring unclassified session " + session.session.id +
                    " for ordinary scoped policy: " +
                    session.classificationError,
                logLevel::WARN);
            continue;
        }
        std::string applicabilityError;
        const SessionApplicability applicability =
            sessionApplicability(session.desktop, applicabilityError);
        if (applicability == SessionApplicability::NotApplicable) continue;
        if (applicability == SessionApplicability::Unsupported) {
            success = false;
            continue;
        }

        const EnforcementMode mode = modeFor(session.desktop);
        if (mode == EnforcementMode::SessionOnly) {
            seenSessionOnly.insert(session.desktop);
        }
        const bool globalAuthoritative =
            globallyEnforced.find(session.desktop) != globallyEnforced.end();
        if (!prepared) {
            log("Session " + session.session.id +
                    " preparation failed: " + preparationError,
                globalAuthoritative ? logLevel::WARN : logLevel::ERROR);
            if (!globalAuthoritative) success = false;
            continue;
        }
        if (mode == EnforcementMode::MandatoryGlobal && !globalAuthoritative) {
            continue;
        }
        const SessionReconcileContext context{session, sessions, true};
        std::string reconcileError;
        if (!reconcileControlledSession(context, reconcileError)) {
            log("Session " + session.session.id + " reconciliation failed: " +
                    reconcileError,
                globalAuthoritative ? logLevel::WARN : logLevel::ERROR);
            if (!globalAuthoritative) success = false;
        }
    }

    for (const DesktopEnvironmentKind desktop : controlled) {
        if (relevantTo(desktop) &&
            modeFor(desktop) == EnforcementMode::SessionOnly &&
            seenSessionOnly.find(desktop) == seenSessionOnly.end()) {
            log(std::string("No current ") +
                    DesktopEnvironmentBackend::kindName(desktop) +
                    " sessions; enforcement deferred",
                logLevel::DEBUG);
        }
    }
    return success;
}
