#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

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

SessionReconcileResult SessionAwareDesktopEnvironmentPolicy::reconcileSession(
    const ClassifiedGraphicalSession& session)
{
    std::string error;
    const SessionApplicability applicability =
        sessionApplicability(session.desktop, error);
    if (applicability == SessionApplicability::NotApplicable) {
        return {SessionReconcileStatus::NotApplicable, {}};
    }
    if (applicability == SessionApplicability::Unsupported) {
        return {SessionReconcileStatus::Unsupported, std::move(error)};
    }
    const EnforcementMode mode = modeFor(session.desktop);
    if (!prepare(error)) {
        return {mode == EnforcementMode::MandatoryGlobal
                    ? SessionReconcileStatus::GlobalEnforcementFailed
                    : SessionReconcileStatus::SessionOnlyFailed,
                std::move(error)};
    }
    if (mode == EnforcementMode::MandatoryGlobal &&
        !ensureGlobalState(session.desktop, error)) {
        return {SessionReconcileStatus::GlobalEnforcementFailed,
                std::move(error)};
    }
    if (!reconcileControlledSession(session, error)) {
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

bool SessionAwareDesktopEnvironmentPolicy::ensureGlobalState(
    DesktopEnvironmentKind desktop,
    std::string& error)
{
    if (!applyGlobalValue(desktop, error)) return false;
    log("global value: OK", logLevel::DEBUG);
    if (!applyGlobalProtection(desktop, error)) return false;
    log("global protection: OK", logLevel::DEBUG);
    if (!verifyGlobalState(desktop, error)) return false;
    log("global verify: OK", logLevel::DEBUG);
    return true;
}

bool SessionAwareDesktopEnvironmentPolicy::applyGlobalValue(
    DesktopEnvironmentKind,
    std::string& error)
{
    error = "mandatory global value enforcement is not implemented";
    return false;
}

bool SessionAwareDesktopEnvironmentPolicy::applyGlobalProtection(
    DesktopEnvironmentKind,
    std::string& error)
{
    error = "mandatory global protection is not implemented";
    return false;
}

bool SessionAwareDesktopEnvironmentPolicy::verifyGlobalState(
    DesktopEnvironmentKind,
    std::string& error)
{
    error = "mandatory global verification is not implemented";
    return false;
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
    if (!prepare(error)) {
        log(error, logLevel::ERROR);
        return false;
    }

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
        } else {
            log(std::string("controlled desktop ") +
                    DesktopEnvironmentBackend::kindName(desktop) +
                    ": mode=mandatory-global",
                logLevel::DEBUG);
            std::string globalError;
            const bool verified = ensureGlobalState(desktop, globalError);
            if (!verified) {
                log(std::string("Mandatory global enforcement failed for ") +
                        DesktopEnvironmentBackend::kindName(desktop) + ": " +
                        globalError,
                    logLevel::ERROR);
                success = false;
            } else {
                globallyEnforced.insert(desktop);
            }
        }
    }

    std::vector<ClassifiedGraphicalSession> sessions;
    if (!inventory_->currentSessions(sessions, error)) {
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
        std::string reconcileError;
        if (!reconcileControlledSession(session, reconcileError)) {
            const bool globalAuthoritative =
                globallyEnforced.find(session.desktop) != globallyEnforced.end();
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
