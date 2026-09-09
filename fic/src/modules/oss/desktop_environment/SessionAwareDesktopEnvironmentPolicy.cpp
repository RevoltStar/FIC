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
    const ClassifiedGraphicalSession& session,
    bool globalEnforcementVerified,
    const std::string& globalDiagnostic)
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
    if (mode == EnforcementMode::MandatoryGlobal &&
        !globalEnforcementVerified) {
        return {SessionReconcileStatus::GlobalEnforcementFailed,
                globalDiagnostic};
    }
    if (!prepare(error)) {
        return {mode == EnforcementMode::MandatoryGlobal
                    ? SessionReconcileStatus::GlobalEnforcementFailed
                    : SessionReconcileStatus::SessionOnlyFailed,
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
            // The daemon's DesktopGlobalConfigReconciler has already ensured
            // and verified all active global requirements before policy apply.
            globallyEnforced.insert(desktop);
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
