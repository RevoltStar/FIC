#ifndef FIC_DESKTOP_ENVIRONMENT_CONTROL_H
#define FIC_DESKTOP_ENVIRONMENT_CONTROL_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "session/UserSession.h"

#include <set>
#include <map>
#include <string>
#include <vector>

using DesktopEnvironmentSet = std::set<DesktopEnvironmentKind>;

// Generic classified session содержит только факты о самой сессии.
// DE-specific derived metadata (например topology того же UID)
// сознательно отсутствует: она вычисляется DE-specific consumer-ом из
// SessionReconcileContext в момент reconciliation.
struct ClassifiedGraphicalSession {
    UserSession session;
    SessionContext context;
    DesktopEnvironmentKind desktop = DesktopEnvironmentKind::Unknown;
    std::string classificationError;

    bool classified() const {
        return desktop != DesktopEnvironmentKind::Unknown;
    }
};

// DE-neutral reconciliation facts: target session + snapshot графической
// сессии inventory + достоверность snapshot. Не содержит DE-specific
// derived metadata (topology proof objects и т.п.) — DE-specific consumer
// вычисляет их из этих фактов в момент reconciliation.
// Содержит references: использовать синхронно внутри одного
// reconciliation call; не хранить в long-lived объектах, не передавать
// асинхронно и не переживать underlying objects.
struct SessionReconcileContext {
    const ClassifiedGraphicalSession& target;
    const std::vector<ClassifiedGraphicalSession>& sessions;
    bool inventoryComplete = false;
};

enum class SessionApplicability {
    Applicable,
    NotApplicable,
    Unsupported
};

enum class EnforcementMode {
    MandatoryGlobal,
    SessionOnly,
    Unsupported
};

enum class SessionReconcileStatus {
    NotApplicable,
    Unsupported,
    GlobalEnforcementFailed,
    MandatoryGlobalConverged,
    MandatoryGlobalRuntimeWarning,
    SessionOnlyConverged,
    SessionOnlyFailed
};

struct SessionReconcileResult {
    SessionReconcileStatus status = SessionReconcileStatus::NotApplicable;
    std::string diagnostic;

    bool successful() const {
        return status == SessionReconcileStatus::NotApplicable ||
            status == SessionReconcileStatus::MandatoryGlobalConverged ||
            status == SessionReconcileStatus::MandatoryGlobalRuntimeWarning ||
            status == SessionReconcileStatus::SessionOnlyConverged;
    }
};

struct PolicyGlobalEnforcementResult {
    bool hasRequirement = false;
    bool verified = false;
    std::set<std::string> backends;
    std::string diagnostic;
};

using PolicyGlobalEnforcementResults =
    std::map<DesktopEnvironmentKind, PolicyGlobalEnforcementResult>;

class ControlledDesktopEnvironmentScope {
public:
    virtual ~ControlledDesktopEnvironmentScope() = default;
    virtual bool controlledDesktopEnvironments(
        DesktopEnvironmentSet& controlled,
        std::string& error) = 0;
};

class GraphicalSessionInventory {
public:
    virtual ~GraphicalSessionInventory() = default;
    virtual bool currentSessions(
        std::vector<ClassifiedGraphicalSession>& sessions,
        std::string& error) = 0;
};

class SessionAwarePolicy {
public:
    virtual ~SessionAwarePolicy() = default;
    virtual SessionApplicability sessionApplicability(
        DesktopEnvironmentKind desktop,
        std::string& error) = 0;
    virtual EnforcementMode enforcementMode(
        DesktopEnvironmentKind desktop) const = 0;
    virtual void setGlobalEnforcementResults(
        PolicyGlobalEnforcementResults results) = 0;
    virtual SessionReconcileResult reconcileSession(
        const SessionReconcileContext& context,
        const PolicyGlobalEnforcementResult& globalResult) = 0;
};

class SessionInventoryCompliancePolicy {
public:
    virtual ~SessionInventoryCompliancePolicy() = default;
    virtual bool evaluateSessionInventory(
        const std::vector<ClassifiedGraphicalSession>& sessions,
        std::string& error) = 0;
};

#endif // FIC_DESKTOP_ENVIRONMENT_CONTROL_H
