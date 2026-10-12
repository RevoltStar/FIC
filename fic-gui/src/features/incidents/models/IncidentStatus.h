#pragma once
#include <QString>
#include <QDateTime>
#include <optional>
#include <nlohmann/json.hpp>

struct IncidentStatus {
    QString severity, provenance, runtime, mode, modeDiagnostic, detail;
    bool stateProven = false, persistentBroken = true, modeProven = false;
    bool pam = false, sessions = false, userRuntime = false, network = false;
    static IncidentStatus parse(const nlohmann::json& response);
    bool normal() const;
};

// Acquisition state only; enforcement and incident transitions belong to daemon.
struct IncidentSnapshot {
    std::optional<IncidentStatus> status;
    QDateTime acquired;
    QString error;
    bool stale = false, reachable = false;
    quint64 lastSequence = 0;
    bool accept(quint64 sequence, const std::optional<IncidentStatus>& value,
                const QString& diagnostic, bool daemonReachable,
                QDateTime now = QDateTime::currentDateTimeUtc());
};
