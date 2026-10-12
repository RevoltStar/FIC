#pragma once
#include "features/incidents/services/IncidentService.h"
#include "features/incidents/models/IncidentAuditModel.h"
#include <QSet>

// Bounded, current-boot acquisition cache only. No event store or enforcement.
class IncidentHistoryService {
public:
    static constexpr int PageSize = 200, MaxPages = 4, MaxEvents = 1000;
    static constexpr qsizetype MaxMemoryBytes = 4 * 1024 * 1024;
    explicit IncidentHistoryService(IncidentService::RequestFunction request = {});
    IncidentHistorySnapshot refresh();
private:
    nlohmann::json request(const nlohmann::json& payload) const;
    IncidentService::RequestFunction request_;
    IncidentHistorySnapshot data_;
};
