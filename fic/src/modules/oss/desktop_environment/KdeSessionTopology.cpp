#include "modules/oss/desktop_environment/KdeSessionTopology.h"

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"

KdeSessionTopologyInfo determineKdeSessionTopology(
    const ClassifiedGraphicalSession& target,
    const std::vector<ClassifiedGraphicalSession>& sessions,
    bool inventoryComplete) {
    KdeSessionTopologyInfo info;
    if (!inventoryComplete) return info;

    const auto uid = target.session.uid;
    for (const ClassifiedGraphicalSession& candidate : sessions) {
        if (candidate.session.uid != uid) continue;
        if (candidate.desktop == DesktopEnvironmentKind::Kde) {
            ++info.kdeSessionCount;
        } else if (!candidate.classified()) {
            if (info.unknownSessionCount == 0) {
                info.unknownSessionId = candidate.session.id;
                info.unknownClassificationError = candidate.classificationError;
            }
            ++info.unknownSessionCount;
        }
        // Достоверно классифицированная non-KDE сессия того же UID не
        // влияет на доказанность unique KDE topology.
    }

    if (info.kdeSessionCount > 1) {
        info.state = KdeSessionTopology::Ambiguous;
    } else if (info.unknownSessionCount > 0 || info.kdeSessionCount == 0) {
        info.state = KdeSessionTopology::Unknown;
    } else {
        info.state = KdeSessionTopology::Unique;
    }
    return info;
}