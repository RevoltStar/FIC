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
        // Exact target identity: uid + session.id. Совпадение только по
        // UID недостаточно: replacement session того же UID — не target.
        if (candidate.session.id == target.session.id) {
            info.targetPresent = true;
            if (candidate.desktop == DesktopEnvironmentKind::Kde)
                info.targetClassifiedKde = true;
        }
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

    // Precedence: сначала доказывается сама target (present + KDE),
    // только потом same-UID topology. Несколько других KDE сессий при
    // отсутствии target — Unknown, а не Ambiguous: reconciliation target
    // как таковой больше не доказан.
    if (!info.targetClassifiedKde) {
        info.state = KdeSessionTopology::Unknown;
    } else if (info.kdeSessionCount > 1) {
        info.state = KdeSessionTopology::Ambiguous;
    } else if (info.unknownSessionCount > 0) {
        info.state = KdeSessionTopology::Unknown;
    } else {
        info.state = KdeSessionTopology::Unique;
    }
    return info;
}