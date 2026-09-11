#ifndef FIC_KDE_SESSION_TOPOLOGY_H
#define FIC_KDE_SESSION_TOPOLOGY_H

#include <cstddef>
#include <string>
#include <vector>

// Доказуемая топология KDE графических сессий одного UID.
//
// Unique    — среди relevant graphical sessions того же UID ровно одна
//             сессия классифицирована как KDE, и нет ни одной same-UID
//             сессии с неизвестной или ошибочной классификацией.
// Ambiguous — доказано наличие нескольких KDE сессий одного UID.
// Unknown   — uniqueness доказать невозможно (неполная inventory,
//             unclassified/failed same-UID сессия, KDE target не найден).
// Unknown fail closed так же, как Ambiguous.
enum class KdeSessionTopology {
    Unique,
    Ambiguous,
    Unknown
};

struct KdeSessionTopologyInfo {
    KdeSessionTopology state = KdeSessionTopology::Unknown;
    std::size_t kdeSessionCount = 0;
    std::size_t unknownSessionCount = 0;
    // Детали первой same-UID unclassified сессии для диагностики.
    std::string unknownSessionId;
    std::string unknownClassificationError;
};

struct ClassifiedGraphicalSession;

// Единственный общий алгоритм вычисления KDE topology; используется и
// обычным SessionAwareDesktopEnvironmentPolicy::apply(), и targeted
// session_ready reconciliation.
KdeSessionTopologyInfo determineKdeSessionTopology(
    const ClassifiedGraphicalSession& target,
    const std::vector<ClassifiedGraphicalSession>& sessions,
    bool inventoryComplete);

#endif // FIC_KDE_SESSION_TOPOLOGY_H