#ifndef FIC_KDE_SESSION_TOPOLOGY_H
#define FIC_KDE_SESSION_TOPOLOGY_H

#include <cstddef>
#include <string>
#include <vector>

// Доказуемая топология KDE графических сессий одного UID.
//
// Unique    — в complete inventory присутствует сама target session
//             (exact identity: uid + session.id), она по-прежнему
//             классифицирована как KDE, это единственная same-UID KDE
//             сессия, и нет ни одной same-UID сессии с неизвестной или
//             ошибочной классификацией. Unique означает не просто одну
//             KDE session того же UID, а присутствие и уникальность
//             exact target session.
// Ambiguous — доказано наличие нескольких KDE сессий одного UID при
//             доказанной KDE target.
// Unknown   — uniqueness доказать невозможно (неполная inventory,
//             target отсутствует в inventory, target больше не KDE,
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
    // Exact target (uid + session.id) присутствует в inventory.
    // Diagnostics-only: не является вторым источником topology semantics.
    bool targetPresent = false;
    // Exact target присутствует и классифицирован как KDE.
    bool targetClassifiedKde = false;
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